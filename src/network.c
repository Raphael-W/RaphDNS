#include "network.h"
#include "packet.h"
#include "cache.h"
#include "helpers.h"
#include "pending.h"
#include "blocklist.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <poll.h>
#include <fcntl.h>
#include <errno.h>

#include "resolver.h"

#define BUF_SIZE 4096

static bool verbose = false; // Whether to log every query, which costs throughput

// Returns the name of a DNS type, for logging
static const char *dns_type_name(const uint16_t type) {
    switch (type) {
    case DNS_TYPE_A:     return "A";
    case DNS_TYPE_NS:    return "NS";
    case DNS_TYPE_CNAME: return "CNAME";
    case DNS_TYPE_SOA:   return "SOA";
    case DNS_TYPE_PTR:   return "PTR";
    case DNS_TYPE_MX:    return "MX";
    case DNS_TYPE_TXT:   return "TXT";
    case DNS_TYPE_AAAA:  return "AAAA";
    case DNS_TYPE_SRV:   return "SRV";
    case DNS_TYPE_OPT:   return "OPT";
    case DNS_TYPE_HTTPS: return "HTTPS";
    case DNS_TYPE_ANY:   return "ANY";
    default:             return "UNKNOWN";
    }
}

// Writes an error response to the query into out, with the given rcode
// Returns the response's length in bytes, or -1 on failure
static int make_error(const dns_packet *query, const uint8_t rcode, uint8_t *out, const size_t out_size) {
    dns_packet fail = *query;
    fail.qr = 1;
    fail.ra = 1;
    fail.aa = 0;
    fail.qd_count = 1;
    fail.rcode = rcode;
    fail.an_count = fail.ns_count = fail.ar_count = 0;
    return create_dns_packet(out, out_size, &fail);
}

// SOCKET SETUP
// Returns a new UDP socket, or -1 on failure
// Non-blocking, so reads return EAGAIN instead of waiting when nothing has arrived
static int udp_socket(void) {
    const int sock = socket(AF_INET, SOCK_DGRAM, 0);
    if (sock < 0) {
        perror("socket");
        return -1;
    }

    if (fcntl(sock, F_SETFL, O_NONBLOCK) < 0) {
        perror("fcntl");
        close(sock);
        return -1;
    }
    return sock;
}

// Fills out with ip:port. Returns false if ip isn't a valid IPv4 address
static bool make_addr(const char *ip, int port, struct sockaddr_in *out) {
    memset(out, 0, sizeof *out);
    out->sin_family = AF_INET;
    out->sin_port = htons(port); // network byte order
    return inet_pton(AF_INET, ip, &out->sin_addr) == 1;
}

// Returns the socket that clients send queries to, bound to 127.0.0.1:port, or -1 on failure
static int open_listener(const int port, const char* ip) {
    const int sock = udp_socket();
    if (sock < 0) return -1;

    // Allows server to be restarted without waiting for the port to free up
    const int yes = 1;
    setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, &yes, sizeof yes);

    struct sockaddr_in addr;
    make_addr(ip, port, &addr);
    if (bind(sock, (struct sockaddr *)&addr, sizeof addr) < 0) {
        perror("bind");
        close(sock);
        return -1;
    }
    return sock;
}

// Returns the socket for querying nameservers, or -1 on failure
static int open_upstream() {
    return udp_socket();
}

// Sends a packet to ip:53. Returns a success bool
static bool send_to_server(const int sock, const char *ip, const uint8_t *packet, const int len) {
    struct sockaddr_in server;
    if (!make_addr(ip, 53, &server)) return false;
    return sendto(sock, packet, len, 0, (struct sockaddr *)&server, sizeof server) >= 0;
}

// Sends SERVFAIL to the client and removes the query and any parent queries from pending
static void fail_query(const int sock, query *q, const int rcode) {
    // A failed child lookup fails the whole chain, up to the query the client made
    while (q->parent) {
        query *parent = q->parent;
        pending_remove(q);
        q = parent;
    }

    uint8_t buf[BUF_SIZE];
    const dns_packet p = {.id = q->client_id, .rd = 1, .qd_count = 1, .question = q->original};
    const int n = make_error(&p, rcode, buf, sizeof buf);
    if (n > 0) { sendto(sock, buf, n, 0, (struct sockaddr *)&q->client, q->client_len); }
    pending_remove(q);
}

// Retries each timed out query on its next server, failing it if that isn't possible
static void expire_pending(const int sock, const int sock_up, const time_t now) {
    query *q;
    while ((q = pending_next_expired(now))) {
        uint8_t out[512];
        int out_len;
        char next_ip[INET_ADDRSTRLEN];

        if (resolver_on_timeout(&q, out, sizeof out, &out_len, next_ip) != RESOLVE_SEND ||
            !send_to_server(sock_up, next_ip, out, out_len)) {
            fail_query(sock, q, DNS_RCODE_SERVFAIL);
        }
    }
}

// Returns whether the from address is ip:53
static bool from_server(const struct sockaddr_in *from, const char *ip) {
    struct sockaddr_in expected;
    return make_addr(ip, 53, &expected) &&
            from->sin_addr.s_addr == expected.sin_addr.s_addr &&
            from->sin_port == expected.sin_port;
}

static bool reply_is_blocked(const dns_packet *p, list *l) {
    for (int i = 0; i < p->an_count; i++) {
        const dns_record *rec = &p->answers[i];
        char target[256];
        if (rec->type == DNS_TYPE_CNAME &&
            record_rdata_name(rec, target, sizeof target) &&
            list_blocks(target, l)) {
            return true;
        }
    }
    return false;
}

// Reads all waiting client packets: answers each query from the cache, or starts resolving it if it isn't cached
static void handle_client(int sock, int sock_up, cache *c, list *blocklist) {
    // Fetches all packets until EAGAIN (no more to fetch)
    for (;;) {
        uint8_t buf[BUF_SIZE];

        struct sockaddr_in client;
        socklen_t client_len = sizeof client;

        // Receive packet and store in buf
        ssize_t n = recvfrom(sock, buf, sizeof buf, 0, (struct sockaddr *)&client, &client_len);
        if (n < 0) {
            if (errno != EAGAIN && errno != EWOULDBLOCK) perror("recvfrom");
            break;
        }

        // Parse DNS packet
        dns_packet packet = {0};
        if (parse_dns_packet(buf, n, &packet) < 0) {
            if (verbose) printf("Malformed request packet\n");
            free_dns_packet(&packet);
            continue;
        }

        uint8_t response_buf[BUF_SIZE];
        ssize_t response_length = 0;

        // Ignore packets marked as responses
        if (packet.qr == 1) {
            free_dns_packet(&packet);
            continue;
        }

        // There should only ever be one question (despite what the existence of qd_count may suggest)
        if (packet.qd_count != 1) {
            response_length = make_error(&packet, DNS_RCODE_FORMERR, response_buf, sizeof response_buf);
        }

        else if (list_blocks(packet.question.name, blocklist)) {
            response_length = make_error(&packet, DNS_RCODE_NXDOMAIN, response_buf, sizeof response_buf);
            if (verbose) printf("Blocked %s request for %s\n", dns_type_name(packet.question.type), packet.question.name);
        }

        else { // Valid request
            if (verbose) printf("Received %s request for %s\n", dns_type_name(packet.question.type), packet.question.name);
            const dns_packet *cached = cache_lookup(c, &packet.question);

            if (cached) { // Cache exists
                dns_packet reply = *cached;
                reply.id = packet.id;
                reply.question = packet.question;
                reply.aa = 0;
                response_length = create_dns_packet(response_buf, sizeof response_buf, &reply);
            }
            else { // Not cached: start resolving
                query new_query = {.client=client, .client_id=packet.id, .client_len=client_len, .question=packet.question};
                int query_id = pending_add(&new_query);

                if (query_id < 0) {
                    response_length = -1;
                }
                else {
                    query *q = pending_find(query_id);
                    uint8_t out[512];
                    int out_len;
                    char next_ip[INET_ADDRSTRLEN];

                    if (resolver_start(q, out, sizeof out, &out_len, next_ip) != RESOLVE_SEND ||
                        !send_to_server(sock_up, next_ip, out, out_len)) {
                        pending_remove(q);
                        response_length = -1;
                    }
                }
            }
        }

        if (response_length < 0) {
            response_length = make_error(&packet, DNS_RCODE_SERVFAIL, response_buf, sizeof response_buf);
        }
        if (response_length > 0) {
            sendto(sock, response_buf, response_length, 0, (struct sockaddr *)&client, client_len);
        }
        free_dns_packet(&packet);

    }
}

// Reads all waiting nameserver responses and moves each one's lookup on to its next step
// Replies to the client and caches the result once a lookup is finished
static void handle_upstream(const int sock_up, const int sock, cache *c, list *blocklist) {
    // Fetches until EAGAIN (no more to fetch)
    for (;;) {
        uint8_t buf[BUF_SIZE];
        struct sockaddr_in from;
        socklen_t from_len = sizeof from;

        const ssize_t n = recvfrom(sock_up, buf, sizeof buf, 0, (struct sockaddr *)&from, &from_len);
        if (n < 0) {
            if (errno != EAGAIN && errno != EWOULDBLOCK) perror("recv");
            break;
        }
        if (n < 12) continue; // too short for a DNS header

        query *q = pending_find((uint16_t)(buf[0] << 8 | buf[1]));
        if (!q || !from_server(&from, q->servers[q->current])) continue;

        dns_packet reply = {0};
        if (parse_dns_packet(buf, n, &reply) < 0 ||
            strcasecmp(reply.question.name, q->question.name) != 0 ||
            reply.question.type != q->question.type ||
            reply.question.class != q->question.class) {
            free_dns_packet(&reply);
            continue;
        }

        if (!q->parent && reply_is_blocked(&reply, blocklist)) {
            if (verbose) printf("Blocked CNAME while resolving %s\n", q->original.name);
            free_dns_packet(&reply);
            fail_query(sock, q, DNS_RCODE_NXDOMAIN);
            continue;
        }


        uint8_t out[512];
        int out_len;
        char next_ip[INET_ADDRSTRLEN];
        const resolve_step step = resolver_on_response(&q, &reply, out, sizeof out, &out_len, next_ip);

        if (step == RESOLVE_SEND && send_to_server(sock_up, next_ip, out, out_len)) {
            free_dns_packet(&reply);
        }
        else if (step == RESOLVE_DONE) {
            resolver_add_cnames(q, &reply);
            reply.id = q->client_id;
            reply.rd = 1;
            reply.ra = 1;
            reply.aa = 0;
            const int reply_len = create_dns_packet(buf, sizeof buf, &reply);
            if (reply_len > 0) sendto(sock, buf, reply_len, 0, (struct sockaddr *)&q->client, q->client_len);
            pending_remove(q);

            if ((reply.rcode == DNS_RCODE_NOERROR || reply.rcode == DNS_RCODE_NXDOMAIN) && !reply.tc) {
                cache_insert(c, reply);
            }
            else {
                free_dns_packet(&reply);
            }
        }

        else {
            free_dns_packet(&reply);
            fail_query(sock, q, DNS_RCODE_SERVFAIL);
        }
    }
}

// Creates both sockets, then polls them forever, handling queries, responses and timeouts
// Returns 1 if a socket can't be opened
int network_listen(const int port, const char* ip, list *blocklist, const bool log_queries) {
    verbose = log_queries;

    cache cache = cache_create(8);
    if (cache.bucket_count == 0) {
        fprintf(stderr, "Failed to allocate cache\n");
        return 1;
    }

    const int sock = open_listener(port, ip);
    if (sock < 0) return 1;

    const int up_sock = open_upstream();
    if (up_sock < 0) { close(sock); return 1; }

    struct pollfd fds[2] = {
        {.fd = sock, .events = POLLIN},
        {.fd = up_sock, .events = POLLIN}
    };

    printf("Listening on %s:%d\n", ip, port);

    for (;;) {
        int timeout_ms = -1;
        const time_t earliest = pending_earliest();
        if (earliest) {
            const time_t wait = earliest - now_seconds();
            timeout_ms = wait > 0 ? (int)(wait * 1000) : 0;
        }

        if (poll(fds, 2, timeout_ms) < 0) { perror("poll"); continue; }

        if (fds[0].revents & POLLIN) handle_client(sock, up_sock, &cache, blocklist);
        if (fds[1].revents & POLLIN) handle_upstream(up_sock, sock, &cache, blocklist);
        expire_pending(sock, up_sock, now_seconds());
    }

    close(up_sock);
    close(sock);
    return 0;
}