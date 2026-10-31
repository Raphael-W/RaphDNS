#include "network.h"
#include "packet.h"
#include "cache.h"
#include "helpers.h"
#include "pending.h"

#include <stdio.h>
#include <stdlib.h>
#include <strings.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <poll.h>
#include <fcntl.h>
#include <errno.h>

#define BUF_SIZE 4096
#define RESOLVER_IP_UNI "152.78.255.75"
#define RESOLVER_IP "1.1.1.1"

static const char *dns_type_name(uint16_t type) {
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

static int make_error(const dns_packet *query, uint8_t rcode, uint8_t *out, size_t out_size) {
    dns_packet fail = *query;
    fail.qr = 1;
    fail.ra = 1;
    fail.rcode = rcode;
    fail.an_count = fail.ns_count = fail.ar_count = 0;
    return create_dns_packet(out, out_size, &fail);
}

static void set_packet_id(uint8_t *buf, const uint16_t id) {
    buf[0] = id >> 8;
    buf[1] = id & 0xFF;
}

// SOCKET SETUP

// Non-blocking, so reads return EAGAIN instead of waiting when nothing has arrived
static int udp_socket(void) {
    int sock = socket(AF_INET, SOCK_DGRAM, 0);
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

// Socket that clients send queries to
static int open_listener(int port) {
    int sock = udp_socket();
    if (sock < 0) return -1;

    // Allows server to be restarted without waiting for the port to free up
    int yes = 1;
    setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, &yes, sizeof yes);

    struct sockaddr_in addr;
    make_addr("127.0.0.1", port, &addr); // 127.0.0.1 only, for now
    if (bind(sock, (struct sockaddr *)&addr, sizeof addr) < 0) {
        perror("bind");
        close(sock);
        return -1;
    }
    return sock;
}

// Socket for talking to the upstream resolver
static int open_upstream(const char *ip) {
    int sock = udp_socket();
    if (sock < 0) return -1;

    struct sockaddr_in server;
    if (!make_addr(ip, 53, &server)) {
        fprintf(stderr, "Invalid upstream IP: %s\n", ip);
        close(sock);
        return -1;
    }

    // Connecting a UDP socket makes the kernel drop packets from any other address
    if (connect(sock, (struct sockaddr *)&server, sizeof server) < 0) {
        perror("connect");
        close(sock);
        return -1;
    }
    return sock;
}

static void expire_pending(int sock, time_t now) {
    query *q;
    uint8_t buf[BUF_SIZE];
    while ((q = pending_next_expired(now))) {
        dns_packet p = {.id = q->client_id, .rd = 1, .qd_count = 1, .question = q->question};
        int n = make_error(&p, DNS_RCODE_SERVFAIL, buf, sizeof buf);
        if (n > 0) { sendto(sock, buf, n, 0, (struct sockaddr *)&q->client, q->client_len); }
        pending_remove(q);
    }
}

static void handle_client(int sock, int sock_up, cache *c) {
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
            printf("Malformed request packet\n");
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

        else { // Valid request
            printf("Received %s request for %s\n", dns_type_name(packet.question.type), packet.question.name);
            const dns_packet *cached = cache_lookup(c, &packet.question);

            if (cached) { // Cache exists
                dns_packet reply = *cached;
                reply.id = packet.id;
                reply.question = packet.question;
                response_length = create_dns_packet(response_buf, sizeof response_buf, &reply);
            }
            else { // Fetch answer upstream
                query query = {.client=client, .client_id=packet.id, .client_len=client_len, .question=packet.question, .expires_at=now_seconds() + 2};
                int query_id = pending_add(&query);

                if (query_id < 0) {
                    response_length = -1;
                }
                else {
                    set_packet_id(buf, query_id);
                    if (send(sock_up, buf, n, 0) < 0) {
                        pending_remove(pending_find(query_id));
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

static void handle_upstream(int sock_up, int sock, cache *c) {
    for (;;) {
        uint8_t buf[BUF_SIZE];
        ssize_t n = recv(sock_up, buf, sizeof buf, 0);
        if (n < 0) {
            if (errno != EAGAIN && errno != EWOULDBLOCK) perror("recv");
            break;
        }
        if (n < 12) continue; // too short for a DNS header

        query *q = pending_find((uint16_t)(buf[0] << 8 | buf[1]));
        if (!q) continue;

        dns_packet reply = {0};
        if (parse_dns_packet(buf, n, &reply) < 0 ||
            strcasecmp(reply.question.name, q->question.name) != 0 ||
            reply.question.type != q->question.type ||
            reply.question.class != q->question.class) {
            free_dns_packet(&reply);
            continue;
        }

        set_packet_id(buf, q->client_id);
        sendto(sock, buf, n, 0, (struct sockaddr *) &q->client, q->client_len);
        pending_remove(q);
        if ((reply.rcode == DNS_RCODE_NOERROR || reply.rcode == DNS_RCODE_NXDOMAIN) && !reply.tc) {
            cache_insert(c, reply);
        }
        else {
            free_dns_packet(&reply);
        }
    }
}

int network_listen(int port) {
    cache cache = cache_create(8);

    int sock = open_listener(port);
    if (sock < 0) return 1;

    int up_sock = open_upstream(RESOLVER_IP);
    if (up_sock < 0) { close(sock); return 1; }

    struct pollfd fds[2] = {
        {.fd = sock, .events = POLLIN},
        {.fd = up_sock, .events = POLLIN}
    };

    printf("Listening on 127.0.0.1:%d\n", port);

    for (;;) {
        int timeout_ms = -1;
        time_t earliest = pending_earliest();
        if (earliest) {
            time_t wait = earliest - now_seconds();
            timeout_ms = wait > 0 ? (int)(wait * 1000) : 0;
        }

        if (poll(fds, 2, timeout_ms) < 0) { perror("poll"); continue; }

        if (fds[0].revents & POLLIN) handle_client(sock, up_sock, &cache);
        if (fds[1].revents & POLLIN) handle_upstream(up_sock, sock, &cache);
        expire_pending(sock, now_seconds());
    }

    close(up_sock);
    close(sock);
    return 0;
}