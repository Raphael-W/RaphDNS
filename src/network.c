#include "network.h"
#include "packet.h"
#include "cache.h"

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/socket.h>

#define BUF_SIZE 4096
#define RESOLVER_IP "152.78.255.75"

static int make_error(const dns_packet *query, uint8_t rcode, uint8_t *out, size_t out_size) {
    dns_packet fail = *query;
    fail.qr = 1;
    fail.ra = 1;
    fail.rcode = rcode;
    fail.an_count = fail.ns_count = fail.ar_count = 0;
    return create_dns_packet(out, out_size, &fail);
}

long send_dns_packet(const char *server_ip, const uint8_t *query, size_t query_len, uint8_t *out, size_t out_size) {
    int sock = socket(AF_INET, SOCK_DGRAM, 0);
    if (sock < 0) return -1;

    struct timeval tv = { .tv_sec = 2, .tv_usec = 0 };
    setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof tv);

    struct sockaddr_in server = {0};
    server.sin_family = AF_INET;
    server.sin_port = htons(53);
    if (inet_pton(AF_INET, server_ip, &server.sin_addr) != 1) {
        close(sock);
        return -1;
    }

    if (connect(sock, (struct sockaddr *)&server, sizeof server) < 0 ||
        send(sock, query, query_len, 0) < 0) {
        close(sock);
        return -1;
    }

    ssize_t n = recv(sock, out, out_size, 0);
    close(sock);
    if (n < 12) return -1; //too short for a DNS header
    if (out[0] != query[0] || out[1] != query[1]) return -1; // wrong ID
    return n;
}

int network_listen(int port) {
    cache cache = cache_create(8);

    int sock = socket(AF_INET, SOCK_DGRAM, 0);
    if (sock < 0) {
        perror("socket");
        return 1;
    }

    // Let you restart the server without waiting for the port to free up
    int yes = 1;
    setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, &yes, sizeof yes);

    // 2. Bind it to a port, so packets sent there arrive at this socket
    struct sockaddr_in addr = {0};
    addr.sin_family = AF_INET;
    addr.sin_port = htons(port); // network byte order
    addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK); // 127.0.0.1 only, for now

    if (bind(sock, (struct sockaddr *)&addr, sizeof addr) < 0) {
        perror("bind");
        return 1;
    }
    printf("Listening on 127.0.0.1:%d\n", port);

    // 3. Receive packets forever
    uint8_t buf[BUF_SIZE];
    for (;;) {
        struct sockaddr_in client;
        socklen_t client_len = sizeof client;

        // Receive packet and store in buf
        ssize_t n = recvfrom(sock, buf, sizeof buf, 0, (struct sockaddr *)&client, &client_len);
        if (n < 0) { perror("recvfrom"); continue; }

        char ip[INET_ADDRSTRLEN];
        inet_ntop(AF_INET, &client.sin_addr, ip, sizeof ip);

        // Parse DNS packet
        dns_packet packet = {0};
        if (parse_dns_packet(buf, n, &packet) < 0) {
            printf("Malformed request packet\n");
            free_dns_packet(&packet);
            continue;
        }

        uint8_t response_buf[BUF_SIZE];
        ssize_t response_length = 0;

        if (packet.qr == 1) {
            free_dns_packet(&packet);
            continue;
        }
        if (packet.qd_count != 1) {
            response_length = make_error(&packet, DNS_RCODE_FORMERR, response_buf, sizeof response_buf);
        }

        else { // Valid request
            printf("Received DNS request for %s\n", packet.question.name);
            const dns_packet *cached = cache_lookup(&cache, &packet.question);
            if (cached) { // Cache exists
                dns_packet reply = *cached;
                reply.id = packet.id;
                reply.question = packet.question;
                response_length = create_dns_packet(response_buf, sizeof response_buf, &reply);
            }
            else { // Fetch answer upstream
                response_length = send_dns_packet(RESOLVER_IP, buf, n, response_buf, sizeof response_buf);
                if (response_length >= 0) {
                    dns_packet cached_packet = {0};
                    if (parse_dns_packet(response_buf, response_length, &cached_packet) >= 0 &&
                        (cached_packet.rcode == DNS_RCODE_NOERROR || cached_packet.rcode == DNS_RCODE_NXDOMAIN) &&
                        !cached_packet.tc) {
                        cache_insert(&cache, cached_packet);
                    }
                    else {
                        free_dns_packet(&cached_packet);
                    }
                }
            }
        }

        if (response_length < 0) {
            response_length = make_error(&packet, DNS_RCODE_SERVFAIL, response_buf, sizeof response_buf);
        }

        if (response_length >= 0) {
            sendto(sock, response_buf, response_length, 0, (struct sockaddr *)&client, client_len);
        }
        free_dns_packet(&packet);
    }

    close(sock);
    return 0;
}