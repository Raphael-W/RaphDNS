#include "network.h"
#include "packet.h"

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/socket.h>

#define BUF_SIZE 4096

long send_dns_packet(dns_packet *p, const char *server_ip, uint8_t *out, size_t out_size, dns_packet *r) {
    uint8_t query_packet[BUF_SIZE];
    size_t query_length = create_dns_packet(query_packet, BUF_SIZE, p);

    int sock = socket(AF_INET, SOCK_DGRAM, 0);
    if (sock < 0) return -1;

    struct timeval tv = { .tv_sec = 2, .tv_usec = 0 };
    setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof tv);

    struct sockaddr_in server = {0};
    server.sin_family = AF_INET;
    server.sin_port = htons(53);
    inet_pton(AF_INET, server_ip, &server.sin_addr);

    if (sendto(sock, query_packet, query_length, 0, (struct sockaddr *)&server, sizeof server) < 0) {
        close(sock);
        return -1;
    }

    ssize_t n = recvfrom(sock, out, out_size, 0, NULL, NULL);
    close(sock);
    if (n < 0) return -1;

    if (parse_dns_packet(out, n, r) < 0) return -1;
    return n;
}

int network_listen(int port) {
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

        ssize_t n = recvfrom(sock, buf, sizeof buf, 0,
                             (struct sockaddr *)&client, &client_len);
        if (n < 0) {
            perror("recvfrom");
            continue;
        }

        char ip[INET_ADDRSTRLEN];
        inet_ntop(AF_INET, &client.sin_addr, ip, sizeof ip);

        dns_packet packet = {0};
        if (parse_dns_packet(buf, n, &packet) < 0) {
            printf("Malformed request packet\n");
            free_dns_packet(&packet);
            continue;
        }

        if ((packet.qr == 0) && (packet.qd_count == 1)) {
            printf("Received DNS request for %s\n", packet.question.name);
        }

        dns_packet response = {0};
        uint8_t response_buf[BUF_SIZE];
        long response_length = send_dns_packet(&packet, "1.1.1.1", response_buf, sizeof response_buf, &response);
        if (response_length >= 0) {
            sendto(sock, response_buf, response_length, 0, (struct sockaddr *)&client, client_len);
        }
        else {
            printf("Malformed response packet:\n");
            for (int i = 0; i < n; i++) {
                printf("%02x ", buf[i]);
            }
            printf("\n");
        }

        free_dns_packet(&packet);
        free_dns_packet(&response);
    }

    close(sock);
    return 0;
}