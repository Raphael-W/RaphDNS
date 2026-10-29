#include "network.h"
#include "packet.h"

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/socket.h>

#define BUF_SIZE 4096

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
        printf("\n%zd bytes from %s:%d\n", n, ip, ntohs(client.sin_port));
        for (ssize_t i = 0; i < n; i++)
            printf("%02x%s", buf[i], (i % 16 == 15) ? "\n" : " ");
        printf("\n");
        dns_packet packet;
        if (parse_dns_packet(buf, n, &packet) < 0) {
            printf("Malformed packet\n");
            free_dns_packet(&packet);
            continue;
        }
        print_dns_packet(&packet);

        uint8_t new_buf[BUF_SIZE];
        int packet_length = create_dns_packet(new_buf, BUF_SIZE, &packet);
        if (packet_length >= 0) {
            printf("\nWhen parsed and recreated gives this:\n");
            for (ssize_t i = 0; i < packet_length; i++)
                printf("%02x%s", new_buf[i], (i % 16 == 15) ? "\n" : " ");
            printf("\n");

            dns_packet new_packet;
            if (parse_dns_packet(new_buf, packet_length, &new_packet) < 0) {
                printf("Malformed packet\n");
                free_dns_packet(&new_packet);
                continue;
            }
            print_dns_packet(&new_packet);
            free_dns_packet(&new_packet);
        }
        free_dns_packet(&packet);
    }

    close(sock);
    return 0;
}