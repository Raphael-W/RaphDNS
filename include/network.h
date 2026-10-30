#ifndef DNS_NETWORK_H
#define DNS_NETWORK_H
#include "packet.h"

int network_listen(int port);
long send_dns_packet(const char *server_ip, const uint8_t *query, size_t query_len, uint8_t *out, size_t out_size);

#endif //DNS_NETWORK_H
