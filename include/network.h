#ifndef DNS_NETWORK_H
#define DNS_NETWORK_H
#include "packet.h"

int network_listen(int port);
long send_dns_packet(dns_packet *p, const char *server_ip, uint8_t *out, size_t out_size, dns_packet *r);

#endif //DNS_NETWORK_H
