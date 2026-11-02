#ifndef DNS_NETWORK_H
#define DNS_NETWORK_H

#include "packet.h"

int network_listen(int port);
int network_query(const char *ip, const uint8_t *query, size_t query_len, uint8_t *buf, size_t buf_size);

#endif //DNS_NETWORK_H
