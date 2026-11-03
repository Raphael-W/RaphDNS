#ifndef DNS_NETWORK_H
#define DNS_NETWORK_H

#include "packet.h"
#include "blocklist.h"

#define QUERY_TIMEOUT_SECONDS 2

int network_listen(int port, list *blocklist);
int network_query(const char *ip, const uint8_t *query, size_t query_len, uint8_t *buf, size_t buf_size);

#endif //DNS_NETWORK_H
