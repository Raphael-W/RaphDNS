#ifndef DNS_NETWORK_H
#define DNS_NETWORK_H

#include <stdbool.h>

#include "packet.h"
#include "blocklist.h"

#define QUERY_TIMEOUT_SECONDS 2

int network_listen(int port, const char* ip, list *blocklist, bool log_queries);

#endif //DNS_NETWORK_H
