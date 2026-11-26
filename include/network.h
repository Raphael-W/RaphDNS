#ifndef DNS_NETWORK_H
#define DNS_NETWORK_H

#include <stdbool.h>

#include "blocklist.h"
#include "local.h"

#define QUERY_TIMEOUT_SECONDS 2

int network_listen(int port, const char* ip, list *blocklist, local_records *l_records, bool log_queries);

#endif //DNS_NETWORK_H
