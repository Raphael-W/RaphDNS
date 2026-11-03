#ifndef DNS_NETWORK_H
#define DNS_NETWORK_H

#include "packet.h"
#include "blocklist.h"

#define QUERY_TIMEOUT_SECONDS 2

int network_listen(int port, list *blocklist);

#endif //DNS_NETWORK_H
