#ifndef DNS_PENDING_H
#define DNS_PENDING_H
#include <stdbool.h>
#include <stdint.h>
#include <netinet/in.h>

#include "packet.h"

#define PENDING_SIZE 1024

// A query that has been sent upstream and is waiting for a reply
typedef struct query {
    bool in_use;
    uint16_t id;               // ID sent upstream (also picks the slot)
    uint16_t client_id;        // ID the client used, restored before replying
    struct sockaddr_in client; // Where to send the reply
    socklen_t client_len;
    dns_question question;
    time_t expires_at;
} query;

int pending_add(const query *q);
query *pending_find(uint16_t id);
void pending_remove(query *q);
query *pending_next_expired(time_t now);
time_t pending_earliest(void);

#endif //DNS_PENDING_H
