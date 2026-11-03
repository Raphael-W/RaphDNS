#ifndef DNS_PENDING_H
#define DNS_PENDING_H
#include <stdbool.h>
#include <stdint.h>
#include <netinet/in.h>

#include "packet.h"

#define PENDING_SIZE 1024
#define MAX_SERVERS 13
#define MAX_NS_NAMES 4
#define MAX_CNAMES 8

// A CNAME followed during a lookup, added to the final answer
typedef struct {
    char name[256];
    uint32_t ttl;
    uint16_t rdlength;
    uint8_t rdata[256];
} saved_cname;

// A query that has been sent upstream and is waiting for a reply
typedef struct query {
    bool in_use;
    uint16_t id;               // ID sent upstream (also picks the slot)
    uint16_t client_id;        // ID the client used, restored before replying
    struct sockaddr_in client; // Where to send the reply
    socklen_t client_len;
    dns_question question;     // Name currently being looked up
    dns_question original;     // Name the client asked for
    time_t expires_at;

    char servers[MAX_SERVERS][INET_ADDRSTRLEN];
    int server_count;
    int current;
    int queries_left;
    struct query *parent;

    bool waiting;
    char ns_names[MAX_NS_NAMES][256];
    int ns_count;
    int ns_current;

    saved_cname cnames[MAX_CNAMES];
    int cname_count;
} query;

int pending_add(const query *q);
query *pending_find(uint16_t id);
void pending_remove(query *q);
query *pending_next_expired(time_t now);
time_t pending_earliest(void);

#endif //DNS_PENDING_H
