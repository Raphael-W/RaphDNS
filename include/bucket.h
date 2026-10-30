#ifndef DNS_BUCKET_H
#define DNS_BUCKET_H
#include <stdint.h>
#include <time.h>
#include "packet.h"

typedef struct entry {
    uint64_t hash;
    dns_packet packet;
    time_t expires_at;
    struct entry *next;
} entry;

typedef struct bucket {
    entry *first;
    entry *last;
} bucket;

uint32_t packet_min_ttl(const dns_packet *p);
entry *create_entry(uint64_t hash, dns_packet packet);
bucket *create_bucket();
void cache_entry(bucket *bucket, entry *cache_entry);
entry* lookup_entry(bucket *bucket, uint64_t hash, dns_question *question);

#endif //DNS_BUCKET_H
