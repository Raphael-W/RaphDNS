#ifndef DNS_CACHE_H
#define DNS_CACHE_H
#include <stdint.h>
#include <time.h>

#include "packet.h"

typedef struct cache_entry {
    uint64_t hash;
    time_t expires_at;
    time_t updated_at;
    dns_packet packet;
    struct cache_entry *next;
} cache_entry;

typedef struct cache {
    cache_entry **buckets;
    size_t bucket_count;
    size_t entry_count;
} cache;

cache cache_create(size_t bucket_count);
void resize_cache(cache *c, size_t new_count);
void cache_free(cache *c);
void cache_insert(cache *c, dns_packet p);
const dns_packet *cache_lookup(cache *c, const dns_question *q);

#endif //DNS_CACHE_H
