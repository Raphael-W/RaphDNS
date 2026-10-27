#ifndef DNS_BUCKET_H
#define DNS_BUCKET_H
#include <stdint.h>
#include <time.h>

typedef struct entry {
    uint64_t hash;
    char* domain;
    long ip;
    time_t expires_at;
    struct entry *next;
} entry;

typedef struct bucket {
    entry *first;
    entry *last;
} bucket;

entry *create_entry(uint64_t hash, char* domain, long ip, uint32_t ttl);
bucket *create_bucket();
void cache_entry(bucket *bucket, entry *cache_entry);
entry* lookup_entry(bucket *bucket, uint64_t hash, char* domain);

#endif //DNS_BUCKET_H
