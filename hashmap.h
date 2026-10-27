#ifndef DNS_HASHMAP_H
#define DNS_HASHMAP_H

#include <stddef.h>
#include <stdint.h>

#include "bucket.h"

typedef struct hashmap {
    bucket* *buckets;
    int size;
} hashmap;

uint64_t fnv1a(const uint8_t *data, size_t len);
uint64_t key_hash(const uint8_t *domain);
hashmap create_hashmap(int size);
void hashmap_add(hashmap h, char* domain, long ip);
entry* hashmap_lookup(hashmap h, char* domain);

#endif //DNS_HASHMAP_H
