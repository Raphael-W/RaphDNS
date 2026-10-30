#ifndef DNS_HASHMAP_H
#define DNS_HASHMAP_H

#include <stddef.h>
#include <stdint.h>

#include "bucket.h"

typedef struct hashmap {
    bucket** buckets;
    int bucket_count;
    int entry_count;
} hashmap;

uint64_t fnv1a(uint64_t h, const uint8_t *data, size_t len);
uint64_t key_hash(dns_question *q);
int bucket_index(uint64_t hash, int size);
hashmap create_hashmap(int size);
void resize_hashmap(hashmap *h, int new_size);
void hashmap_insert(hashmap *h, dns_packet p);
const dns_packet* hashmap_lookup(hashmap *h, dns_question *q);

#endif //DNS_HASHMAP_H
