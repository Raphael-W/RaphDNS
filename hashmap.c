#include "hashmap.h"
#include "bucket.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <inttypes.h>

uint64_t fnv1a(const uint8_t *data, size_t len) {
    uint64_t h = 0xcbf29ce484222325ULL;
    for (size_t i = 0; i < len; i++) {
        h ^= data[i];
        h *= 0x100000001b3ULL;
    }
    return h;
}

uint64_t key_hash(const uint8_t *domain) {
    return fnv1a(domain, strlen((char*) domain));
}

hashmap create_hashmap(int size) {
    hashmap new_hashmap;
    new_hashmap.buckets = calloc(size, sizeof (bucket *));
    new_hashmap.size = size;
    for (int i = 0; i < size; i++) {
        new_hashmap.buckets[i] = create_bucket();
    }
    return new_hashmap;
}

void hashmap_add(hashmap h, char* domain, long ip) {
    uint64_t domain_hash = key_hash((uint8_t *) domain);
    int bucket_index = (int) (domain_hash % h.size);
    cache_entry(h.buckets[bucket_index], create_entry(domain_hash, domain, ip));
    printf("Inserted %s (%" PRIu64") into bucket %d\n", domain, domain_hash, bucket_index);
}

entry* hashmap_lookup(hashmap h, char* domain) {
    uint64_t domain_hash = key_hash((uint8_t *) domain);
    int bucket_index = (int) (domain_hash % h.size);
    entry *cached_entry = lookup_entry(h.buckets[bucket_index], domain_hash, domain);
    return cached_entry;
}