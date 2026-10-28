#include "hashmap.h"
#include "bucket.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define MAX_LOAD_FACTOR 0.75

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

int bucket_index(uint64_t hash, int size) {
    return (int) (hash % size);
}

hashmap create_hashmap(int size) {
    hashmap new_hashmap;
    new_hashmap.buckets = calloc(size, sizeof (bucket *));
    new_hashmap.bucket_count = size;
    new_hashmap.entry_count = 0;
    for (int i = 0; i < size; i++) {
        new_hashmap.buckets[i] = create_bucket();
    }
    return new_hashmap;
}

void resize_hashmap(hashmap *h, int new_size) {
    bucket **new_buckets = calloc(new_size, sizeof *new_buckets);
    for (int i = 0; i < new_size; i++) {
        new_buckets[i] = create_bucket();
    }

    for (int i = 0; i < h->bucket_count; i++) {
        bucket* current_bucket = h->buckets[i];
        entry* current = current_bucket->first;
        while (current != NULL) {
            entry* next = current -> next;
            current -> next = NULL;
            int new_index = bucket_index(current->hash, new_size);
            cache_entry(new_buckets[new_index], current);
            current = next;
        }
        free(current_bucket);
    }

    h->bucket_count = new_size;
    free(h->buckets);
    h->buckets = new_buckets;
}

void hashmap_insert(hashmap *h, char* domain, long ip) {
    uint64_t domain_hash = key_hash((uint8_t *) domain);
    int index = bucket_index(domain_hash, h->bucket_count);
    cache_entry(h->buckets[index], create_entry(domain_hash, domain, ip, 300));
    h->entry_count++;

    double load_factor = (double) h->entry_count / h->bucket_count;
    if (load_factor >= MAX_LOAD_FACTOR) {
        int old_size = h->bucket_count;
        int new_size = h->bucket_count * 2;
        resize_hashmap(h, new_size);
        printf("Hashmap resized from %d buckets to %d\n", old_size, new_size);
    }
    printf("Inserted %s into bucket %d\n", domain, index);
}

entry* hashmap_lookup(hashmap *h, char* domain) {
    uint64_t domain_hash = key_hash((uint8_t *) domain);
    int index = bucket_index(domain_hash, h->bucket_count);
    entry *cached_entry = lookup_entry(h->buckets[index], domain_hash, domain);

    return cached_entry;
}