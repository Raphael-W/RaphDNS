#include "hashmap.h"
#include "bucket.h"

#include <ctype.h>
#include <stdlib.h>

#define MAX_LOAD_FACTOR 0.75
#define FNV_OFFSET 0xcbf29ce484222325ULL

uint64_t fnv1a(uint64_t h, const uint8_t *data, size_t len) {
    for (size_t i = 0; i < len; i++) {
        h ^= data[i];
        h *= 0x100000001b3ULL;
    }
    return h;
}

uint64_t key_hash(dns_question *q) {
    uint64_t h = FNV_OFFSET;
    // Hash hostname
    for (const char *c = q->name; *c; c++) {
        uint8_t lower = (uint8_t) tolower((unsigned char) *c);
        h = fnv1a(h, &lower, 1);
    }

    // Hash type + class
    uint8_t rest[4] = {q->type >> 8, q->type & 0xFF, q->class >> 8, q->class & 0xFF};
    return fnv1a(h, rest, sizeof rest);
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

void hashmap_insert(hashmap *h, dns_packet p) {
    uint64_t hash = key_hash(&p.question);
    int index = bucket_index(hash, h->bucket_count);

    if (packet_min_ttl(&p) == 0) {
        free_dns_packet(&p);
        return;
    }
    cache_entry(h->buckets[index], create_entry(hash, p));
    h->entry_count++;

    double load_factor = (double) h->entry_count / h->bucket_count;
    if (load_factor >= MAX_LOAD_FACTOR) {
        int new_size = h->bucket_count * 2;
        resize_hashmap(h, new_size);
    }
}

const dns_packet* hashmap_lookup(hashmap *h, dns_question *q) {
    uint64_t hash = key_hash(q);
    int index = bucket_index(hash, h->bucket_count);
    entry *cached_entry = lookup_entry(h->buckets[index], hash, q);

    return cached_entry ? &cached_entry->packet : NULL;
}