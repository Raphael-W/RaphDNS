#include "bucket.h"
#include "helpers.h"

#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

entry *create_entry(uint64_t hash, char* domain, long ip, uint32_t ttl) {
    entry* new_entry = malloc(sizeof *new_entry);

    time_t expires_at = now_seconds() + ttl;

    new_entry->hash = hash;
    new_entry->domain = domain;
    new_entry->ip = ip;
    new_entry->expires_at = expires_at;
    new_entry->next = NULL;

    return new_entry;
}

bucket *create_bucket() {
    bucket* new_bucket = malloc(sizeof *new_bucket);

    new_bucket->first = NULL;
    new_bucket->last = NULL;

    return new_bucket;
}

void cache_entry(bucket *bucket, entry *cache_entry) {
    if (bucket->last == NULL) {
        bucket->first = cache_entry;
        bucket->last = cache_entry;
    }
    else {
        bucket->last->next = cache_entry;
        bucket->last = cache_entry;
    }
}

entry* lookup_entry(bucket *bucket, uint64_t hash, char* domain) {
    entry *before = NULL;
    entry *current = bucket->first;
    while (current != NULL) {
        if (current->expires_at <= now_seconds()) {
            before->next = current->next;
            free(current);
            continue;
        }
        if ((current->hash == hash) && (strcmp(current->domain, domain) == 0)) {
            return current;
        }
        current = current->next;
        before = current;
    }
    return NULL;
}