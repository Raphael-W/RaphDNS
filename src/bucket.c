#include "bucket.h"
#include "helpers.h"

#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#define TTL_MAX 86400

static uint32_t min_u32(uint32_t a, uint32_t b) {
    return a < b ? a : b;
}

uint32_t packet_min_ttl(const dns_packet *p) {
    uint32_t min_ttl = -1;
    // Check answer
    for (int i = 0; i < p->an_count; i++) {
        min_ttl = min_u32(min_ttl, p->answers[i].ttl);
    }

    // Authority
    for (int i = 0; i < p->ns_count; i++) {
        min_ttl = min_u32(min_ttl, p->authority[i].ttl);
    }

    // Additional
    for (int i = 0; i < p->ar_count; i++) {
        if (p->additional[i].type != DNS_TYPE_OPT) {
            min_ttl = min_u32(min_ttl, p->additional[i].ttl);
        }
    }

    if (min_ttl == UINT32_MAX) {min_ttl = 0;}
    else if (min_ttl > TTL_MAX) {min_ttl = TTL_MAX;}
    return min_ttl;
}

bool questions_eq(dns_question *a, dns_question *b) {
    return strcmp(a->name, b->name) == 0 && (a->type == b->type) && (a->class == b->class);
}

entry *create_entry(uint64_t hash, dns_packet packet) {
    entry* new_entry = malloc(sizeof *new_entry);

    time_t expires_at = now_seconds() + packet_min_ttl(&packet);

    new_entry->hash = hash;
    new_entry->packet = packet;
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

entry* lookup_entry(bucket *bucket, uint64_t hash, dns_question *question) {
    entry *before = NULL;
    entry *current = bucket->first;
    while (current != NULL) {
        if (current->expires_at <= now_seconds()) {
            entry* next = current->next;
            if (before) before->next = next; else bucket->first = next;
            if (bucket->last == current) bucket->last = before;
            free_dns_packet(&current->packet);
            free(current);
            continue;
        }
        if ((current->hash == hash) && questions_eq(question, &current->packet.question)) {
            return current;
        }
        before = current;
        current = current->next;
    }
    return NULL;
}