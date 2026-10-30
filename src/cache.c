#include "cache.h"
#include "helpers.h"

#include <ctype.h>
#include <string.h>

#define MAX_LOAD_FACTOR 0.75
#define FNV_OFFSET 0xcbf29ce484222325ULL
#define TTL_MAX 86400

// HASHING

static uint64_t fnv1a(uint64_t h, const uint8_t *data, size_t len) {
     for (size_t i = 0; i < len; i++) {
          h ^= data[i];
          h *= 0x100000001b3ULL;
     }
     return h;
}

static uint64_t key_hash(const dns_question *q) {
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

static bool questions_eq(const dns_question *a, const dns_question *b) {
     return strcasecmp(a->name, b->name) == 0 && (a->type == b->type) && (a->class == b->class);
}

// TTL HANDLING

static uint32_t min_u32(uint32_t a, uint32_t b) {
     return a < b ? a : b;
}

static uint32_t packet_min_ttl(const dns_packet *p) {
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

static void age_records(dns_record *recs, uint16_t count, uint32_t age) {
     for (uint16_t i = 0; i < count; i++) {
          if (recs[i].type == DNS_TYPE_OPT) continue;
          uint32_t *ttl = &recs[i].ttl;
          *ttl = *ttl > age ? *ttl - age: 0;
     }
}

static void update_ttl(cache_entry *e) {
     time_t now = now_seconds();
     uint32_t age = (uint32_t)(now - e->updated_at);
     age_records(e->packet.answers, e->packet.an_count, age);
     age_records(e->packet.authority, e->packet.ns_count, age);
     age_records(e->packet.additional, e->packet.ar_count, age);
     e->updated_at = now;
}

cache cache_create(const size_t bucket_count) {
     cache new_cache = {0};
     new_cache.buckets = calloc(bucket_count, sizeof *new_cache.buckets);
     new_cache.bucket_count = bucket_count;

     if (!new_cache.buckets) {
          new_cache.bucket_count = 0;
     }

     return new_cache;
}

void resize_cache(cache *c, size_t new_count) {
     cache_entry **new_buckets = calloc(new_count, sizeof *new_buckets);
     if (!new_buckets) return;

     for (size_t i = 0; i < c->bucket_count; i++) {
          cache_entry *e = c->buckets[i];
          while (e) {
               cache_entry *next = e->next;
               cache_entry **head = &new_buckets[e->hash % new_count];
               e->next = *head;
               *head = e;
               e = next;
          }
     }
     free(c->buckets);
     c->buckets = new_buckets;
     c->bucket_count = new_count;
}

void cache_free(cache *c) {
     for (size_t i = 0; i < c->bucket_count; i++) {
          cache_entry *e = c->buckets[i];
          while (e) {
               cache_entry *next = e->next;
               free_dns_packet(&e->packet);
               free(e);
               e = next;
          }
     }
     free(c->buckets);
     c->buckets = NULL;
     c->bucket_count = 0;
     c->entry_count = 0;
}

void cache_insert(cache *c, dns_packet p) {
     uint64_t hash = key_hash(&p.question);

     uint32_t ttl = packet_min_ttl(&p);
     if (ttl == 0) { free_dns_packet(&p); return; } // Not cacheable

     cache_entry *e = malloc(sizeof *e);
     if (!e) { free_dns_packet(&p); return; } // Error allocating memory

     time_t now = now_seconds();
     e->hash = hash;
     e->expires_at = now + ttl;
     e->updated_at = now;
     e->packet = p;

     cache_entry **head = &c->buckets[hash % c->bucket_count];
     e->next = *head;
     *head = e;
     c->entry_count++;

     const double load_factor = (double)c->entry_count / (double)c->bucket_count;
     if (load_factor >= MAX_LOAD_FACTOR) {
          size_t new_size = c->bucket_count * 2;
          resize_cache(c, new_size);
     }
}

const dns_packet *cache_lookup(cache *c, const dns_question *q) {
     uint64_t hash = key_hash(q);
     cache_entry **pp = &c->buckets[hash % c->bucket_count];
     while (*pp) {
          cache_entry *e = *pp;
          if (e->expires_at < now_seconds()) {
               *pp = e->next;
               free_dns_packet(&e->packet);
               free(e);
               c->entry_count--;
               continue;
          }
          if (e->hash == hash && questions_eq(&e->packet.question, q)) {
               update_ttl(e);
               return &e->packet;
          }
          pp = &e->next;
     }
     return NULL;
}