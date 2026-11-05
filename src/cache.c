#include "cache.h"
#include "helpers.h"

#include <ctype.h>
#include <string.h>

#define MAX_LOAD_FACTOR 0.75
#define MAX_ENTRY_COUNT 10000
#define TTL_MAX 86400

// HASHING
// Returns the hash of a DNS question (case-insensitive name + type + class)
static uint64_t key_hash(const dns_question *q) {
     uint64_t h = FNV_OFFSET;
     // Hash hostname
     for (const char *c = q->name; *c; c++) {
          uint8_t lower = (uint8_t) tolower((unsigned char) *c);
          h = fnv1a(h, &lower, 1);
     }

     // Hash type + class
     const uint8_t rest[4] = {q->type >> 8, q->type & 0xFF, q->class >> 8, q->class & 0xFF};
     return fnv1a(h, rest, sizeof rest);
}

// Returns true if two questions are equal, ignoring case in the name
static bool questions_eq(const dns_question *a, const dns_question *b) {
     return strcasecmp(a->name, b->name) == 0 && (a->type == b->type) && (a->class == b->class);
}

// TTL HANDLING
// Returns the lower of the two values
static uint32_t min_u32(const uint32_t a, const uint32_t b) {
     return a < b ? a : b;
}

static bool soa_minimum(const dns_record *rec, uint32_t *out) {
     if (rec->rdlength < 22) return false; // Two names (1 byte each) + 5 * 32-bit fields
     const uint8_t *m = rec->rdata + rec->rdlength - 4;
     *out = (uint32_t)m[0] << 24 | (uint32_t)m[1] << 16 | (uint32_t)m[2] << 8 | m[3];
     return true;
}

static void clamp_soa_ttls(dns_packet *p) {
     for (int i = 0; i < p->ns_count; i++) {
          dns_record *rec = &p->authority[i];
          uint32_t minimum;
          if (rec->type == DNS_TYPE_SOA && soa_minimum(rec, &minimum)) {
               rec->ttl = min_u32(rec->ttl, minimum);
          }
     }
}

// Returns the smallest TTL in the packet (the record that will expire first), ignoring OPT records
// Capped at TTL_MAX, or 0 if there are no records to check
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

// Reduces the TTL of each record in the list by age seconds, stopping at 0
// Skips OPT records, as their TTL field isn't a real TTL
static void age_records(dns_record *recs, const uint16_t count, const uint32_t age) {
     for (uint16_t i = 0; i < count; i++) {
          if (recs[i].type == DNS_TYPE_OPT) continue;
          uint32_t *ttl = &recs[i].ttl;
          *ttl = *ttl > age ? *ttl - age: 0;
     }
}

// Reduces the TTL of all the entry's records by the time since this was last done
static void update_ttl(cache_entry *e) {
     const time_t now = now_seconds();
     const uint32_t age = (uint32_t)(now - e->updated_at);
     age_records(e->packet.answers, e->packet.an_count, age);
     age_records(e->packet.authority, e->packet.ns_count, age);
     age_records(e->packet.additional, e->packet.ar_count, age);
     e->updated_at = now;
}

// Iterate over all entries and remove any that have expired
// Returns how many records were removed
static int sweep_expired(cache *c) {
     int removed_count = 0;
     time_t now = now_seconds();
     for (size_t i = 0; i < c->bucket_count; i++) {
          cache_entry **pp = &c->buckets[i];
          while (*pp) {
               cache_entry *e = *pp;
               if (e->expires_at < now) {
                    *pp = e->next;
                    free_dns_packet(&e->packet);
                    free(e);
                    c->entry_count--;
                    removed_count++;
                    continue;
               }
               pp = &e->next;
          }
     }
     return removed_count;
}

// Remove the `count` of entries that next about to expire
static void remove_next_expired(cache *c, int count) {
     cache_entry *soon_to_expire[count];
     int arr_count = 0;
     for (size_t i = 0; i < c->bucket_count; i++) {
          cache_entry *e = c->buckets[i];
          while (e) {
               cache_entry *next = e->next;
               if (arr_count < count || e->expires_at < (soon_to_expire[arr_count - 1]->expires_at)) {
                    int j = (arr_count < count) ? arr_count++ : count - 1;
                    while (j > 0 && soon_to_expire[j - 1]->expires_at > e->expires_at) {
                         soon_to_expire[j] = soon_to_expire[j - 1];
                         j--;
                    }
                    soon_to_expire[j] = e;
               }
               e = next;
          }
     }

     for (int i = 0; i < arr_count; i++) {
          cache_entry **pp = &c->buckets[soon_to_expire[i]->hash % c->bucket_count];
          while (*pp) {
               cache_entry *e = *pp;
               if (e == soon_to_expire[i]) {
                    *pp = e->next;
                    free_dns_packet(&e->packet);
                    free(e);
                    c->entry_count--;
                    break;
               }
               pp = &e->next;
          }
     }
}

// MAIN
// Returns an empty cache with `bucket_count` buckets, or with 0 buckets if allocation fails
cache cache_create(const size_t bucket_count) {
     cache new_cache = {0};
     new_cache.buckets = calloc(bucket_count, sizeof *new_cache.buckets);
     new_cache.bucket_count = bucket_count;

     if (!new_cache.buckets) { new_cache.bucket_count = 0; }
     return new_cache;
}

// Resizes the cache and moves all existing entries to their new buckets
// Leaves the cache unchanged if allocation fails
void resize_cache(cache *c, const size_t new_count) {
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

// Frees every entry in the cache and its bucket array, leaving it empty
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

// Takes ownership of p and adds it to the cache, growing the cache if it's too full
// p is freed instead if it can't be cached
void cache_insert(cache *c, dns_packet p) {
     clamp_soa_ttls(&p);
     const uint64_t hash = key_hash(&p.question);
     const uint32_t ttl = packet_min_ttl(&p);

     if (ttl == 0) { free_dns_packet(&p); return; } // Not cacheable

     // If MAX ENTRY COUNT hit, first try sweeping expired records, then delete soon-to-expire records
     if (c->entry_count >= MAX_ENTRY_COUNT) {
          if (sweep_expired(c) < 100) { remove_next_expired(c, 100); }
     }

     cache_entry *e = malloc(sizeof *e);
     if (!e) { free_dns_packet(&p); return; } // Error allocating memory

     const time_t now = now_seconds();
     e->hash = hash;
     e->expires_at = now + ttl;
     e->updated_at = now;
     e->packet = p;

     cache_entry **head = &c->buckets[hash % c->bucket_count];
     e->next = *head;
     *head = e;
     c->entry_count++;

     // Check whether an expired entry sweep is enough to lower the load factor first
     double load_factor = (double)c->entry_count / (double)c->bucket_count;
     if (load_factor >= MAX_LOAD_FACTOR) { sweep_expired(c); }

     load_factor = (double)c->entry_count / (double)c->bucket_count;
     if (load_factor >= MAX_LOAD_FACTOR) {
          const size_t new_size = c->bucket_count * 2;
          resize_cache(c, new_size);
     }
}

// Returns the cached packet that answers the question, or NULL if there isn't one
// Removes any expired entries it finds along the way
const dns_packet *cache_lookup(cache *c, const dns_question *q) {
     const uint64_t hash = key_hash(q);
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