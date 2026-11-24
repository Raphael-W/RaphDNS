#include "cache.h"
#include "harness.h"

#include <string.h>

// FIXTURES
// The cache takes ownership of inserted packets, so records and rdata have to be on the heap

// Returns a heap-allocated record with a copy of rdata
static dns_record *make_record(const char *name, const uint16_t type, const uint32_t ttl,
                               const uint8_t *rdata, const uint16_t rdlength) {
    dns_record *r = calloc(1, sizeof *r);
    strncpy(r->name, name, sizeof r->name - 1);
    r->type = type;
    r->class = DNS_CLASS_IN;
    r->ttl = ttl;
    r->rdlength = rdlength;
    r->rdata = malloc(rdlength);
    memcpy(r->rdata, rdata, rdlength);
    return r;
}

// Returns a response to `name` (type, class IN) with a single A record answer with the given TTL
static dns_packet make_response(const char *name, const uint16_t type, const uint32_t ttl) {
    static const uint8_t ip[] = {93, 184, 215, 14};
    dns_packet p = {.id = 0x1234, .qr = 1, .rd = 1, .ra = 1, .qd_count = 1, .an_count = 1};
    strncpy(p.question.name, name, sizeof p.question.name - 1);
    p.question.type = type;
    p.question.class = DNS_CLASS_IN;
    p.answers = make_record(name, DNS_TYPE_A, ttl, ip, sizeof ip);
    return p;
}

static dns_question make_question(const char *name, const uint16_t type, const uint16_t class) {
    dns_question q = {.type = type, .class = class};
    strncpy(q.name, name, sizeof q.name - 1);
    return q;
}

// Returns true if every entry is in the bucket its hash maps to
static bool entries_in_correct_buckets(const cache *c) {
    for (size_t i = 0; i < c->bucket_count; i++) {
        for (const cache_entry *e = c->buckets[i]; e; e = e->next) {
            if (e->hash % c->bucket_count != i) return false;
        }
    }
    return true;
}

// CREATING
static void test_create_cache(void) {
    cache c = cache_create(8);
    CHECK(c.buckets != NULL);
    CHECK(c.bucket_count == 8);
    CHECK(c.entry_count == 0);
    bool all_empty = true;
    for (size_t i = 0; i < c.bucket_count; i++) {
        if (c.buckets[i]) all_empty = false;
    }
    CHECK(all_empty);
    cache_free(&c);
}

static void test_free_empties_cache(void) {
    cache c = cache_create(8);
    cache_insert(&c, make_response("example.com", DNS_TYPE_A, 300));
    cache_free(&c);
    CHECK(c.buckets == NULL);
    CHECK(c.bucket_count == 0);
    CHECK(c.entry_count == 0);
}

// LOOKUP
static void test_lookup_empty_cache_misses(void) {
    cache c = cache_create(8);
    const dns_question q = make_question("example.com", DNS_TYPE_A, DNS_CLASS_IN);
    CHECK(cache_lookup(&c, &q) == NULL);
    cache_free(&c);
}

static void test_insert_then_lookup_hits(void) {
    cache c = cache_create(8);
    cache_insert(&c, make_response("example.com", DNS_TYPE_A, 300));
    CHECK(c.entry_count == 1);

    const dns_question q = make_question("example.com", DNS_TYPE_A, DNS_CLASS_IN);
    const dns_packet *p = cache_lookup(&c, &q);
    CHECK(p != NULL);
    if (p) {
        const uint8_t expected_ip[] = {93, 184, 215, 14};
        CHECK(p->id == 0x1234);
        CHECK(p->an_count == 1);
        CHECK(strcmp(p->answers[0].name, "example.com") == 0);
        CHECK(p->answers[0].ttl <= 300);
        CHECK(p->answers[0].rdlength == 4 && memcmp(p->answers[0].rdata, expected_ip, 4) == 0);
    }
    cache_free(&c);
}

static void test_lookup_ignores_name_case(void) {
    cache c = cache_create(8);
    cache_insert(&c, make_response("Example.COM", DNS_TYPE_A, 300));
    const dns_question q = make_question("eXAMPLE.com", DNS_TYPE_A, DNS_CLASS_IN);
    CHECK(cache_lookup(&c, &q) != NULL);
    cache_free(&c);
}

// Each part of the key (name, type, class) has to match
static void test_lookup_mismatch_misses(void) {
    cache c = cache_create(8);
    cache_insert(&c, make_response("example.com", DNS_TYPE_A, 300));

    const dns_question other_name = make_question("example.org", DNS_TYPE_A, DNS_CLASS_IN);
    const dns_question other_type = make_question("example.com", DNS_TYPE_AAAA, DNS_CLASS_IN);
    const dns_question other_class = make_question("example.com", DNS_TYPE_A, DNS_CLASS_CH);
    CHECK(cache_lookup(&c, &other_name) == NULL);
    CHECK(cache_lookup(&c, &other_type) == NULL);
    CHECK(cache_lookup(&c, &other_class) == NULL);
    cache_free(&c);
}

// TTL HANDLING
static void test_zero_ttl_not_cached(void) {
    cache c = cache_create(8);
    cache_insert(&c, make_response("example.com", DNS_TYPE_A, 0));
    CHECK(c.entry_count == 0);
    cache_free(&c);
}

static void test_packet_without_records_not_cached(void) {
    cache c = cache_create(8);
    dns_packet p = {.qr = 1, .qd_count = 1, .question = make_question("example.com", DNS_TYPE_A, DNS_CLASS_IN)};
    cache_insert(&c, p);
    CHECK(c.entry_count == 0);
    cache_free(&c);
}

// An OPT record's TTL field holds EDNS flags rather than a TTL, so a 0 there mustn't stop the packet being cached
static void test_opt_ttl_ignored(void) {
    cache c = cache_create(8);
    dns_packet p = make_response("example.com", DNS_TYPE_A, 300);
    p.ar_count = 1;
    p.additional = make_record("", DNS_TYPE_OPT, 0, (const uint8_t *)"", 0);
    cache_insert(&c, p);
    CHECK(c.entry_count == 1);
    cache_free(&c);
}

static void test_ttl_capped_at_one_day(void) {
    cache c = cache_create(8);
    cache_insert(&c, make_response("example.com", DNS_TYPE_A, 1000000));
    CHECK(c.entry_count == 1);
    for (size_t i = 0; i < c.bucket_count; i++) {
        for (const cache_entry *e = c.buckets[i]; e; e = e->next) {
            CHECK(e->expires_at - e->updated_at == 86400);
        }
    }
    cache_free(&c);
}

// RFC 2308: a negative answer is cached for no longer than the SOA's MINIMUM field
static void test_soa_ttl_clamped_to_minimum(void) {
    // mname "." + rname "." + serial, refresh, retry, expire, minimum (60)
    static const uint8_t soa[] = {
        0, 0,
        0, 0, 0, 1,  0, 0, 0x0E, 0x10,  0, 0, 0x02, 0x58,  0, 0x09, 0x3A, 0x80,
        0, 0, 0, 60
    };
    cache c = cache_create(8);
    dns_packet p = {.qr = 1, .rcode = DNS_RCODE_NXDOMAIN, .qd_count = 1, .ns_count = 1,
                    .question = make_question("missing.example.com", DNS_TYPE_A, DNS_CLASS_IN)};
    p.authority = make_record("example.com", DNS_TYPE_SOA, 3600, soa, sizeof soa);
    cache_insert(&c, p);

    const dns_question q = make_question("missing.example.com", DNS_TYPE_A, DNS_CLASS_IN);
    const dns_packet *hit = cache_lookup(&c, &q);
    CHECK(hit != NULL);
    if (hit) {
        CHECK(hit->rcode == DNS_RCODE_NXDOMAIN);
        CHECK(hit->authority[0].ttl <= 60);
    }
    cache_free(&c);
}

// RESIZING
static void test_grows_when_load_factor_reached(void) {
    cache c = cache_create(4);
    cache_insert(&c, make_response("a.example.com", DNS_TYPE_A, 300));
    cache_insert(&c, make_response("b.example.com", DNS_TYPE_A, 300));
    CHECK(c.bucket_count == 4);
    cache_insert(&c, make_response("c.example.com", DNS_TYPE_A, 300)); // 3/4 = 0.75
    CHECK(c.bucket_count == 8);
    CHECK(c.entry_count == 3);
    CHECK(entries_in_correct_buckets(&c));
    cache_free(&c);
}

static void test_entries_found_after_resize(void) {
    cache c = cache_create(2);
    const char *names[] = {"a.example.com", "b.example.com", "c.example.com", "d.example.com", "e.example.com"};
    const size_t n = sizeof names / sizeof names[0];
    for (size_t i = 0; i < n; i++) {
        cache_insert(&c, make_response(names[i], DNS_TYPE_A, 300));
    }
    CHECK(c.entry_count == n);
    CHECK(c.bucket_count > 2);
    for (size_t i = 0; i < n; i++) {
        const dns_question q = make_question(names[i], DNS_TYPE_A, DNS_CLASS_IN);
        const dns_packet *p = cache_lookup(&c, &q);
        CHECK(p != NULL && strcmp(p->question.name, names[i]) == 0);
    }
    cache_free(&c);
}

static void test_manual_resize_keeps_entries(void) {
    cache c = cache_create(8);
    cache_insert(&c, make_response("example.com", DNS_TYPE_A, 300));
    resize_cache(&c, 3);
    CHECK(c.bucket_count == 3);
    CHECK(c.entry_count == 1);
    CHECK(entries_in_correct_buckets(&c));
    const dns_question q = make_question("example.com", DNS_TYPE_A, DNS_CLASS_IN);
    CHECK(cache_lookup(&c, &q) != NULL);
    cache_free(&c);
}

int main(void) {
    RUN(test_create_cache);
    RUN(test_free_empties_cache);

    RUN(test_lookup_empty_cache_misses);
    RUN(test_insert_then_lookup_hits);
    RUN(test_lookup_ignores_name_case);
    RUN(test_lookup_mismatch_misses);

    RUN(test_zero_ttl_not_cached);
    RUN(test_packet_without_records_not_cached);
    RUN(test_opt_ttl_ignored);
    RUN(test_ttl_capped_at_one_day);
    RUN(test_soa_ttl_clamped_to_minimum);

    RUN(test_grows_when_load_factor_reached);
    RUN(test_entries_found_after_resize);
    RUN(test_manual_resize_keeps_entries);

    printf("\n%d/%d checks passed\n", checks - failures, checks);
    return failures ? 1 : 0;
}
