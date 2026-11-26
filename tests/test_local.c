#include "local.h"
#include "harness.h"

#include <limits.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <unistd.h>

// FIXTURES
// Local records are loaded from hosts-style files, so each test writes its own into a temporary directory
static char tmp_dir[PATH_MAX];

// Writes contents to tmp_dir/name and returns the full path (valid until the next call)
// Returns "" if the path is too long, so loading it fails
static const char *write_file(const char *name, const char *contents) {
    static char path[PATH_MAX];
    if (!FORMAT(path, "%s/%s", tmp_dir, name)) {
        CHECK(!"path too long");
        path[0] = '\0';
        return path;
    }
    FILE *f = fopen(path, "w");
    if (f) { fputs(contents, f); fclose(f); }
    return path;
}

// Returns records loaded from a file with the given contents
static local_records *records_from(const char *contents) {
    local_records *l = local_records_create(4);
    load_local_records(write_file("hosts.txt", contents), l);
    return l;
}

// Returns how many records have this name and type
static size_t count_records(const local_records *l, const char *name, const uint16_t type) {
    size_t n = 0;
    for (size_t i = 0; i < l->count; i++) {
        if (strcasecmp(l->records[i].name, name) == 0 && l->records[i].type == type) n++;
    }
    return n;
}

// Returns the first record with this name and type, or NULL
static const local_record *find_record(const local_records *l, const char *name, const uint16_t type) {
    for (size_t i = 0; i < l->count; i++) {
        if (strcasecmp(l->records[i].name, name) == 0 && l->records[i].type == type) return &l->records[i];
    }
    return NULL;
}

// Returns a query for name/type with a fixed id and RD set
static dns_packet query_for(const char *name, const uint16_t type) {
    dns_packet q;
    memset(&q, 0, sizeof q);
    q.id = 0x1234;
    q.rd = 1;
    q.qd_count = 1;
    snprintf(q.question.name, sizeof q.question.name, "%s", name);
    q.question.type = type;
    q.question.class = DNS_CLASS_IN;
    return q;
}

// CREATING
static void test_create_records(void) {
    local_records *l = local_records_create(8);
    REQUIRE(l != NULL);
    CHECK(l->records != NULL);
    CHECK(l->count == 0);
    CHECK(l->capacity == 8);
    local_records_free(l);
}

static void test_free_null_is_harmless(void) {
    local_records_free(NULL);
    CHECK(true);
}

// RESIZING
static void test_resize_grows(void) {
    local_records *l = local_records_create(2);
    REQUIRE(l != NULL);
    CHECK(local_records_resize(l, 10) == 0);
    CHECK(l->capacity == 10);
    local_records_free(l);
}

static void test_resize_below_count_fails(void) {
    local_records *l = local_records_create(4);
    REQUIRE(l != NULL);
    const uint8_t ip[4] = {10, 0, 0, 1};
    insert_record(l, "a.home.arpa", DNS_TYPE_A, 4, ip);
    insert_record(l, "b.home.arpa", DNS_TYPE_A, 4, ip);
    CHECK(local_records_resize(l, 1) == -1);
    CHECK(l->capacity == 4);
    CHECK(l->count == 2);
    local_records_free(l);
}

// INSERTING
static void test_insert_record(void) {
    local_records *l = local_records_create(4);
    REQUIRE(l != NULL);
    const uint8_t ip[4] = {192, 168, 0, 20};
    CHECK(insert_record(l, "nas.home.arpa", DNS_TYPE_A, 4, ip) == 0);
    REQUIRE(l->count == 1);
    CHECK(strcmp(l->records[0].name, "nas.home.arpa") == 0);
    CHECK(l->records[0].type == DNS_TYPE_A);
    CHECK(l->records[0].rdlength == 4);
    CHECK(memcmp(l->records[0].rdata, ip, 4) == 0);
    local_records_free(l);
}

static void test_insert_strips_trailing_dot(void) {
    local_records *l = local_records_create(4);
    REQUIRE(l != NULL);
    const uint8_t ip[4] = {10, 0, 0, 1};
    CHECK(insert_record(l, "nas.home.arpa.", DNS_TYPE_A, 4, ip) == 0);
    REQUIRE(l->count == 1);
    CHECK(strcmp(l->records[0].name, "nas.home.arpa") == 0);
    local_records_free(l);
}

static void test_insert_rejects_bad_names(void) {
    local_records *l = local_records_create(4);
    REQUIRE(l != NULL);
    const uint8_t ip[4] = {10, 0, 0, 1};
    CHECK(insert_record(l, "", DNS_TYPE_A, 4, ip) == -1);
    CHECK(insert_record(l, ".", DNS_TYPE_A, 4, ip) == -1);

    char long_name[300];
    memset(long_name, 'a', sizeof long_name - 1);
    long_name[sizeof long_name - 1] = '\0';
    CHECK(insert_record(l, long_name, DNS_TYPE_A, 4, ip) == -1);
    CHECK(l->count == 0);
    local_records_free(l);
}

static void test_insert_rejects_long_rdata(void) {
    local_records *l = local_records_create(4);
    REQUIRE(l != NULL);
    uint8_t big[300] = {0};
    CHECK(insert_record(l, "a.home.arpa", DNS_TYPE_TXT, sizeof big, big) == -1);
    CHECK(l->count == 0);
    local_records_free(l);
}

static void test_insert_grows_when_full(void) {
    local_records *l = local_records_create(2);
    REQUIRE(l != NULL);
    const uint8_t ip[4] = {10, 0, 0, 1};
    bool all_inserted = true;
    for (int i = 0; i < 20; i++) {
        char name[32];
        snprintf(name, sizeof name, "host%d.home.arpa", i);
        if (insert_record(l, name, DNS_TYPE_A, 4, ip) != 0) all_inserted = false;
    }
    CHECK(all_inserted);
    CHECK(l->count == 20);
    CHECK(l->capacity >= 20);
    CHECK(strcmp(l->records[19].name, "host19.home.arpa") == 0);
    local_records_free(l);
}

// Starting from zero capacity must still work
static void test_insert_from_zero_capacity(void) {
    local_records *l = local_records_create(0);
    REQUIRE(l != NULL);
    const uint8_t ip[4] = {10, 0, 0, 1};
    CHECK(insert_record(l, "a.home.arpa", DNS_TYPE_A, 4, ip) == 0);
    CHECK(l->count == 1);
    local_records_free(l);
}

// LOADING
static void test_load_ipv4(void) {
    local_records *l = records_from("192.168.0.20 nas.home.arpa\n");
    const local_record *r = find_record(l, "nas.home.arpa", DNS_TYPE_A);
    REQUIRE(r != NULL);
    const uint8_t ip[4] = {192, 168, 0, 20};
    CHECK(r->rdlength == 4);
    CHECK(memcmp(r->rdata, ip, 4) == 0);
    local_records_free(l);
}

static void test_load_ipv6(void) {
    local_records *l = records_from("fd00::1 nas.home.arpa\n");
    const local_record *r = find_record(l, "nas.home.arpa", DNS_TYPE_AAAA);
    REQUIRE(r != NULL);
    const uint8_t ip[16] = {0xfd, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1};
    CHECK(r->rdlength == 16);
    CHECK(memcmp(r->rdata, ip, 16) == 0);
    local_records_free(l);
}

// Each name gets an A record and a matching PTR record
static void test_load_creates_ipv4_ptr(void) {
    local_records *l = records_from("192.168.0.20 nas.home.arpa\n");
    const local_record *r = find_record(l, "20.0.168.192.in-addr.arpa", DNS_TYPE_PTR);
    REQUIRE(r != NULL);

    uint8_t wire[256];
    const int wire_len = name_to_wire("nas.home.arpa", wire, sizeof wire);
    REQUIRE(wire_len > 0);
    CHECK(r->rdlength == wire_len);
    CHECK(memcmp(r->rdata, wire, (size_t)wire_len) == 0);
    local_records_free(l);
}

static void test_load_creates_ipv6_ptr(void) {
    local_records *l = records_from("2001:db8::567:89ab nas.home.arpa\n");
    const char *ptr = "b.a.9.8.7.6.5.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.8.b.d.0.1.0.0.2.ip6.arpa";
    CHECK(find_record(l, ptr, DNS_TYPE_PTR) != NULL);
    local_records_free(l);
}

// Several names on one line all point at the same address
static void test_load_several_names_per_line(void) {
    local_records *l = records_from("10.0.0.5 nas.home.arpa files.home.arpa\n");
    CHECK(count_records(l, "nas.home.arpa", DNS_TYPE_A) == 1);
    CHECK(count_records(l, "files.home.arpa", DNS_TYPE_A) == 1);
    CHECK(count_records(l, "5.0.0.10.in-addr.arpa", DNS_TYPE_PTR) == 2);
    local_records_free(l);
}

static void test_load_skips_comments_and_blank_lines(void) {
    local_records *l = records_from("# A comment\n\n10.0.0.1 a.home.arpa # trailing\n#10.0.0.2 b.home.arpa\n   \n");
    CHECK(count_records(l, "a.home.arpa", DNS_TYPE_A) == 1);
    CHECK(count_records(l, "b.home.arpa", DNS_TYPE_A) == 0);
    CHECK(count_records(l, "trailing", DNS_TYPE_A) == 0);
    CHECK(l->count == 2); // A + PTR
    local_records_free(l);
}

static void test_load_handles_crlf_and_tabs(void) {
    local_records *l = records_from("10.0.0.1\ta.home.arpa\r\n10.0.0.2 \t b.home.arpa\r\n");
    CHECK(count_records(l, "a.home.arpa", DNS_TYPE_A) == 1);
    CHECK(count_records(l, "b.home.arpa", DNS_TYPE_A) == 1);
    local_records_free(l);
}

static void test_load_last_line_without_newline(void) {
    local_records *l = records_from("10.0.0.1 a.home.arpa\n10.0.0.2 b.home.arpa");
    CHECK(count_records(l, "b.home.arpa", DNS_TYPE_A) == 1);
    local_records_free(l);
}

static void test_load_skips_invalid_addresses(void) {
    local_records *l = records_from("not-an-ip bad.home.arpa\n256.0.0.1 bad2.home.arpa\n10.0.0.1 good.home.arpa\n");
    CHECK(count_records(l, "bad.home.arpa", DNS_TYPE_A) == 0);
    CHECK(count_records(l, "bad2.home.arpa", DNS_TYPE_A) == 0);
    CHECK(count_records(l, "good.home.arpa", DNS_TYPE_A) == 1);
    local_records_free(l);
}

// An address with no names adds nothing
static void test_load_address_without_names(void) {
    local_records *l = records_from("10.0.0.1\n");
    CHECK(l->count == 0);
    local_records_free(l);
}

static void test_load_missing_file_fails(void) {
    char path[PATH_MAX];
    REQUIRE(FORMAT(path, "%s/does-not-exist.txt", tmp_dir));
    local_records *l = local_records_create(4);
    REQUIRE(l != NULL);
    CHECK(load_local_records(path, l) == -1);
    CHECK(l->count == 0);
    local_records_free(l);
}

// ANSWERING
static void test_answer_a(void) {
    local_records *l = records_from("192.168.0.20 nas.home.arpa\n");
    const dns_packet q = query_for("nas.home.arpa", DNS_TYPE_A);
    dns_packet p;
    memset(&p, 0, sizeof p);

    CHECK(local_record_packet(l, &q, &p) == LOCAL_ANSWER);
    CHECK(p.id == q.id);
    CHECK(p.qr);
    CHECK(p.aa);
    CHECK(p.ra);
    CHECK(p.rd == q.rd);
    CHECK(p.opcode == DNS_OPCODE_QUERY);
    CHECK(p.rcode == DNS_RCODE_NOERROR);
    CHECK(p.qd_count == 1);
    CHECK(strcmp(p.question.name, "nas.home.arpa") == 0);
    REQUIRE(p.an_count == 1);
    REQUIRE(p.answers != NULL);

    const dns_record *a = &p.answers[0];
    const uint8_t ip[4] = {192, 168, 0, 20};
    CHECK(strcmp(a->name, "nas.home.arpa") == 0);
    CHECK(a->type == DNS_TYPE_A);
    CHECK(a->class == DNS_CLASS_IN);
    CHECK(a->ttl > 0);
    CHECK(a->rdlength == 4);
    CHECK(a->rdata && memcmp(a->rdata, ip, 4) == 0);

    free_dns_packet(&p);
    local_records_free(l);
}

static void test_answer_is_case_insensitive(void) {
    local_records *l = records_from("10.0.0.1 nas.home.arpa\n");
    const dns_packet q = query_for("NAS.Home.ARPA", DNS_TYPE_A);
    dns_packet p;
    memset(&p, 0, sizeof p);
    CHECK(local_record_packet(l, &q, &p) == LOCAL_ANSWER);
    CHECK(p.an_count == 1);
    // The answer echoes the name as it was asked
    if (p.answers) CHECK(strcmp(p.answers[0].name, "NAS.Home.ARPA") == 0);
    free_dns_packet(&p);
    local_records_free(l);
}

static void test_answer_several_records(void) {
    local_records *l = records_from("10.0.0.1 nas.home.arpa\n10.0.0.2 nas.home.arpa\nfd00::1 nas.home.arpa\n");
    const dns_packet q = query_for("nas.home.arpa", DNS_TYPE_A);
    dns_packet p;
    memset(&p, 0, sizeof p);
    CHECK(local_record_packet(l, &q, &p) == LOCAL_ANSWER);
    CHECK(p.an_count == 2);
    bool all_a = true;
    for (int i = 0; i < p.an_count && p.answers; i++) {
        if (p.answers[i].type != DNS_TYPE_A) all_a = false;
    }
    CHECK(all_a);
    free_dns_packet(&p);
    local_records_free(l);
}

static void test_answer_ptr(void) {
    local_records *l = records_from("192.168.0.20 nas.home.arpa\n");
    const dns_packet q = query_for("20.0.168.192.in-addr.arpa", DNS_TYPE_PTR);
    dns_packet p;
    memset(&p, 0, sizeof p);
    CHECK(local_record_packet(l, &q, &p) == LOCAL_ANSWER);
    REQUIRE(p.an_count == 1);
    REQUIRE(p.answers != NULL);

    char name[256];
    CHECK(record_rdata_name(&p.answers[0], name, sizeof name));
    CHECK(strcmp(name, "nas.home.arpa") == 0);
    free_dns_packet(&p);
    local_records_free(l);
}

// The name exists but has no records of the asked type
static void test_no_data(void) {
    local_records *l = records_from("10.0.0.1 nas.home.arpa\n");
    const dns_packet q = query_for("nas.home.arpa", DNS_TYPE_AAAA);
    dns_packet p;
    memset(&p, 0, sizeof p);
    CHECK(local_record_packet(l, &q, &p) == LOCAL_NO_DATA);
    CHECK(p.rcode == DNS_RCODE_NOERROR);
    CHECK(p.an_count == 0);
    CHECK(p.answers == NULL);
    CHECK(p.aa);
    CHECK(p.id == q.id);
    free_dns_packet(&p);
    local_records_free(l);
}

static void test_nxdomain_under_home_arpa(void) {
    local_records *l = records_from("10.0.0.1 nas.home.arpa\n");
    const char *names[] = {"missing.home.arpa", "a.b.home.arpa", "HOME.ARPA", "x.HOME.arpa"};
    for (size_t i = 0; i < sizeof names / sizeof names[0]; i++) {
        const dns_packet q = query_for(names[i], DNS_TYPE_A);
        dns_packet p;
        memset(&p, 0, sizeof p);
        CHECK(local_record_packet(l, &q, &p) == LOCAL_NXDOMAIN);
        CHECK(p.rcode == DNS_RCODE_NXDOMAIN);
        CHECK(p.an_count == 0);
        CHECK(p.aa);
        free_dns_packet(&p);
    }
    local_records_free(l);
}

// Names outside home.arpa (including lookalikes) are left for the resolver
static void test_not_found_outside_home_arpa(void) {
    local_records *l = records_from("10.0.0.1 nas.home.arpa\n");
    const char *names[] = {"example.com", "nothome.arpa", "home.arpa.com", "arpa", "evilhome.arpa"};
    for (size_t i = 0; i < sizeof names / sizeof names[0]; i++) {
        const dns_packet q = query_for(names[i], DNS_TYPE_A);
        dns_packet p;
        memset(&p, 0, sizeof p);
        CHECK(local_record_packet(l, &q, &p) == LOCAL_NOT_FOUND);
        CHECK(p.answers == NULL);
    }
    local_records_free(l);
}

// Local records outside home.arpa are still answered
static void test_answers_names_outside_home_arpa(void) {
    local_records *l = records_from("10.0.0.1 printer.lan\n");
    const dns_packet q = query_for("printer.lan", DNS_TYPE_A);
    dns_packet p;
    memset(&p, 0, sizeof p);
    CHECK(local_record_packet(l, &q, &p) == LOCAL_ANSWER);
    CHECK(p.an_count == 1);
    free_dns_packet(&p);
    local_records_free(l);
}

static void test_empty_records(void) {
    local_records *l = local_records_create(4);
    REQUIRE(l != NULL);
    dns_packet q = query_for("example.com", DNS_TYPE_A);
    dns_packet p;
    memset(&p, 0, sizeof p);
    CHECK(local_record_packet(l, &q, &p) == LOCAL_NOT_FOUND);

    q = query_for("nas.home.arpa", DNS_TYPE_A);
    CHECK(local_record_packet(l, &q, &p) == LOCAL_NXDOMAIN);
    free_dns_packet(&p);
    local_records_free(l);
}

int main(void) {
    const char *base = getenv("TMPDIR");
    snprintf(tmp_dir, sizeof tmp_dir, "%s/dns_local_XXXXXX", base && *base ? base : "/tmp");
    if (!mkdtemp(tmp_dir)) { perror("mkdtemp"); return 1; }

    RUN(test_create_records);
    RUN(test_free_null_is_harmless);

    RUN(test_resize_grows);
    RUN(test_resize_below_count_fails);

    RUN(test_insert_record);
    RUN(test_insert_strips_trailing_dot);
    RUN(test_insert_rejects_bad_names);
    RUN(test_insert_rejects_long_rdata);
    RUN(test_insert_grows_when_full);
    RUN(test_insert_from_zero_capacity);

    RUN(test_load_ipv4);
    RUN(test_load_ipv6);
    RUN(test_load_creates_ipv4_ptr);
    RUN(test_load_creates_ipv6_ptr);
    RUN(test_load_several_names_per_line);
    RUN(test_load_skips_comments_and_blank_lines);
    RUN(test_load_handles_crlf_and_tabs);
    RUN(test_load_last_line_without_newline);
    RUN(test_load_skips_invalid_addresses);
    RUN(test_load_address_without_names);
    RUN(test_load_missing_file_fails);

    RUN(test_answer_a);
    RUN(test_answer_is_case_insensitive);
    RUN(test_answer_several_records);
    RUN(test_answer_ptr);
    RUN(test_no_data);
    RUN(test_nxdomain_under_home_arpa);
    RUN(test_not_found_outside_home_arpa);
    RUN(test_answers_names_outside_home_arpa);
    RUN(test_empty_records);

    unlink(write_file("hosts.txt", ""));
    rmdir(tmp_dir);
    printf("\n%d/%d checks passed\n", checks - failures, checks);
    return failures ? 1 : 0;
}
