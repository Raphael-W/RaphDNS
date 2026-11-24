// network.c's only public function runs the server loop, so its helpers are static.
// Including the source gives this test access to them; dnscore's copy of network.o is never linked in,
// as nothing here needs a symbol from it
#include "../src/network.c"
#include "harness.h"

#include <limits.h>

// FIXTURES
static const uint8_t ADS_EXAMPLE_COM[] = {3, 'a', 'd', 's', 7, 'e', 'x', 'a', 'm', 'p', 'l', 'e', 3, 'c', 'o', 'm', 0};
static const uint8_t CDN_EXAMPLE_NET[] = {3, 'c', 'd', 'n', 7, 'e', 'x', 'a', 'm', 'p', 'l', 'e', 3, 'n', 'e', 't', 0};
static uint8_t IP[] = {93, 184, 215, 14};
static uint8_t BIG_RDATA[400];

static dns_record record(const char *name, const uint16_t type, uint8_t *rdata, const uint16_t rdlength) {
    dns_record r = {.type = type, .class = DNS_CLASS_IN, .ttl = 300, .rdlength = rdlength, .rdata = rdata};
    strncpy(r.name, name, sizeof r.name - 1);
    return r;
}

static dns_packet response(void) {
    return (dns_packet){.id = 0x1234, .qr = 1, .rd = 1, .ra = 1, .qd_count = 1,
                        .question = {.name = "example.com", .type = DNS_TYPE_A, .class = DNS_CLASS_IN}};
}

// LOGGING
static void test_dns_type_name(void) {
    CHECK(strcmp(dns_type_name(DNS_TYPE_A), "A") == 0);
    CHECK(strcmp(dns_type_name(DNS_TYPE_AAAA), "AAAA") == 0);
    CHECK(strcmp(dns_type_name(DNS_TYPE_HTTPS), "HTTPS") == 0);
    CHECK(strcmp(dns_type_name(99), "TYPE99") == 0);
}

static void test_format_duration(void) {
    char buf[16];
    format_duration(999, buf, sizeof buf);
    CHECK(strcmp(buf, "999 ns") == 0);
    format_duration(1000, buf, sizeof buf);
    CHECK(strcmp(buf, "1 us") == 0);
    format_duration(28500, buf, sizeof buf);
    CHECK(strcmp(buf, "28 us") == 0);
    format_duration(142000000, buf, sizeof buf);
    CHECK(strcmp(buf, "142 ms") == 0);
    format_duration(2000000000, buf, sizeof buf);
    CHECK(strcmp(buf, "2 s") == 0);
}

// ERRORS
static void test_make_error(void) {
    dns_record answer = record("example.com", DNS_TYPE_A, IP, 4);
    dns_packet query = {.id = 0xBEEF, .rd = 1, .aa = 1, .qd_count = 1, .an_count = 1, .answers = &answer,
                        .question = {.name = "example.com", .type = DNS_TYPE_A, .class = DNS_CLASS_IN}};
    uint8_t out[512];
    const int len = make_error(&query, DNS_RCODE_SERVFAIL, out, sizeof out);
    CHECK(len > 0);

    dns_packet p;
    CHECK(parse_dns_packet(out, len, &p) == len);
    CHECK(p.id == 0xBEEF);
    CHECK(p.qr == 1 && p.ra == 1 && p.rd == 1 && p.aa == 0);
    CHECK(p.rcode == DNS_RCODE_SERVFAIL);
    CHECK(p.an_count == 0 && p.ns_count == 0 && p.ar_count == 0);
    CHECK(strcmp(p.question.name, "example.com") == 0);
    free_dns_packet(&p);
}

// EDNS
static void test_client_limit(void) {
    dns_packet p = {0};
    CHECK(client_limit(&p) == 512); // No OPT record

    dns_record opt = {.type = DNS_TYPE_OPT};
    p.ar_count = 1;
    p.additional = &opt;
    opt.class = 1232;
    CHECK(client_limit(&p) == 1232);
    opt.class = 100;
    CHECK(client_limit(&p) == 512); // RFC 6891: values below 512 are treated as 512
    opt.class = 65000;
    CHECK(client_limit(&p) == BUF_SIZE);
}

static void test_strip_opt(void) {
    dns_record additional[3] = {
        record("ns1.example.com", DNS_TYPE_A, IP, 4),
        {.type = DNS_TYPE_OPT, .class = 1232, .rdata = malloc(1)}, // strip_opt frees it
        record("ns2.example.com", DNS_TYPE_A, IP, 4),
    };
    dns_packet p = {.ar_count = 3, .additional = additional};
    strip_opt(&p);
    CHECK(p.ar_count == 2);
    CHECK(strcmp(p.additional[0].name, "ns1.example.com") == 0);
    CHECK(strcmp(p.additional[1].name, "ns2.example.com") == 0);
}

// TRUNCATION
static void test_write_reply_fits(void) {
    dns_record answer = record("example.com", DNS_TYPE_A, IP, 4);
    dns_packet reply = response();
    reply.an_count = 1;
    reply.answers = &answer;

    uint8_t out[512];
    const int len = write_reply(out, sizeof out, reply);
    dns_packet p;
    CHECK(len > 0 && parse_dns_packet(out, len, &p) == len);
    CHECK(p.an_count == 1 && p.tc == 0);
    free_dns_packet(&p);
}

// Additional records are dropped first, as the client can do without them
static void test_write_reply_drops_additional(void) {
    dns_record answer = record("example.com", DNS_TYPE_A, IP, 4);
    dns_record extra = record("example.com", DNS_TYPE_TXT, BIG_RDATA, sizeof BIG_RDATA);
    dns_packet reply = response();
    reply.an_count = 1;
    reply.answers = &answer;
    reply.ar_count = 1;
    reply.additional = &extra;

    uint8_t out[300];
    const int len = write_reply(out, sizeof out, reply);
    dns_packet p;
    CHECK(len > 0 && parse_dns_packet(out, len, &p) == len);
    CHECK(p.an_count == 1 && p.ar_count == 0 && p.tc == 0);
    free_dns_packet(&p);
}

// Then authority, as long as there's an answer
static void test_write_reply_drops_authority(void) {
    dns_record answer = record("example.com", DNS_TYPE_A, IP, 4);
    dns_record auth = record("example.com", DNS_TYPE_TXT, BIG_RDATA, sizeof BIG_RDATA);
    dns_packet reply = response();
    reply.an_count = 1;
    reply.answers = &answer;
    reply.ns_count = 1;
    reply.authority = &auth;

    uint8_t out[300];
    const int len = write_reply(out, sizeof out, reply);
    dns_packet p;
    CHECK(len > 0 && parse_dns_packet(out, len, &p) == len);
    CHECK(p.an_count == 1 && p.ns_count == 0 && p.tc == 0);
    free_dns_packet(&p);
}

// A negative answer keeps its SOA, so when that alone doesn't fit, it's truncated instead
static void test_write_reply_keeps_authority_without_answer(void) {
    dns_record auth = record("example.com", DNS_TYPE_SOA, BIG_RDATA, sizeof BIG_RDATA);
    dns_packet reply = response();
    reply.rcode = DNS_RCODE_NXDOMAIN;
    reply.ns_count = 1;
    reply.authority = &auth;

    uint8_t out[300];
    const int len = write_reply(out, sizeof out, reply);
    dns_packet p;
    CHECK(len > 0 && parse_dns_packet(out, len, &p) == len);
    CHECK(p.tc == 1 && p.ns_count == 0);
    free_dns_packet(&p);
}

// If the answer itself doesn't fit, the client gets an empty reply with TC set, telling it to retry over TCP
static void test_write_reply_truncates(void) {
    dns_record answer = record("example.com", DNS_TYPE_TXT, BIG_RDATA, sizeof BIG_RDATA);
    dns_packet reply = response();
    reply.an_count = 1;
    reply.answers = &answer;

    uint8_t out[300];
    const int len = write_reply(out, sizeof out, reply);
    dns_packet p;
    CHECK(len > 0 && parse_dns_packet(out, len, &p) == len);
    CHECK(p.tc == 1);
    CHECK(p.an_count == 0 && p.ns_count == 0 && p.ar_count == 0);
    CHECK(p.id == 0x1234 && strcmp(p.question.name, "example.com") == 0);
    free_dns_packet(&p);
}

// ADDRESSES
static void test_from_server(void) {
    struct sockaddr_in from;
    make_addr("192.0.2.1", 53, &from);
    CHECK(from_server(&from, "192.0.2.1"));
    CHECK(!from_server(&from, "192.0.2.2"));
    CHECK(!from_server(&from, "not an ip"));

    make_addr("192.0.2.1", 5353, &from);
    CHECK(!from_server(&from, "192.0.2.1")); // Replies must come from port 53
}

static void test_make_addr(void) {
    struct sockaddr_in a;
    CHECK(make_addr("127.0.0.1", 8053, &a));
    CHECK(a.sin_family == AF_INET);
    CHECK(ntohs(a.sin_port) == 8053);
    CHECK(ntohl(a.sin_addr.s_addr) == 0x7F000001);
    CHECK(!make_addr("256.0.0.1", 53, &a));
    CHECK(!make_addr("::1", 53, &a));
}

// BLOCKING
// A CNAME pointing to a blocked domain blocks the reply, so blocklists can't be dodged with an alias
static void test_reply_is_blocked(void) {
    char dir[PATH_MAX];
    const char *base = getenv("TMPDIR");
    snprintf(dir, sizeof dir, "%s/dns_network_XXXXXX", base && *base ? base : "/tmp");
    if (!mkdtemp(dir)) { perror("mkdtemp"); CHECK(false); return; }
    char path[PATH_MAX];
    snprintf(path, sizeof path, "%s/list.txt", dir);
    FILE *f = fopen(path, "w");
    if (f) { fputs("ads.example.com\n", f); fclose(f); }

    list *l = list_create(8);
    load_blocklist(path, l);
    unlink(path);
    rmdir(dir);

    dns_packet p = response();
    dns_record to_blocked = record("www.example.com", DNS_TYPE_CNAME, (uint8_t *)ADS_EXAMPLE_COM, sizeof ADS_EXAMPLE_COM);
    p.an_count = 1;
    p.answers = &to_blocked;
    CHECK(reply_is_blocked(&p, l));

    dns_record to_allowed = record("www.example.com", DNS_TYPE_CNAME, (uint8_t *)CDN_EXAMPLE_NET, sizeof CDN_EXAMPLE_NET);
    p.answers = &to_allowed;
    CHECK(!reply_is_blocked(&p, l));

    // Only CNAME targets are checked; the record names were already checked against the question
    dns_record a = record("ads.example.com", DNS_TYPE_A, IP, 4);
    p.answers = &a;
    CHECK(!reply_is_blocked(&p, l));

    list_free(l);
}

int main(void) {
    RUN(test_dns_type_name);
    RUN(test_format_duration);
    RUN(test_make_error);
    RUN(test_client_limit);
    RUN(test_strip_opt);
    RUN(test_write_reply_fits);
    RUN(test_write_reply_drops_additional);
    RUN(test_write_reply_drops_authority);
    RUN(test_write_reply_keeps_authority_without_answer);
    RUN(test_write_reply_truncates);
    RUN(test_from_server);
    RUN(test_make_addr);
    RUN(test_reply_is_blocked);

    printf("\n%d/%d checks passed\n", checks - failures, checks);
    return failures ? 1 : 0;
}
