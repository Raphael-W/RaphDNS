#include "packet.h"
#include "harness.h"

#include <stdio.h>
#include <string.h>

// FIXTURES
// A query for example.com A with ID 0x1234 and RD set, as it appears on the wire
//
// It's important that the examples below are bytes instead of a dns_packet struct created into bytes.
// Tests need to be able to individually test functions without relying on others (e.g. testing parse_dns_packet()
// shouldn't have to rely on create_dns_packet()).
static const uint8_t EXAMPLE_QUERY[] = {
    0x12, 0x34,                         // ID
    0x01, 0x00,                         // Flags: RD
    0x00, 0x01, 0x00, 0x00,             // QDCOUNT 1, ANCOUNT 0
    0x00, 0x00, 0x00, 0x00,             // NSCOUNT 0, ARCOUNT 0
    7, 'e', 'x', 'a', 'm', 'p', 'l', 'e',
    3, 'c', 'o', 'm', 0,
    0x00, 0x01, 0x00, 0x01              // Type A, class IN
};

// A response to EXAMPLE_QUERY whose answer names the record with a compression pointer to offset 12
static const uint8_t EXAMPLE_RESPONSE[] = {
    0x12, 0x34,                         // ID
    0x81, 0x80,                         // Flags: QR, RD, RA
    0x00, 0x01, 0x00, 0x01,             // QDCOUNT 1, ANCOUNT 1
    0x00, 0x00, 0x00, 0x00,             // NSCOUNT 0, ARCOUNT 0
    7, 'e', 'x', 'a', 'm', 'p', 'l', 'e',
    3, 'c', 'o', 'm', 0,
    0x00, 0x01, 0x00, 0x01,             // Type A, class IN
    0xC0, 0x0C,                         // Name: pointer to offset 12 (example.com)
    0x00, 0x01, 0x00, 0x01,             // Type A, class IN
    0x00, 0x00, 0x0E, 0x10,             // TTL 3600
    0x00, 0x04,                         // RDLENGTH 4
    93, 184, 215, 14                    // 93.184.215.14
};

// PARSING
static void test_parse_query(void) {
    dns_packet p;
    const int n = parse_dns_packet(EXAMPLE_QUERY, sizeof EXAMPLE_QUERY, &p);

    CHECK(n == (int)sizeof EXAMPLE_QUERY);
    CHECK(p.id == 0x1234);
    CHECK(p.qr == 0);
    CHECK(p.rd == 1);
    CHECK(p.opcode == DNS_OPCODE_QUERY);
    CHECK(p.qd_count == 1);
    CHECK(p.an_count == 0);
    CHECK(strcmp(p.question.name, "example.com") == 0);
    CHECK(p.question.type == DNS_TYPE_A);
    CHECK(p.question.class == DNS_CLASS_IN);
    free_dns_packet(&p);
}

static void test_parse_compressed_answer(void) {
    dns_packet p;
    const int n = parse_dns_packet(EXAMPLE_RESPONSE, sizeof EXAMPLE_RESPONSE, &p);

    CHECK(n == (int)sizeof EXAMPLE_RESPONSE);
    CHECK(p.qr == 1);
    CHECK(p.ra == 1);
    CHECK(p.an_count == 1);
    if (p.an_count == 1 && p.answers) {
        const dns_record *a = &p.answers[0];
        const uint8_t expected_ip[] = {93, 184, 215, 14};
        CHECK(strcmp(a->name, "example.com") == 0);
        CHECK(a->type == DNS_TYPE_A);
        CHECK(a->ttl == 3600);
        CHECK(a->rdlength == 4 && memcmp(a->rdata, expected_ip, 4) == 0);
    }
    free_dns_packet(&p);
}

// BUILDING
// Building a packet and parsing it back should give the same fields
static void test_round_trip_query(void) {
    const dns_packet in = {.id = 0xBEEF, .rd = 1, .qd_count = 1,
                           .question = {.name = "www.example.org", .type = DNS_TYPE_AAAA, .class = DNS_CLASS_IN}};
    uint8_t buf[512];
    const int len = create_dns_packet(buf, sizeof buf, &in);
    CHECK(len > 0);

    dns_packet out;
    CHECK(parse_dns_packet(buf, len, &out) == len);
    CHECK(out.id == 0xBEEF);
    CHECK(out.rd == 1);
    CHECK(strcmp(out.question.name, "www.example.org") == 0);
    CHECK(out.question.type == DNS_TYPE_AAAA);
    free_dns_packet(&out);
}

// A round trip can't catch a mistake made the same way in both directions, so also compare against real wire bytes
static void test_create_matches_wire_bytes(void) {
    const dns_packet in = {.id = 0x1234, .rd = 1, .qd_count = 1,
                           .question = {.name = "example.com", .type = DNS_TYPE_A, .class = DNS_CLASS_IN}};
    uint8_t buf[512];
    const int len = create_dns_packet(buf, sizeof buf, &in);

    CHECK(len == (int)sizeof EXAMPLE_QUERY && memcmp(buf, EXAMPLE_QUERY, len) == 0);
}

static void test_create_fails_when_buffer_too_small(void) {
    const dns_packet in = {.id = 1, .qd_count = 1,
                           .question = {.name = "example.com", .type = DNS_TYPE_A, .class = DNS_CLASS_IN}};
    uint8_t buf[20]; // The packet needs 29 bytes
    CHECK(create_dns_packet(buf, sizeof buf, &in) == -1);
}

// MALFORMED INPUT
// Each of these should be rejected with -1 rather than read out of bounds
static void test_rejects_short_header(void) {
    dns_packet p;
    CHECK(parse_dns_packet(EXAMPLE_QUERY, 6, &p) == -1);
    free_dns_packet(&p);
}

static void test_rejects_truncated_question(void) {
    dns_packet p;
    CHECK(parse_dns_packet(EXAMPLE_QUERY, sizeof EXAMPLE_QUERY - 2, &p) == -1);
    free_dns_packet(&p);
}

static void test_rejects_compression_loop(void) {
    // The question's name is a pointer to itself
    const uint8_t buf[] = {
        0x00, 0x01, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0xC0, 0x0C,
        0x00, 0x01, 0x00, 0x01
    };
    dns_packet p;
    CHECK(parse_dns_packet(buf, sizeof buf, &p) == -1);
    free_dns_packet(&p);
}

static void test_rejects_inflated_record_count(void) {
    // Claims 5 answers but contains none
    uint8_t buf[sizeof EXAMPLE_QUERY];
    memcpy(buf, EXAMPLE_QUERY, sizeof buf);
    buf[7] = 5; // Low byte of ANCOUNT
    dns_packet p;
    CHECK(parse_dns_packet(buf, sizeof buf, &p) == -1);
    free_dns_packet(&p);
}

int main(void) {
    RUN(test_parse_query);
    RUN(test_parse_compressed_answer);
    RUN(test_round_trip_query);
    RUN(test_create_matches_wire_bytes);
    RUN(test_create_fails_when_buffer_too_small);
    RUN(test_rejects_short_header);
    RUN(test_rejects_truncated_question);
    RUN(test_rejects_compression_loop);
    RUN(test_rejects_inflated_record_count);

    printf("\n%d/%d checks passed\n", checks - failures, checks);
    return failures ? 1 : 0;
}
