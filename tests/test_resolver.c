#include "resolver.h"
#include "harness.h"

#include <string.h>

// The resolver never touches the network: it writes the next query into a buffer and says where to send it,
// so each test plays the part of the nameservers by feeding it replies

// FIXTURES
// Names in rdata are in wire format
static const uint8_t NS1_EXAMPLE_COM[] = {3, 'n', 's', '1', 7, 'e', 'x', 'a', 'm', 'p', 'l', 'e', 3, 'c', 'o', 'm', 0};
static const uint8_t CDN_EXAMPLE_NET[] = {3, 'c', 'd', 'n', 7, 'e', 'x', 'a', 'm', 'p', 'l', 'e', 3, 'n', 'e', 't', 0};
static const uint8_t IP_GLUE[] = {192, 0, 2, 1};
static const uint8_t IP_ANSWER[] = {93, 184, 215, 14};

static dns_record record(const char *name, const uint16_t type, const uint8_t *rdata, const uint16_t rdlength) {
    dns_record r = {.type = type, .class = DNS_CLASS_IN, .ttl = 300, .rdlength = rdlength, .rdata = (uint8_t *)rdata};
    strncpy(r.name, name, sizeof r.name - 1);
    return r;
}

// Adds a client lookup for name to the pending table and returns it
static query *new_lookup(const char *name, const uint16_t type) {
    query in = {.question = {.type = type, .class = DNS_CLASS_IN}};
    strncpy(in.question.name, name, sizeof in.question.name - 1);
    return pending_find((uint16_t)pending_add(&in));
}

// Returns true if next_ip is one of the root servers' addresses
static bool is_root(const char *ip) {
    const char *roots[] = {"198.41.0.4", "170.247.170.2", "192.33.4.12", "199.7.91.13", "192.203.230.10",
                           "192.5.5.241", "192.112.36.4", "198.97.190.53", "192.36.148.17", "192.58.128.30",
                           "193.0.14.129", "199.7.83.42", "202.12.27.33"};
    for (size_t i = 0; i < sizeof roots / sizeof roots[0]; i++) {
        if (strcmp(ip, roots[i]) == 0) return true;
    }
    return false;
}

// STARTING
static void test_start_queries_a_root(void) {
    query *q = new_lookup("example.com", DNS_TYPE_A);
    uint8_t out[512];
    int len;
    char ip[INET_ADDRSTRLEN];

    CHECK(resolver_start(q, out, sizeof out, &len, ip) == RESOLVE_SEND);
    CHECK(is_root(ip));
    CHECK(q->server_count == MAX_SERVERS);
    CHECK(strcmp(q->original.name, "example.com") == 0);

    // The query written out should ask the same question, with EDNS advertising our UDP size
    dns_packet sent;
    CHECK(parse_dns_packet(out, len, &sent) == len);
    CHECK(sent.id == q->id);
    CHECK(sent.qr == 0);
    CHECK(sent.rd == 0); // Iterative, so recursion isn't requested
    CHECK(strcmp(sent.question.name, "example.com") == 0);
    CHECK(sent.question.type == DNS_TYPE_A);
    CHECK(sent.ar_count == 1);
    if (sent.ar_count == 1) {
        CHECK(sent.additional[0].type == DNS_TYPE_OPT);
        CHECK(sent.additional[0].class == EDNS_UDP_SIZE);
    }
    free_dns_packet(&sent);
    pending_remove(q);
}

// RESPONSES
static void test_answer_finishes(void) {
    query *q = new_lookup("example.com", DNS_TYPE_A);
    uint8_t out[512];
    int len;
    char ip[INET_ADDRSTRLEN];
    resolver_start(q, out, sizeof out, &len, ip);

    dns_record answer = record("example.com", DNS_TYPE_A, IP_ANSWER, 4);
    const dns_packet reply = {.qr = 1, .aa = 1, .an_count = 1, .answers = &answer, .question = q->question};
    query *qp = q;
    CHECK(resolver_on_response(&qp, &reply, out, sizeof out, &len, ip) == RESOLVE_DONE);
    CHECK(qp == q);
    pending_remove(q);
}

static void test_nxdomain_finishes(void) {
    query *q = new_lookup("missing.example.com", DNS_TYPE_A);
    uint8_t out[512];
    int len;
    char ip[INET_ADDRSTRLEN];
    resolver_start(q, out, sizeof out, &len, ip);

    const dns_packet reply = {.qr = 1, .rcode = DNS_RCODE_NXDOMAIN, .question = q->question};
    query *qp = q;
    CHECK(resolver_on_response(&qp, &reply, out, sizeof out, &len, ip) == RESOLVE_DONE);
    pending_remove(q);
}

// SERVFAIL, REFUSED etc. and truncated replies are retried on the next server
static void test_error_and_truncation_try_next_server(void) {
    query *q = new_lookup("example.com", DNS_TYPE_A);
    uint8_t out[512];
    int len;
    char ip[INET_ADDRSTRLEN];
    resolver_start(q, out, sizeof out, &len, ip);

    const dns_packet servfail = {.qr = 1, .rcode = DNS_RCODE_SERVFAIL};
    query *qp = q;
    CHECK(resolver_on_response(&qp, &servfail, out, sizeof out, &len, ip) == RESOLVE_SEND);
    CHECK(q->current == 1);
    CHECK(strcmp(ip, q->servers[1]) == 0);

    const dns_packet truncated = {.qr = 1, .tc = 1};
    CHECK(resolver_on_response(&qp, &truncated, out, sizeof out, &len, ip) == RESOLVE_SEND);
    CHECK(q->current == 2);
    pending_remove(q);
}

// A referral with glue sends the next query straight to the glue address
static void test_referral_with_glue(void) {
    query *q = new_lookup("www.example.com", DNS_TYPE_A);
    uint8_t out[512];
    int len;
    char ip[INET_ADDRSTRLEN];
    resolver_start(q, out, sizeof out, &len, ip);

    dns_record ns = record("example.com", DNS_TYPE_NS, NS1_EXAMPLE_COM, sizeof NS1_EXAMPLE_COM);
    dns_record glue = record("ns1.example.com", DNS_TYPE_A, IP_GLUE, 4);
    const dns_packet referral = {.qr = 1, .ns_count = 1, .authority = &ns, .ar_count = 1, .additional = &glue};
    query *qp = q;
    CHECK(resolver_on_response(&qp, &referral, out, sizeof out, &len, ip) == RESOLVE_SEND);
    CHECK(qp == q);
    CHECK(strcmp(ip, "192.0.2.1") == 0);
    CHECK(q->server_count == 1);
    CHECK(q->ns_count == 1 && strcmp(q->ns_names[0], "ns1.example.com") == 0);
    pending_remove(q);
}

// Glue for a nameserver the referral didn't name is ignored
static void test_referral_ignores_unrelated_glue(void) {
    query *q = new_lookup("www.example.com", DNS_TYPE_A);
    uint8_t out[512];
    int len;
    char ip[INET_ADDRSTRLEN];
    resolver_start(q, out, sizeof out, &len, ip);

    dns_record ns = record("example.com", DNS_TYPE_NS, NS1_EXAMPLE_COM, sizeof NS1_EXAMPLE_COM);
    dns_record glue = record("ns9.other.org", DNS_TYPE_A, IP_GLUE, 4);
    const dns_packet referral = {.qr = 1, .ns_count = 1, .authority = &ns, .ar_count = 1, .additional = &glue};
    query *qp = q;
    resolver_on_response(&qp, &referral, out, sizeof out, &len, ip);
    CHECK(strcmp(ip, "192.0.2.1") != 0);
    CHECK(qp != q); // Had to start a child lookup instead
    if (qp != q) pending_remove(qp);
    pending_remove(q);
}

// CHILD LOOKUPS
// Without glue, a child lookup finds the nameserver's address, then the parent carries on with it
static void test_referral_without_glue_uses_child(void) {
    query *q = new_lookup("www.example.com", DNS_TYPE_A);
    uint8_t out[512];
    int len;
    char ip[INET_ADDRSTRLEN];
    resolver_start(q, out, sizeof out, &len, ip);

    dns_record ns = record("example.com", DNS_TYPE_NS, NS1_EXAMPLE_COM, sizeof NS1_EXAMPLE_COM);
    const dns_packet referral = {.qr = 1, .ns_count = 1, .authority = &ns};
    query *qp = q;
    CHECK(resolver_on_response(&qp, &referral, out, sizeof out, &len, ip) == RESOLVE_SEND);

    query *child = qp;
    CHECK(child != q);
    CHECK(child->parent == q);
    CHECK(q->waiting);
    CHECK(strcmp(child->question.name, "ns1.example.com") == 0);
    CHECK(child->question.type == DNS_TYPE_A);
    CHECK(is_root(ip));

    const uint16_t child_id = child->id;
    dns_record answer = record("ns1.example.com", DNS_TYPE_A, IP_GLUE, 4);
    const dns_packet child_reply = {.qr = 1, .aa = 1, .an_count = 1, .answers = &answer};
    CHECK(resolver_on_response(&qp, &child_reply, out, sizeof out, &len, ip) == RESOLVE_SEND);
    CHECK(qp == q);
    CHECK(!q->waiting);
    CHECK(strcmp(ip, "192.0.2.1") == 0);
    CHECK(pending_find(child_id) == NULL); // The child is done with
    pending_remove(q);
}

// The query budget is shared, so a child can't reset it
static void test_child_shares_query_budget(void) {
    query *q = new_lookup("www.example.com", DNS_TYPE_A);
    uint8_t out[512];
    int len;
    char ip[INET_ADDRSTRLEN];
    resolver_start(q, out, sizeof out, &len, ip);
    q->queries_left = 5;

    dns_record ns = record("example.com", DNS_TYPE_NS, NS1_EXAMPLE_COM, sizeof NS1_EXAMPLE_COM);
    const dns_packet referral = {.qr = 1, .ns_count = 1, .authority = &ns};
    query *qp = q;
    resolver_on_response(&qp, &referral, out, sizeof out, &len, ip);
    CHECK(qp->queries_left == 4);

    dns_record answer = record("ns1.example.com", DNS_TYPE_A, IP_GLUE, 4);
    const dns_packet child_reply = {.qr = 1, .aa = 1, .an_count = 1, .answers = &answer};
    resolver_on_response(&qp, &child_reply, out, sizeof out, &len, ip);
    CHECK(qp == q && q->queries_left == 3);
    pending_remove(q);
}

// A child that runs out of servers, with no other nameservers to try, fails the whole lookup
static void test_failed_child_fails_parent(void) {
    query *q = new_lookup("www.example.com", DNS_TYPE_A);
    uint8_t out[512];
    int len;
    char ip[INET_ADDRSTRLEN];
    resolver_start(q, out, sizeof out, &len, ip);

    dns_record ns = record("example.com", DNS_TYPE_NS, NS1_EXAMPLE_COM, sizeof NS1_EXAMPLE_COM);
    const dns_packet referral = {.qr = 1, .ns_count = 1, .authority = &ns};
    query *qp = q;
    resolver_on_response(&qp, &referral, out, sizeof out, &len, ip);
    const uint16_t child_id = qp->id;

    resolve_step step = RESOLVE_SEND;
    for (int i = 0; i < MAX_SERVERS && step == RESOLVE_SEND; i++) {
        step = resolver_on_timeout(&qp, out, sizeof out, &len, ip);
    }
    CHECK(step == RESOLVE_FAILED);
    CHECK(qp == q); // Handed back to the parent, for network.c to fail
    CHECK(pending_find(child_id) == NULL);
    pending_remove(q);
}

// TIMEOUTS AND LIMITS
static void test_timeout_tries_next_server(void) {
    query *q = new_lookup("example.com", DNS_TYPE_A);
    uint8_t out[512];
    int len;
    char ip[INET_ADDRSTRLEN];
    resolver_start(q, out, sizeof out, &len, ip);
    char first[INET_ADDRSTRLEN];
    memcpy(first, ip, sizeof first);

    query *qp = q;
    CHECK(resolver_on_timeout(&qp, out, sizeof out, &len, ip) == RESOLVE_SEND);
    CHECK(strcmp(ip, first) != 0);
    CHECK(is_root(ip));
    pending_remove(q);
}

static void test_all_servers_timing_out_fails(void) {
    query *q = new_lookup("example.com", DNS_TYPE_A);
    uint8_t out[512];
    int len;
    char ip[INET_ADDRSTRLEN];
    resolver_start(q, out, sizeof out, &len, ip);

    query *qp = q;
    int sends = 0;
    while (resolver_on_timeout(&qp, out, sizeof out, &len, ip) == RESOLVE_SEND) sends++;
    CHECK(sends == MAX_SERVERS - 1); // Every root once, counting the first
    pending_remove(q);
}

static void test_out_of_queries_fails(void) {
    query *q = new_lookup("example.com", DNS_TYPE_A);
    uint8_t out[512];
    int len;
    char ip[INET_ADDRSTRLEN];
    resolver_start(q, out, sizeof out, &len, ip);
    q->queries_left = 0;

    query *qp = q;
    CHECK(resolver_on_timeout(&qp, out, sizeof out, &len, ip) == RESOLVE_FAILED);
    pending_remove(q);
}

// CNAMES
// An answer that's only a CNAME restarts the lookup for its target
static void test_follows_cname(void) {
    query *q = new_lookup("www.example.com", DNS_TYPE_A);
    uint8_t out[512];
    int len;
    char ip[INET_ADDRSTRLEN];
    resolver_start(q, out, sizeof out, &len, ip);

    dns_record cname = record("www.example.com", DNS_TYPE_CNAME, CDN_EXAMPLE_NET, sizeof CDN_EXAMPLE_NET);
    const dns_packet reply = {.qr = 1, .aa = 1, .an_count = 1, .answers = &cname};
    query *qp = q;
    CHECK(resolver_on_response(&qp, &reply, out, sizeof out, &len, ip) == RESOLVE_SEND);
    CHECK(strcmp(q->question.name, "cdn.example.net") == 0);
    CHECK(strcmp(q->original.name, "www.example.com") == 0);
    CHECK(q->cname_count == 1);
    CHECK(is_root(ip)); // Starts again from the root

    dns_packet sent;
    CHECK(parse_dns_packet(out, len, &sent) == len);
    CHECK(strcmp(sent.question.name, "cdn.example.net") == 0);
    free_dns_packet(&sent);
    pending_remove(q);
}

// Asking for the CNAME itself, or for a type the answer already has, mustn't follow it
static void test_does_not_follow_cname_when_not_needed(void) {
    uint8_t out[512];
    int len;
    char ip[INET_ADDRSTRLEN];

    query *q = new_lookup("www.example.com", DNS_TYPE_CNAME);
    resolver_start(q, out, sizeof out, &len, ip);
    dns_record cname = record("www.example.com", DNS_TYPE_CNAME, CDN_EXAMPLE_NET, sizeof CDN_EXAMPLE_NET);
    const dns_packet reply = {.qr = 1, .aa = 1, .an_count = 1, .answers = &cname};
    query *qp = q;
    CHECK(resolver_on_response(&qp, &reply, out, sizeof out, &len, ip) == RESOLVE_DONE);
    pending_remove(q);

    q = new_lookup("www.example.com", DNS_TYPE_A);
    resolver_start(q, out, sizeof out, &len, ip);
    dns_record both[] = {cname, record("cdn.example.net", DNS_TYPE_A, IP_ANSWER, 4)};
    const dns_packet full = {.qr = 1, .aa = 1, .an_count = 2, .answers = both};
    qp = q;
    CHECK(resolver_on_response(&qp, &full, out, sizeof out, &len, ip) == RESOLVE_DONE);
    CHECK(q->cname_count == 0);
    pending_remove(q);
}

// The client gets the CNAMEs followed, then the final answer, under the name it asked for
static void test_add_cnames_to_answer(void) {
    query *q = new_lookup("www.example.com", DNS_TYPE_A);
    uint8_t out[512];
    int len;
    char ip[INET_ADDRSTRLEN];
    resolver_start(q, out, sizeof out, &len, ip);

    dns_record cname = record("www.example.com", DNS_TYPE_CNAME, CDN_EXAMPLE_NET, sizeof CDN_EXAMPLE_NET);
    const dns_packet cname_reply = {.qr = 1, .aa = 1, .an_count = 1, .answers = &cname};
    query *qp = q;
    resolver_on_response(&qp, &cname_reply, out, sizeof out, &len, ip);

    // resolver_add_cnames replaces the answers array, so the final reply's has to be on the heap
    dns_packet final = {.qr = 1, .aa = 1, .an_count = 1, .question = q->question};
    final.answers = calloc(1, sizeof *final.answers);
    final.answers[0] = record("cdn.example.net", DNS_TYPE_A, NULL, 4);
    final.answers[0].rdata = malloc(4);
    memcpy(final.answers[0].rdata, IP_ANSWER, 4);

    resolver_add_cnames(q, &final);
    CHECK(strcmp(final.question.name, "www.example.com") == 0);
    CHECK(final.an_count == 2);
    if (final.an_count == 2) {
        CHECK(final.answers[0].type == DNS_TYPE_CNAME);
        CHECK(strcmp(final.answers[0].name, "www.example.com") == 0);
        CHECK(final.answers[0].rdlength == sizeof CDN_EXAMPLE_NET &&
              memcmp(final.answers[0].rdata, CDN_EXAMPLE_NET, sizeof CDN_EXAMPLE_NET) == 0);
        CHECK(final.answers[1].type == DNS_TYPE_A);
        CHECK(strcmp(final.answers[1].name, "cdn.example.net") == 0);
    }
    free_dns_packet(&final);
    pending_remove(q);
}

// With no CNAMEs followed, only the question is restored
static void test_add_cnames_without_cnames(void) {
    query *q = new_lookup("example.com", DNS_TYPE_A);
    uint8_t out[512];
    int len;
    char ip[INET_ADDRSTRLEN];
    resolver_start(q, out, sizeof out, &len, ip);

    dns_record answer = record("example.com", DNS_TYPE_A, IP_ANSWER, 4);
    dns_packet reply = {.qr = 1, .an_count = 1, .answers = &answer, .question = {.name = "other"}};
    resolver_add_cnames(q, &reply);
    CHECK(reply.an_count == 1 && reply.answers == &answer);
    CHECK(strcmp(reply.question.name, "example.com") == 0);
    pending_remove(q);
}

int main(void) {
    RUN(test_start_queries_a_root);

    RUN(test_answer_finishes);
    RUN(test_nxdomain_finishes);
    RUN(test_error_and_truncation_try_next_server);
    RUN(test_referral_with_glue);
    RUN(test_referral_ignores_unrelated_glue);

    RUN(test_referral_without_glue_uses_child);
    RUN(test_child_shares_query_budget);
    RUN(test_failed_child_fails_parent);

    RUN(test_timeout_tries_next_server);
    RUN(test_all_servers_timing_out_fails);
    RUN(test_out_of_queries_fails);

    RUN(test_follows_cname);
    RUN(test_does_not_follow_cname_when_not_needed);
    RUN(test_add_cnames_to_answer);
    RUN(test_add_cnames_without_cnames);

    CHECK(pending_earliest() == 0); // Every test cleaned up after itself
    printf("\n%d/%d checks passed\n", checks - failures, checks);
    return failures ? 1 : 0;
}
