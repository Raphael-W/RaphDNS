#include "resolver.h"

#include "network.h"
#include "packet.h"

#include <stdlib.h>
#include <string.h>
#include <arpa/inet.h>

#include "helpers.h"

#define MAX_QUERIES 32
#define MAX_SERVERS 13

static char* ROOT_HINTS[] = {
    "198.41.0.4",           // A.ROOT-SERVERS.NET
    "170.247.170.2",        // B.ROOT-SERVERS.NET
    "192.33.4.12",          // C.ROOT-SERVERS.NET
    "199.7.91.13",          // D.ROOT-SERVERS.NET
    "192.203.230.10",       // E.ROOT-SERVERS.NET
    "192.5.5.241",          // F.ROOT-SERVERS.NET
    "192.112.36.4",         // G.ROOT-SERVERS.NET
    "198.97.190.53",        // H.ROOT-SERVERS.NET
    "192.36.148.17",        // I.ROOT-SERVERS.NET
    "192.58.128.30",        // J.ROOT-SERVERS.NET
    "193.0.14.129",         // K.ROOT-SERVERS.NET
    "199.7.83.42",          // L.ROOT-SERVERS.NET
    "202.12.27.33"          // M.ROOT-SERVERS.NET
};

// Copies the root servers from a random starting point, so lookups don't always try the same one first
static int copy_roots(char ips[][INET_ADDRSTRLEN], int max) {
    int total = sizeof ROOT_HINTS / sizeof ROOT_HINTS[0];
    int start = rand() % total;
    int count = total < max ? total : max;

    for (int i = 0; i < count; i++) {
        strncpy(ips[i], ROOT_HINTS[(start + i) % total], INET_ADDRSTRLEN - 1);
        ips[i][INET_ADDRSTRLEN - 1] = '\0';
    }
    return count;
}

static int find_glue(const dns_packet *p, char ips[][INET_ADDRSTRLEN], int max) {
    int count = 0;
    for (int i = 0; i < p->ns_count; i++) {
        char ns_name[256];
        if (p->authority[i].type != DNS_TYPE_NS) continue;
        if (!record_rdata_name(&p->authority[i], ns_name, sizeof ns_name)) continue;

        for (int j = 0; j < p->ar_count && count < max; j++) {
            const dns_record *rec = &p->additional[j];
            if (rec->type == DNS_TYPE_A && rec->rdlength == 4 && strcasecmp(rec->name, ns_name) == 0) {
                inet_ntop(AF_INET, rec->rdata, ips[count++], INET_ADDRSTRLEN);
            }
        }
    }
    return count;
}

static int find_answer(const dns_packet *p, char ips[][INET_ADDRSTRLEN], int max) {
    int count = 0;
    for (int i = 0; i < p->an_count && count < max; i++) {
        const dns_record *rec = &p->answers[i];
        if (rec->type == DNS_TYPE_A && rec->rdlength == 4) {
            inet_ntop(AF_INET, rec->rdata, ips[count++], INET_ADDRSTRLEN);
        }
    }
    return count;
}

static int resolve(const char* name, uint8_t* buf, size_t buf_size, int* queries_left);

// For referrals without glue: looks up each nameserver's address from the root until one resolves
static int resolve_nameserver(const dns_packet *p, char ips[][INET_ADDRSTRLEN], int max, int* queries_left) {
    for (int i = 0; i < p->ns_count; i++) {
        char ns_name[256];
        if (p->authority[i].type != DNS_TYPE_NS) continue;
        if (!record_rdata_name(&p->authority[i], ns_name, sizeof ns_name)) continue;

        uint8_t ns_buf[4096];
        int n = resolve(ns_name, ns_buf, sizeof ns_buf, queries_left);
        if (n < 0) continue;

        dns_packet ns_response = {0};
        int count = parse_dns_packet(ns_buf, n, &ns_response) >= 0 ? find_answer(&ns_response, ips, max): 0;
        free_dns_packet(&ns_response);
        if (count > 0) return count;
    }
    return 0;
}

// queries_left is shared with nested nameserver lookups, so nameservers that depend on each other can't recurse forever
static int resolve(const char* name, uint8_t* buf, size_t buf_size, int* queries_left) {
    char servers[MAX_SERVERS][INET_ADDRSTRLEN];
    int server_count = copy_roots(servers, MAX_SERVERS);
    int current = 0;

    while (*queries_left > 0) {
        (*queries_left)--;

        dns_question question = {.type = DNS_TYPE_A, .class = DNS_CLASS_IN};
        strncpy(question.name, name, sizeof question.name - 1);

        uint8_t query[4096];
        dns_packet request = {
            .id = 1,
            .qr = 0,
            .opcode = DNS_OPCODE_QUERY,
            .aa = 0, .tc = 0, .rd=0, .ra=0, .ad=0, .cd=0,
            .rcode=DNS_RCODE_NOERROR,
            .qd_count = 1, .an_count = 0, .ns_count = 0, .ar_count = 0,
            .question = question
        };
        int query_len = create_dns_packet(query, sizeof query, &request);
        if (query_len < 0) return -1;

        int n = network_query(servers[current], query, query_len, buf, buf_size);
        if (n < 0) {
            if (++current < server_count) continue;
            return -1;
        }

        dns_packet response = {0};
        if (parse_dns_packet(buf, n, &response) < 0) {
            free_dns_packet(&response);
            if (++current < server_count) continue;
            return -1;
        }

        if (response.rcode != DNS_RCODE_NOERROR && response.rcode != DNS_RCODE_NXDOMAIN) {
            free_dns_packet(&response);
            if (++current < server_count) continue;
            return -1;
        }

        if (response.an_count > 0 || response.aa || response.rcode == DNS_RCODE_NXDOMAIN) {
            free_dns_packet(&response);
            return n;
        }

        server_count = find_glue(&response, servers, MAX_SERVERS);
        if (server_count == 0) {
            server_count = resolve_nameserver(&response, servers, MAX_SERVERS, queries_left);
        }
        current = 0;
        free_dns_packet(&response);
        if (server_count == 0) return -1;
    }

    return -1;
}

int resolve_host(const char* name, uint8_t* buf, const size_t buf_size) {
    int queries_left = MAX_QUERIES;
    return resolve(name, buf, buf_size, &queries_left);
}

static resolve_step next_query(query *q, uint8_t *out, size_t out_size, int *out_len, char *next_ip) {
    if (q->queries_left <= 0) return RESOLVE_FAILED;
    q->queries_left--;

    dns_packet request = {.id = q->id, .opcode = DNS_OPCODE_QUERY, .qd_count = 1, .question = q->question};
    *out_len = create_dns_packet(out, out_size, &request);
    if (*out_len < 0) return RESOLVE_FAILED;

    memcpy(next_ip, q->servers[q->current], INET_ADDRSTRLEN);
    q->expires_at = now_seconds() + QUERY_TIMEOUT_SECONDS;
    return RESOLVE_SEND;
}

static resolve_step next_nameserver(query **qp, uint8_t *out, size_t out_size, int *out_len, char *next_ip);

// A child lookup failed: its parent tries its next nameserver. With no parent, network.c fails *qp
static resolve_step lookup_failed(query **qp, uint8_t *out, size_t out_size, int *out_len, char *next_ip) {
    query *q = *qp;
    query *parent = q->parent;
    if (!parent) return RESOLVE_FAILED;

    parent->queries_left = q->queries_left;
    parent->waiting = false;
    pending_remove(q);
    *qp = parent;
    return next_nameserver(qp, out, out_size, out_len, next_ip);
}

static resolve_step try_next_server(query **qp, uint8_t *out, size_t out_size, int *out_len, char *next_ip) {
    query *q = *qp;
    // Out of addresses: move on to the next saved nameserver, which fails the lookup if there are none left
    if (++q->current >= q->server_count) return next_nameserver(qp, out, out_size, out_len, next_ip);
    return next_query(q, out, out_size, out_len, next_ip);
}

resolve_step resolver_start(query *q, uint8_t *out, size_t out_size, int *out_len, char *next_ip) {
    q->original = q->question;
    q->server_count = copy_roots(q->servers, MAX_SERVERS);
    q->current = 0;
    q->queries_left = q->parent ? q->parent->queries_left : MAX_QUERIES;
    return next_query(q, out, out_size, out_len, next_ip);
}

// Starts a child lookup for the parent's next nameserver. *qp becomes the child, so network.c tracks it
static resolve_step next_nameserver(query **qp, uint8_t *out, size_t out_size, int *out_len, char *next_ip) {
    query *q = *qp;
    if (q->ns_current >= q->ns_count) return lookup_failed(qp, out, out_size, out_len, next_ip);

    query new_child = {.parent = q, .question = {.type = DNS_TYPE_A, .class = DNS_CLASS_IN}};
    strncpy(new_child.question.name, q->ns_names[q->ns_current++], sizeof new_child.question.name - 1);

    int child_id = pending_add(&new_child);
    if (child_id < 0) return lookup_failed(qp, out, out_size, out_len, next_ip);

    query *child = pending_find(child_id);
    q->waiting = true;
    *qp = child;

    if (resolver_start(child, out, out_size, out_len, next_ip) != RESOLVE_SEND) {
        return lookup_failed(qp, out, out_size, out_len, next_ip);
    }
    return RESOLVE_SEND;
}

// A child lookup got a final response: its parent carries on using the nameserver's addresses
static resolve_step child_finished(query **qp, const dns_packet *reply, uint8_t *out, size_t out_size, int *out_len, char *next_ip) {
    query *q = *qp;
    query *parent = q->parent;

    parent->queries_left = q->queries_left;
    parent->waiting = false;
    pending_remove(q);
    *qp = parent;

    parent->server_count = find_answer(reply, parent->servers, MAX_SERVERS);
    if (parent->server_count == 0) return next_nameserver(qp, out, out_size, out_len, next_ip);
    parent->current = 0;
    return next_query(parent, out, out_size, out_len, next_ip);
}

static void collect_ns_names(query *q, const dns_packet *reply) {
    q->ns_count = 0;
    q->ns_current = 0;
    for (int i = 0; i < reply->ns_count && q->ns_count < MAX_NS_NAMES; i++) {
        if (reply->authority[i].type != DNS_TYPE_NS) continue;
        if (record_rdata_name(&reply->authority[i], q->ns_names[q->ns_count], sizeof q->ns_names[0])) {
            q->ns_count++;
        }
    }
}

// Returns the CNAME to follow if the answer has no records of the requested type, or NULL if it's complete
static const dns_record *cname_to_follow(const query *q, const dns_packet *reply) {
    if (reply->rcode != DNS_RCODE_NOERROR) return NULL;
    if (q->question.type == DNS_TYPE_CNAME || q->question.type == DNS_TYPE_ANY) return NULL;

    const dns_record *last = NULL;
    for (int i = 0; i < reply->an_count; i++) {
        if (reply->answers[i].type == q->question.type) return NULL;
        if (reply->answers[i].type == DNS_TYPE_CNAME) last = &reply->answers[i];
    }
    return last;
}

// Saves the CNAMEs and restarts the lookup from the root with the name they point to
static resolve_step follow_cname(query *q, const dns_packet *reply, const dns_record *last, uint8_t *out, size_t out_size, int *out_len, char *next_ip) {
    char target[256];
    if (!record_rdata_name(last, target, sizeof target)) return RESOLVE_FAILED;

    for (int i = 0; i < reply->an_count; i++) {
        const dns_record *rec = &reply->answers[i];
        if (rec->type != DNS_TYPE_CNAME) continue;
        if (q->cname_count == MAX_CNAMES || rec->rdlength > sizeof q->cnames[0].rdata) return RESOLVE_FAILED;

        saved_cname *saved = &q->cnames[q->cname_count++];
        memcpy(saved->name, rec->name, sizeof saved->name);
        saved->ttl = rec->ttl;
        saved->rdlength = rec->rdlength;
        memcpy(saved->rdata, rec->rdata, rec->rdlength);
    }

    memcpy(q->question.name, target, sizeof q->question.name);
    q->server_count = copy_roots(q->servers, MAX_SERVERS);
    q->current = 0;
    q->ns_count = 0;
    return next_query(q, out, out_size, out_len, next_ip);
}

// Puts the saved CNAMEs in front of the answers, and restores the question the client asked
void resolver_add_cnames(const query *q, dns_packet *reply) {
    reply->question = q->original;
    if (q->cname_count == 0) return;

    int total = q->cname_count + reply->an_count;
    dns_record *answers = calloc(total, sizeof *answers);
    if (!answers) return;

    for (int i = 0; i < q->cname_count; i++) {
        const saved_cname *saved = &q->cnames[i];
        dns_record *rec = &answers[i];
        memcpy(rec->name, saved->name, sizeof rec->name);
        rec->type = DNS_TYPE_CNAME;
        rec->class = DNS_CLASS_IN;
        rec->ttl = saved->ttl;
        rec->rdlength = saved->rdlength;
        rec->rdata = malloc(saved->rdlength);
        if (rec->rdata) memcpy(rec->rdata, saved->rdata, saved->rdlength);
        else rec->rdlength = 0;
    }
    if (reply->an_count) memcpy(&answers[q->cname_count], reply->answers, reply->an_count * sizeof *answers);

    free(reply->answers);
    reply->answers = answers;
    reply->an_count = total;
}

resolve_step resolver_on_response(query **qp, const dns_packet *reply, uint8_t *out, size_t out_size, int *out_len, char *next_ip) {
    query *q = *qp;
    if (reply->rcode != DNS_RCODE_NOERROR && reply->rcode != DNS_RCODE_NXDOMAIN) {
        return try_next_server(qp, out, out_size, out_len, next_ip);
    }
    if (reply->an_count > 0 || reply->aa || reply->rcode == DNS_RCODE_NXDOMAIN) {
        const dns_record *last = cname_to_follow(q, reply);
        if (last) return follow_cname(q, reply, last, out, out_size, out_len, next_ip);
        if (q->parent) return child_finished(qp, reply, out, out_size, out_len, next_ip);
        return RESOLVE_DONE;
    }

    // Save the names even with glue, as a referral may only have glue for some of its nameservers
    collect_ns_names(q, reply);
    q->server_count = find_glue(reply, q->servers, MAX_SERVERS);
    if (q->server_count == 0) return next_nameserver(qp, out, out_size, out_len, next_ip);
    q->current = 0;
    return next_query(q, out, out_size, out_len, next_ip);
}

resolve_step resolver_on_timeout(query **qp, uint8_t *out, size_t out_size, int *out_len, char *next_ip) {
    return try_next_server(qp, out, out_size, out_len, next_ip);
}