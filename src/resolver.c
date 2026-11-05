#include "resolver.h"

#include "network.h"
#include "packet.h"

#include <stdlib.h>
#include <string.h>
#include <arpa/inet.h>

#include "helpers.h"

#define MAX_QUERIES 32

// All 13 root servers
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

// Shuffles count rows of row_size bytes in place, so each order is equally likely (Fisher-Yates)
static void shuffle_rows(void *rows, const int count, const size_t row_size) {
    char tmp[row_size];

    char *base = rows;
    for (int i = count - 1; i > 0; i--) {
        const int j = (int)arc4random_uniform(i + 1);
        memcpy(tmp, base + i * row_size, row_size);
        memcpy(base + i * row_size, base + j * row_size, row_size);
        memcpy(base + j * row_size, tmp, row_size);
    }
}

// Copies the root servers from a random starting point, so lookups don't always try the same one first
static int copy_roots(char ips[][INET_ADDRSTRLEN], const int max) {
    const int total = sizeof ROOT_HINTS / sizeof ROOT_HINTS[0];
    const int start = rand() % total;
    const int count = total < max ? total : max;

    for (int i = 0; i < count; i++) {
        strncpy(ips[i], ROOT_HINTS[(start + i) % total], INET_ADDRSTRLEN - 1);
        ips[i][INET_ADDRSTRLEN - 1] = '\0';
    }
    return count;
}

// Copies the addresses of the referral's nameservers from the additional section into ips. Returns the number found
static int find_glue(const dns_packet *p, char ips[][INET_ADDRSTRLEN], const int max) {
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
    shuffle_rows(ips, count, INET_ADDRSTRLEN);
    return count;
}

// Copies the addresses from the A records in the answer section into ips. Returns the number found
static int find_answer(const dns_packet *p, char ips[][INET_ADDRSTRLEN], const int max) {
    int count = 0;
    for (int i = 0; i < p->an_count && count < max; i++) {
        const dns_record *rec = &p->answers[i];
        if (rec->type == DNS_TYPE_A && rec->rdlength == 4) {
            inet_ntop(AF_INET, rec->rdata, ips[count++], INET_ADDRSTRLEN);
        }
    }
    shuffle_rows(ips, count, INET_ADDRSTRLEN);
    return count;
}

// Writes the query for q's current server into out and restarts its timeout
// Returns RESOLVE_SEND, or RESOLVE_FAILED if it's out of queries or the packet can't be created
static resolve_step next_query(query *q, uint8_t *out, const size_t out_size, int *out_len, char *next_ip) {
    if (q->queries_left <= 0) return RESOLVE_FAILED;
    q->queries_left--;

    dns_record opt = {.type = DNS_TYPE_OPT, .class = EDNS_UDP_SIZE}; // For OPT, class holds the UDP size
    const dns_packet request = {.id = q->id, .opcode = DNS_OPCODE_QUERY, .qd_count = 1, .ar_count = 1,
                                .question = q->question, .additional = &opt};
    *out_len = create_dns_packet(out, out_size, &request);
    if (*out_len < 0) return RESOLVE_FAILED;

    memcpy(next_ip, q->servers[q->current], INET_ADDRSTRLEN);
    q->expires_at = now_seconds() + QUERY_TIMEOUT_SECONDS;
    return RESOLVE_SEND;
}

static resolve_step next_nameserver(query **qp, uint8_t *out, size_t out_size, int *out_len, char *next_ip);

// A child lookup failed: its parent tries its next nameserver. With no parent, network.c fails *qp
static resolve_step lookup_failed(query **qp, uint8_t *out, const size_t out_size, int *out_len, char *next_ip) {
    query *q = *qp;
    query *parent = q->parent;
    if (!parent) return RESOLVE_FAILED;

    parent->queries_left = q->queries_left;
    parent->waiting = false;
    pending_remove(q);
    *qp = parent;
    return next_nameserver(qp, out, out_size, out_len, next_ip);
}

// Moves the lookup on to its next server after a timeout or error response
static resolve_step try_next_server(query **qp, uint8_t *out, const size_t out_size, int *out_len, char *next_ip) {
    query *q = *qp;
    // Out of addresses: move on to the next saved nameserver, which fails the lookup if there are none left
    if (++q->current >= q->server_count) return next_nameserver(qp, out, out_size, out_len, next_ip);
    return next_query(q, out, out_size, out_len, next_ip);
}

// Begins a lookup from the root servers, sharing the parent's query budget if q is a child lookup
resolve_step resolver_start(query *q, uint8_t *out, const size_t out_size, int *out_len, char *next_ip) {
    q->original = q->question;
    q->server_count = copy_roots(q->servers, MAX_SERVERS);
    q->current = 0;
    q->queries_left = q->parent ? q->parent->queries_left : MAX_QUERIES;
    return next_query(q, out, out_size, out_len, next_ip);
}

// Starts a child lookup for the parent's next nameserver. *qp becomes the child, so network.c tracks it
static resolve_step next_nameserver(query **qp, uint8_t *out, const size_t out_size, int *out_len, char *next_ip) {
    query *q = *qp;
    if (q->ns_current >= q->ns_count) return lookup_failed(qp, out, out_size, out_len, next_ip);

    query new_child = {.parent = q, .question = {.type = DNS_TYPE_A, .class = DNS_CLASS_IN}};
    strncpy(new_child.question.name, q->ns_names[q->ns_current++], sizeof new_child.question.name - 1);

    const int child_id = pending_add(&new_child);
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
static resolve_step child_finished(query **qp, const dns_packet *reply, uint8_t *out, const size_t out_size, int *out_len, char *next_ip) {
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

// Saves the names of the referral's nameservers to q, replacing any saved earlier
static void collect_ns_names(query *q, const dns_packet *reply) {
    q->ns_count = 0;
    q->ns_current = 0;
    for (int i = 0; i < reply->ns_count && q->ns_count < MAX_NS_NAMES; i++) {
        if (reply->authority[i].type != DNS_TYPE_NS) continue;
        if (record_rdata_name(&reply->authority[i], q->ns_names[q->ns_count], sizeof q->ns_names[0])) {
            q->ns_count++;
        }
    }
    shuffle_rows(q->ns_names, q->ns_count, sizeof q->ns_names[0]);
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
static resolve_step follow_cname(query *q, const dns_packet *reply, const dns_record *last, uint8_t *out, const size_t out_size, int *out_len, char *next_ip) {
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

    const int total = q->cname_count + reply->an_count;
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

// Decides the next step for a lookup from a nameserver's response: retry, follow a CNAME or referral, or finish
// *qp changes if the step moves the lookup to a parent or child query
resolve_step resolver_on_response(query **qp, const dns_packet *reply, uint8_t *out, const size_t out_size, int *out_len, char *next_ip) {
    if (reply->tc) return try_next_server(qp, out, out_size, out_len, next_ip);

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

// Decides the next step for a lookup whose current server didn't respond in time
// *qp changes if the step moves the lookup to a parent or child query
resolve_step resolver_on_timeout(query **qp, uint8_t *out, const size_t out_size, int *out_len, char *next_ip) {
    return try_next_server(qp, out, out_size, out_len, next_ip);
}