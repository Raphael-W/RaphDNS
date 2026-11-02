#include "resolver.h"

#include "network.h"
#include "packet.h"

#include <stdlib.h>
#include <string.h>
#include <arpa/inet.h>

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