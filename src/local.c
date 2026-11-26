#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "local.h"
#include "packet.h"

#include <arpa/inet.h>

// Returns true if the name is home.arpa or a subdomain of it, ignoring case
static bool is_local_name(const char* name) {
    const size_t len = strlen(name);
    if (len == 9 && strcasecmp(name, "home.arpa") == 0) return true;
    if (len < 10) return false;

    name += len - 10;
    if (strcasecmp(name, ".home.arpa") == 0) return true;
    return false;
}

// Writes the reverse lookup name for an IPv4 address into out, e.g. 20.0.168.192.in-addr.arpa
// Returns -1 if out is too small
static int ipv4_ptr_name(const uint8_t *rdata, char* out, const size_t out_size) {
    const int n = snprintf(out, out_size, "%u.%u.%u.%u.in-addr.arpa", rdata[3], rdata[2], rdata[1], rdata[0]);
    if (n < 0 || n >= (int) out_size) return -1;
    return 0;
}

// Writes the reverse lookup name for an IPv6 address into out, one nibble per label in reverse order, ending in ip6.arpa
// Returns -1 if out is too small
static int ipv6_ptr_name(const uint8_t *rdata, char* out, const size_t out_size) {
    int pos = 0;
    for (int i = 0; i < 16; i++) {
        const uint8_t b = rdata[15-i];
        const uint8_t low = b & 0x0F;
        const uint8_t high = b >> 4;
        const int n = snprintf(out + pos, out_size - pos, "%x.%x.", low, high);
        if (n < 0 || n >= (int) out_size - pos) return -1;
        pos += n;
    }
    const int n = snprintf(out + pos, out_size - pos, "ip6.arpa");
    if (n < 0 || n >= (int) out_size - pos) return -1;
    return 0;
}

// Copies a record into the list, dropping any trailing dot from the name and growing the list if it's full
// Returns -1 if the name or rdata is too long, or allocation fails
int insert_record(local_records *l, const char *name, const uint16_t type, const uint16_t rdlength, const uint8_t *rdata) {
    size_t name_len = strlen(name);
    if (name_len > 0 && name[name_len - 1] == '.') name_len--; // remove a trailing dot
    if (name_len == 0 || name_len >= sizeof l->records[0].name) return -1; // name is too long
    if (rdlength > sizeof l->records[0].rdata) return -1; // rdata is too long

    if (l->count >= l->capacity) {
        const int status = local_records_resize(l, l->capacity ? l->capacity * 2 : 16);
        if (status < 0) return -1;
    }

    local_record *r = &l->records[l->count];

    strncpy(r->name, name, name_len);
    r->name[name_len] = '\0';
    r->type = type;
    r->rdlength = rdlength;
    memcpy(r->rdata, rdata, rdlength);
    l->count++;

    return 0;
}

// Resizes the record array to hold new_size records
// Leaves the list unchanged and returns -1 if new_size is smaller than the record count, or allocation fails
int local_records_resize(local_records *l, const size_t new_size) {
    if (new_size < l->count) return -1;
    local_record *grown = realloc(l->records, new_size * sizeof *grown);
    if (!grown) return -1;

    l->records = grown;
    l->capacity = new_size;
    return 0;
}

// Frees the record list and its record array
void local_records_free(local_records *l) {
    if (!l) return;
    free(l->records);
    free(l);
}

// Returns an empty record list with room for `size` records, or NULL if allocation fails
local_records *local_records_create(const size_t size) {
    local_records *l = malloc(sizeof *l);
    if (!l) return NULL;

    l->records = calloc(size, sizeof *l->records);
    if (!l->records) { free(l); return NULL; }
    l->count = 0;
    l->capacity = size;
    return l;
}

// Loads a hosts-style file into the list, adding an A or AAAA record for each name and a PTR record pointing back to it
// Invalid lines are reported and skipped. Returns -1 if the file can't be opened
int load_local_records(const char* path, local_records *l) {
    FILE *f = fopen(path, "r");
    if (!f) { perror(path); return -1; }

    char line[1024];
    int line_no = 0;
    while (fgets(line, sizeof line, f)) {
        line_no++;
        char *comment = strchr(line, '#');
        if (comment) *comment = '\0';        // drop comments

        char *save;
        char *addr = strtok_r(line, " \t\r\n", &save);
        if (!addr) continue;                 // blank line

        uint8_t rdata[16];
        uint16_t type;
        uint16_t rdlength;
        if (inet_pton(AF_INET, addr, rdata) == 1) {
            type = DNS_TYPE_A;
            rdlength = 4;
        } else if (inet_pton(AF_INET6, addr, rdata) == 1) {
            type = DNS_TYPE_AAAA;
            rdlength = 16;
        } else {
            fprintf(stderr, "%s:%d: invalid address '%s'\n", path, line_no, addr);
            continue;
        }

        // Reverse lookup name for this address, e.g. 20.0.168.192.in-addr.arpa
        char ptr_name[sizeof l->records[0].name];
        const int ptr_status = type == DNS_TYPE_A
            ? ipv4_ptr_name(rdata, ptr_name, sizeof ptr_name)
            : ipv6_ptr_name(rdata, ptr_name, sizeof ptr_name);

        char *name;
        while ((name = strtok_r(NULL, " \t\r\n", &save))) {
            if (insert_record(l, name, type, rdlength, rdata) < 0) {
                fprintf(stderr, "%s:%d: could not add record for '%s'\n", path, line_no, name);
            }

            // PTR record: the reverse name points back to this name, in wire format
            uint8_t wire[sizeof l->records[0].rdata];
            const int wire_len = name_to_wire(name, wire, sizeof wire);
            if (ptr_status < 0 || wire_len < 0 ||
                insert_record(l, ptr_name, DNS_TYPE_PTR, (uint16_t)wire_len, wire) < 0) {
                fprintf(stderr, "%s:%d: could not add PTR record for '%s'\n", path, line_no, name);
            }
        }

    }
    fclose(f);
    return 0;
}

// Builds a reply to q from the local records into p
// Returns LOCAL_NOT_FOUND if the name isn't local, so it should be resolved as normal
local_status local_record_packet(const local_records *l, const dns_packet *q, dns_packet *p) {
    int record_count = 0;
    int rcode = DNS_RCODE_NOERROR;
    bool name_exists = false;

    for (size_t i = 0; i < l->count; i++) {
        const local_record *r = &l->records[i];
        if (strcasecmp(r->name, q->question.name) == 0) {
            name_exists = true;
            if (r->type == q->question.type) record_count++;
        }
    }

    dns_record *records = NULL;
    if (record_count > 0) {
        records = calloc(record_count, sizeof *records);
    }

    else if (!name_exists) {
        if (is_local_name(q->question.name)) rcode = DNS_RCODE_NXDOMAIN;
        else return LOCAL_NOT_FOUND;
    }

    p->id = q->id;
    p->question = q->question;
    p->opcode = DNS_OPCODE_QUERY;
    p->aa = 1;
    p->qr = 1;
    p->ra = 1;
    p->rd = q->rd;
    p->rcode = rcode;
    p->qd_count = 1;
    p->an_count = record_count;
    p->answers = records;

    if (rcode == DNS_RCODE_NXDOMAIN) return LOCAL_NXDOMAIN;
    if (record_count == 0) return LOCAL_NO_DATA;
    if (!records) { free_dns_packet(p); return LOCAL_ERROR; }

    int n = 0;
    for (size_t i = 0; i < l->count; i++) {
        const local_record *r = &l->records[i];
        if (strcasecmp(r->name, q->question.name) == 0 && r->type == q->question.type) {
            dns_record *a = &records[n];
            strncpy(a->name, q->question.name, sizeof q->question.name);
            a->type = r->type;
            a->class = DNS_CLASS_IN;
            a->ttl = 300;
            a->rdlength = r->rdlength;
            a->rdata = malloc(r->rdlength);
            if (!a->rdata) { free_dns_packet(p); return LOCAL_ERROR; }
            memcpy(a->rdata, r->rdata, r->rdlength);
            n++;
        }
    }
    return LOCAL_ANSWER;
}
