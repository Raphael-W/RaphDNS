#include "packet.h"

#include <stdio.h>
#include <string.h>
#include <arpa/inet.h>

typedef struct {
    uint8_t *buf;
    size_t size;  // bytes
    size_t bit;   // current position, in bits
    bool ok;      // false if we ran past the end
} bit_writer;

typedef struct {
    const uint8_t *buf;
    size_t size;
    size_t bit;
    bool ok;
} bit_reader;

// HELPER FUNCTIONS

static uint32_t read_bits(bit_reader *r, unsigned count) {
      uint32_t value = 0;
      for (unsigned i = 0; i < count; i++) {
          size_t byte = r->bit / 8;
          unsigned shift = 7 - r->bit % 8;
          if (byte >= r->size) {
              r->ok = false; return 0;
          }
          value = (value << 1) | ((r->buf[byte] >> shift) & 1);
          r->bit++;
      }
      return value;
}

static void write_bits(bit_writer *w, uint32_t value, unsigned count) {
      for (int i = count - 1; i >= 0; i--) {
          size_t byte = w->bit / 8;
          unsigned shift = 7 - w->bit % 8;
          if (byte >= w->size) { w->ok = false; return; }
          if ((value >> i) & 1)
              w->buf[byte] |= 1u << shift;
          else
              w->buf[byte] &= ~(1u << shift);
          w->bit++;
      }
}

static void read_name(bit_reader *r, char *out, size_t out_size) {
    size_t n = 0;
    uint8_t len;
    while ((len = read_bits(r, 8)) > 0) {
        if (n + len + 2 > out_size) { r->ok = false; break; }
        if (n) out[n++] = '.';
        for (uint8_t i = 0; i < len; i++)
            out[n++] = (char) read_bits(r, 8);
    }
    out[n] = '\0';
}

static void write_name(bit_writer *w, const char *in) {
    while (*in) {
        size_t len = strcspn(in, ".");
        if (len == 0 || len > 63) {
            w->ok = false; return;
        }
        write_bits(w, len, 8);
        for (size_t i = 0; i < len; i++)
            write_bits(w, (uint8_t)in[i], 8);
        in += len;
        if (*in == '.') in++;
    }
    write_bits(w, 0, 8);
}

static void read_record(bit_reader *r, dns_record *rec) {
    read_name(r, rec->name, sizeof rec->name);
    rec->type = read_bits(r, 16);
    rec->class = read_bits(r, 16);
    rec->ttl = read_bits(r, 32);
    rec->rdlength = read_bits(r, 16);

    rec->rdata = malloc(rec->rdlength);
    if (!rec->rdata) {
        r->ok = false;
        return;
    }
    for (uint16_t i = 0; i < rec->rdlength; i++) {
        rec->rdata[i] = read_bits(r, 8);
    }
}

static dns_record *read_records(bit_reader *r, uint16_t count) {
    dns_record *records = calloc(count, sizeof *records);
    if (!records) {
        r->ok = false;
        return NULL;
    }
    for (uint16_t i = 0; i < count && r -> ok; i++) {
        read_record(r, &records[i]);
    }
    return records;
}

static void write_record(bit_writer *w, const dns_record *rec) {
    write_name(w, rec->name);
    write_bits(w, rec->type, 16);
    write_bits(w, rec->class, 16);
    write_bits(w, rec->ttl, 32);
    write_bits(w, rec->rdlength, 16);

    for (uint16_t i = 0; i < rec->rdlength; i++) {
        write_bits(w, rec->rdata[i], 8);
    }
}

static void write_records(bit_writer *w, const dns_record *records, uint16_t count) {
    for (uint16_t i = 0; i < count && w->ok; i++) {
        write_record(w, &records[i]);
    }
}

void print_record(const dns_record *r, char* name) {
    printf("\n%s:\n", name);
    printf("Name: %s\n", r->name);
    printf("Type: %u\n", r->type);
    printf("Class: %u\n", r->class);
    printf("TTL: %u\n", r->ttl);
    printf("Resource Length: %u\n", r->rdlength);
    char ip[INET6_ADDRSTRLEN];
    if (r->type == 1 && r->rdlength == 4) { // A
        printf("Resource Data: %s\n", inet_ntop(AF_INET, r->rdata, ip, sizeof ip));
    }
    else if (r->type == 28 && r->rdlength == 16) { // AAAA
        printf("Resource Data: %s\n", inet_ntop(AF_INET6, r->rdata, ip, sizeof ip));
    }
    else {
        printf("Resource Data: ");
        for (uint16_t i = 0; i < r->rdlength; i++)
            printf("%02x ", r->rdata[i]);
        printf("\n");
    }
}

void print_dns_packet(const dns_packet *p) {
    printf("Header: \n");
    printf("ID: %u\n", p->id);
    printf("Query/response: %d\n", p->qr);
    printf("Opcode: %d\n", p->opcode);
    printf("Authoritive Answer: %d\n", p->aa);
    printf("Truncate Flag: %d\n", p->tc);
    printf("Recursion Desired: %d\n", p->rd);
    printf("Recursion Available: %d\n", p->ra);
    printf("Authenticated Data: %d\n", p->ad);
    printf("Checking Disabled: %d\n", p->cd);
    printf("Error Code: %d\n", p->rcode);
    printf("Question Count: %u\n", p->qd_count);
    printf("Answer Record Count: %u\n", p->an_count);
    printf("Authority Record Count: %u\n", p->ns_count);
    printf("Additional Record Count: %u\n", p->ar_count);

    if (p->qd_count == 1) {
        printf("\nQuestion: \n");
        printf("Name: %s\n", p->question.name);
        printf("Type: %u\n", p->question.type);
        printf("Class: %u\n", p->question.class);
    }

    for (int i = 0; i < p->an_count; i++) {
        print_record(p->answers, "Answer Record");
    }

    for (int i = 0; i < p->ns_count; i++) {
        print_record(p->authority, "Authority Record");
    }

    for (int i = 0; i < p->ar_count; i++) {
        print_record(p->additional, "Additional Record");
    }
}

// READ & WRITE DNS PACKETS

dns_packet parse_dns_packet(const uint8_t* buf, size_t buf_size) {
    dns_packet new_packet = {0};
    bit_reader r = {.buf = buf, .size = buf_size, .bit = 0, .ok = true};

    //HEADER
    new_packet.id = read_bits(&r, 16);
    new_packet.qr = read_bits(&r, 1);
    new_packet.opcode = read_bits(&r, 4);
    new_packet.aa = read_bits(&r, 1);
    new_packet.tc = read_bits(&r, 1);
    new_packet.rd = read_bits(&r, 1);
    new_packet.ra = read_bits(&r, 1);
    read_bits(&r, 1); // Z (reserved)
    new_packet.ad = read_bits(&r, 1);
    new_packet.cd = read_bits(&r, 1);
    new_packet.rcode = read_bits(&r, 4);
    new_packet.qd_count = read_bits(&r, 16);
    new_packet.an_count = read_bits(&r, 16);
    new_packet.ns_count = read_bits(&r, 16);
    new_packet.ar_count = read_bits(&r, 16);

    // QUESTION
    dns_question new_question = {0};
    read_name(&r, new_question.name, sizeof new_question.name);
    new_question.type = read_bits(&r, 16);
    new_question.class = read_bits(&r, 16);
    new_packet.question = new_question;

    // RECORDS
    new_packet.answers = read_records(&r, new_packet.an_count);
    new_packet.authority = read_records(&r, new_packet.ns_count);
    new_packet.additional = read_records(&r, new_packet.ar_count);

    return new_packet;
}

int create_dns_packet(uint8_t* buf, size_t buf_size, dns_packet* p) {
    bit_writer w = {.buf = buf, .size = buf_size, .bit = 0, .ok = true};
    memset(buf, 0, 12);

    // HEADER
    write_bits(&w, p->id, 16);
    write_bits(&w, p->qr, 1);
    write_bits(&w, p->opcode, 4);
    write_bits(&w, p->aa, 1);
    write_bits(&w, p->tc, 1);
    write_bits(&w, p->rd, 1);
    write_bits(&w, p->ra, 1);
    write_bits(&w, 0, 1);          // Z (reserved)
    write_bits(&w, p->ad, 1);
    write_bits(&w, p->cd, 1);
    write_bits(&w, p->rcode, 4);
    write_bits(&w, p->qd_count, 16);
    write_bits(&w, p->an_count, 16);
    write_bits(&w, p->ns_count, 16);
    write_bits(&w, p->ar_count, 16);

    // QUESTION
    write_name(&w, p->question.name);
    write_bits(&w, p->question.type, 16);
    write_bits(&w, p->question.class, 16);

    // RECORDS
    write_records(&w, p->answers, p->an_count);
    write_records(&w, p->authority, p->ns_count);
    write_records(&w, p->additional, p->ar_count);

    return w.ok ? (int)((w.bit + 7) / 8) : -1;
}