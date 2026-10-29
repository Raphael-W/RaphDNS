#ifndef DNS_PACKET_H
#define DNS_PACKET_H
#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>

typedef enum {
    DNS_TYPE_A     = 1,
    DNS_TYPE_NS    = 2,
    DNS_TYPE_CNAME = 5,
    DNS_TYPE_SOA   = 6,
    DNS_TYPE_PTR   = 12,
    DNS_TYPE_MX    = 15,
    DNS_TYPE_TXT   = 16,
    DNS_TYPE_AAAA  = 28,
    DNS_TYPE_SRV   = 33,
    DNS_TYPE_OPT   = 41,
    DNS_TYPE_HTTPS = 65,
    DNS_TYPE_ANY   = 255,
} dns_type;

typedef enum {
    DNS_CLASS_IN  = 1, //Internet
    DNS_CLASS_CH  = 3, //Chaos (e.g. version.bind)
    DNS_CLASS_ANY = 255,
} dns_class;

typedef enum {
    DNS_RCODE_NOERROR  = 0,
    DNS_RCODE_FORMERR  = 1, //Malformed query
    DNS_RCODE_SERVFAIL = 2, //Server/upstream failure
    DNS_RCODE_NXDOMAIN = 3, //Name doesn't exist
    DNS_RCODE_NOTIMP   = 4, //Not implemented (e.g. opcode)
    DNS_RCODE_REFUSED  = 5,
} dns_rcode;

typedef enum {
    DNS_OPCODE_QUERY  = 0,
    DNS_OPCODE_IQUERY = 1, //Obsolete
    DNS_OPCODE_STATUS = 2,
    DNS_OPCODE_NOTIFY = 4,
    DNS_OPCODE_UPDATE = 5,
} dns_opcode;

typedef struct {
    char name[256]; //e.g. hostname (e.g. example.com)
    uint16_t type; //A/AAAA/CNAME etc.
    uint16_t class; //Network
} dns_question;

typedef struct {
    char name[256]; //e.g. hostname (e.g. example.com)
    uint16_t type; //A/AAAA/CNAME etc.
    uint16_t class; //Network
    uint32_t ttl; //Time to live (cache length)
    uint16_t rdlength; //Byte length of resource data
    uint8_t *rdata; //Resource data (e.g. IP address)
} dns_record;

typedef struct {
    // HEADER
    u_int16_t id; //Identifier
    bool qr; //Query or Response
    uint8_t opcode; //Type of message
    bool aa; //Authoritative Answer Flag
    bool tc; //Truncate Flag (due to excessive length)
    bool rd; //Recursion desire
    bool ra; //Recursion available
    bool ad; //Authenticated Data (part of DNSSEC)
    bool cd; //Checking Disabled (part of DNSSEC)
    uint8_t rcode; //Error code
    uint16_t qd_count; //Question count
    uint16_t an_count; //Answer Record Count
    uint16_t ns_count; //Authority Record Count
    uint16_t ar_count; //Additional Record Count

    dns_question question;
    dns_record *answers;
    dns_record *authority;
    dns_record *additional;
} dns_packet;

void print_dns_packet(const dns_packet *p);
int parse_dns_packet(const uint8_t* buf, size_t buf_size, dns_packet *p);
int create_dns_packet(uint8_t* buf, size_t buf_size, dns_packet* packet);
void free_dns_packet(dns_packet *p);

#endif //DNS_PACKET_H
