#ifndef DNS_PACKET_H
#define DNS_PACKET_H
#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>

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

int parse_dns_packet(const uint8_t* buf, size_t buf_size, dns_packet *p);
int create_dns_packet(uint8_t* buf, size_t buf_size, dns_packet* packet);
void print_dns_packet(const dns_packet *p);

#endif //DNS_PACKET_H
