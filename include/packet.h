#ifndef DNS_PACKET_H
#define DNS_PACKET_H
#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>

typedef struct dns_packet {
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

    // QUESTION
    char name[256];
    uint16_t type;
    uint16_t class;

} dns_packet;

dns_packet parse_dns(const uint8_t* buf);
void print_dns(const dns_packet *packet);

#endif //DNS_PACKET_H
