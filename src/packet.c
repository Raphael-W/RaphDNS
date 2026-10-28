#include "packet.h"

#include <stdio.h>
#include <string.h>

dns_packet parse_dns(const uint8_t* buf) {
    dns_packet new_packet = {0};
    //HEADER
    new_packet.id = (buf[0] << 8) | buf[1];
    new_packet.qr = (buf[2] >> 7) & 1;
    new_packet.opcode = (buf[2] >> 3) & 0xF;
    new_packet.aa = (buf[2] >> 2) & 1;
    new_packet.tc = (buf[2] >> 1) & 1;
    new_packet.rd = buf[2] & 1;
    new_packet.ra = (buf[3] >> 7) & 1;
    new_packet.ad = (buf[3] >> 5) & 1;
    new_packet.cd = (buf[3] >> 4) & 1;
    new_packet.rcode = buf[3] & 0xF;
    new_packet.qd_count = (buf[4] << 8) | buf[5];
    new_packet.an_count = (buf[6] << 8) | buf[7];
    new_packet.ns_count = (buf[8] << 8) | buf[9];
    new_packet.ar_count = (buf[10] << 8) | buf[11];

    // QUESTION
    uint8_t label_length = buf[12];
    int name_length = 0;
    while (label_length > 0) {
        memcpy(new_packet.name + name_length, buf + 13 + name_length, label_length);
        name_length += label_length;
        new_packet.name[name_length] = '.';
        label_length = buf[13 + name_length];
        name_length++;
    }
    new_packet.name[name_length - 1] = '\0';

    int name_end = 13 + name_length;
    new_packet.type = (buf[name_end] << 8) | buf[name_end + 1];
    new_packet.class = (buf[name_end + 2] << 8) | buf[name_end + 3];
    return new_packet;
}

void print_dns(const dns_packet *packet) {
    printf("Header: \n");
    printf("ID: %u\n", packet->id);
    printf("Query/response: %d\n", packet->qr);
    printf("Opcode: %d\n", packet->opcode);
    printf("Authoritive Answer: %d\n", packet->aa);
    printf("Truncate Flag: %d\n", packet->tc);
    printf("Recursion Desired: %d\n", packet->rd);
    printf("Recursion Available: %d\n", packet->ra);
    printf("Authenticated Data: %d\n", packet->ad);
    printf("Checking Disabled: %d\n", packet->cd);
    printf("Error Code: %d\n", packet->rcode);
    printf("Question Count: %u\n", packet->qd_count);
    printf("Answer Record Count: %u\n", packet->an_count);
    printf("Authority Record Count: %u\n", packet->ns_count);
    printf("Additional Record Count: %u\n", packet->ar_count);

    printf("\nQuestion: \n");
    printf("Name: %s\n", packet->name);
    printf("Type: %u\n", packet->type);
    printf("Class: %u\n", packet->class);
}