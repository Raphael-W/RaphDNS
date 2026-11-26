#ifndef DNS_LOCAL_H
#define DNS_LOCAL_H

#include <stddef.h>
#include <stdint.h>
#include "packet.h"

typedef struct {
    char name[256];
    uint16_t type;
    uint16_t rdlength;
    uint8_t rdata[256]; // an IPv4/IPv6 address, or a name in wire format for PTR
} local_record;

typedef struct {
    local_record *records;
    size_t count;
    size_t capacity;
} local_records;

// Result of local_record_packet. Values above LOCAL_NOT_FOUND mean a reply was built
typedef enum {
    LOCAL_ERROR = -1,    // allocation failed
    LOCAL_NOT_FOUND = 0, // not a local name: resolve as normal
    LOCAL_ANSWER = 1,    // reply has answers
    LOCAL_NO_DATA = 2,   // name exists, but has no records of this type
    LOCAL_NXDOMAIN = 3,  // name is under home.arpa but isn't in the local records
} local_status;

int insert_record(local_records *l, const char *name, uint16_t type, uint16_t rdlength, const uint8_t *rdata);
local_records *local_records_create(size_t size);
void local_records_free(local_records *l);
int load_local_records(const char* path, local_records *l);
int local_records_resize(local_records *l, size_t new_size);
local_status local_record_packet(const local_records *l, const dns_packet *q, dns_packet *p);

#endif //DNS_LOCAL_H
