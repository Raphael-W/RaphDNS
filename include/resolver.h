#ifndef DNS_RESOLVER_H
#define DNS_RESOLVER_H
#include <stdint.h>
#include "pending.h"

#define EDNS_UDP_SIZE 1232

typedef enum {
    RESOLVE_SEND,
    RESOLVE_DONE,
    RESOLVE_FAILED
} resolve_step;

resolve_step resolver_start(query *q, uint8_t *out, size_t out_size, int *out_len, char *next_ip);
resolve_step resolver_on_response(query **qp, const dns_packet *reply, uint8_t *out, size_t out_size, int *out_len, char *next_ip);
void resolver_add_cnames(const query *q, dns_packet *reply);
resolve_step resolver_on_timeout(query **qp, uint8_t *out, size_t out_size, int *out_len, char *next_ip);

#endif //DNS_RESOLVER_H
