#ifndef DNS_HELPERS_H
#define DNS_HELPERS_H
#include <stdint.h>
#include <time.h>

extern const char* example_domains[];
extern const int example_domain_length;

uint32_t ip(uint32_t a, uint32_t b, uint32_t c, uint32_t d);
void print_ip(uint32_t ip);
time_t now_seconds(void);

#endif //DNS_HELPERS_H