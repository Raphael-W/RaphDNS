#ifndef DNS_HELPERS_H
#define DNS_HELPERS_H
#include <stdint.h>
#include <time.h>

#define FNV_OFFSET 0xcbf29ce484222325ULL

time_t now_seconds(void);
uint64_t fnv1a(uint64_t h, const uint8_t *data, size_t len);

#endif //DNS_HELPERS_H