#ifndef DNS_RESOLVER_H
#define DNS_RESOLVER_H
#include <stdint.h>
#include <sys/_types/_size_t.h>

int resolve_host(const char* name, uint8_t* buf, const size_t buf_size);

#endif //DNS_RESOLVER_H
