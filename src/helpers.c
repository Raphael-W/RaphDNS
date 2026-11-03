#include "helpers.h"

#include <stdint.h>
#include <stdio.h>
#include <time.h>

// Returns the current monotonic time in seconds, for measuring elapsed time (not the time of day)
time_t now_seconds(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return ts.tv_sec;
}

// Continues the FNV-1a hash h over len bytes of data, returning the new hash
uint64_t fnv1a(uint64_t h, const uint8_t *data, const size_t len) {
    for (size_t i = 0; i < len; i++) {
        h ^= data[i];
        h *= 0x100000001b3ULL;
    }
    return h;
}
