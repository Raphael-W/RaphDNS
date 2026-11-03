#include "helpers.h"

#include <stdio.h>
#include <time.h>

// Returns the current monotonic time in seconds, for measuring elapsed time (not the time of day)
time_t now_seconds(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return ts.tv_sec;
}
