#include "helpers.h"

#include <stdarg.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <time.h>
#include <unistd.h>

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

// Prints a printf-style message to stdout, prefixed with the local date and time
// colour is one of the LOG_ colours, or NULL for none. It's ignored unless stdout is a terminal
void log_message(const char *colour, const char *format, ...) {
    const time_t now = time(NULL);
    struct tm local;
    char timestamp[32] = "unknown time";
    if (localtime_r(&now, &local)) strftime(timestamp, sizeof timestamp, "%Y-%m-%d %H:%M:%S", &local);

    const bool use_colour = colour && isatty(STDOUT_FILENO);

    printf("[%s] %s", timestamp, use_colour ? colour : "");

    va_list args;
    va_start(args, format);
    vprintf(format, args);
    va_end(args);

    printf("%s\n", use_colour ? "\033[0m" : "");
    fflush(stdout); // Otherwise output redirected to a file is held back until the buffer fills
}
