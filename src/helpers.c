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

// Returns the current monotonic time in nanoseconds, for timing how long a request takes
uint64_t now_nanos(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint64_t)ts.tv_sec * 1000000000ULL + ts.tv_nsec;
}

// Continues the FNV-1a hash h over len bytes of data, returning the new hash
uint64_t fnv1a(uint64_t h, const uint8_t *data, const size_t len) {
    for (size_t i = 0; i < len; i++) {
        h ^= data[i];
        h *= 0x100000001b3ULL;
    }
    return h;
}

// Writes the local date and time into out as "[YYYY-MM-DD HH:MM:SS] ", returning the number of characters written
// Exposed so callers that align columns know the prefix's width
int log_timestamp(char *out, const size_t len) {
    const time_t now = time(NULL);
    struct tm local;
    char timestamp[32] = "unknown time";
    if (localtime_r(&now, &local)) strftime(timestamp, sizeof timestamp, "%Y-%m-%d %H:%M:%S", &local);
    return snprintf(out, len, "[%s] ", timestamp);
}

// Prints prefix (uncoloured), then a printf-style message wrapped in colour, with a trailing newline
// colour is one of the LOG_ colours, or NULL for none. It's ignored unless stdout is a terminal
void log_message(const char *prefix, const char *colour, const char *format, ...) {
    const bool use_colour = colour && isatty(STDOUT_FILENO);

    printf("%s%s", prefix, use_colour ? colour : "");

    va_list args;
    va_start(args, format);
    vprintf(format, args);
    va_end(args);

    printf("%s\n", use_colour ? "\033[0m" : "");
    fflush(stdout); // Otherwise output redirected to a file is held back until the buffer fills
}
