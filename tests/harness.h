#ifndef DNS_TEST_HARNESS_H
#define DNS_TEST_HARNESS_H

#include <stdbool.h>
#include <stdio.h>

// CHECK reports a failure and carries on, so one run shows every failing check
static int failures = 0;
static int checks = 0;

#define CHECK(cond) do {                                                              \
    checks++;                                                                         \
    if (!(cond)) {                                                                    \
        fprintf(stderr, "  %s:%d: CHECK failed: %s\n", __FILE__, __LINE__, #cond);    \
        failures++;                                                                   \
    }                                                                                 \
} while (0)

// Like CHECK, but returns from the test on failure, for setup steps the rest of the test depends on
#define REQUIRE(cond) do {                                                            \
    checks++;                                                                         \
    if (!(cond)) {                                                                    \
        fprintf(stderr, "  %s:%d: REQUIRE failed: %s\n", __FILE__, __LINE__, #cond);  \
        failures++;                                                                   \
        return;                                                                       \
    }                                                                                 \
} while (0)

// Returns whether snprintf's return value n means the whole string fitted in size bytes
static inline bool format_fits(const int n, const size_t size) {
    return n >= 0 && (size_t)n < size;
}

// Formats into buf (an array, not a pointer) like snprintf. Returns false if the result was cut off
#define FORMAT(buf, ...) format_fits(snprintf((buf), sizeof (buf), __VA_ARGS__), sizeof (buf))

#define RUN(test) do { printf("%s\n", #test); test(); } while (0)

#endif
