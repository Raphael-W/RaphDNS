#ifndef DNS_TEST_HARNESS_H
#define DNS_TEST_HARNESS_H

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

#define RUN(test) do { printf("%s\n", #test); test(); } while (0)

#endif
