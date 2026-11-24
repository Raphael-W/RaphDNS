#include "helpers.h"
#include "harness.h"

#include <string.h>
#include <ctype.h>

// FNV-1a
// Published FNV-1a 64-bit test vectors
static void test_fnv1a_known_vectors(void) {
    CHECK(fnv1a(FNV_OFFSET, (const uint8_t *)"", 0) == 0xcbf29ce484222325ULL);
    CHECK(fnv1a(FNV_OFFSET, (const uint8_t *)"a", 1) == 0xaf63dc4c8601ec8cULL);
    CHECK(fnv1a(FNV_OFFSET, (const uint8_t *)"foobar", 6) == 0x85944171f73967e8ULL);
}

// The cache and blocklist hash a byte at a time, which must match hashing it all at once
static void test_fnv1a_chains(void) {
    const uint8_t *data = (const uint8_t *)"example.com";
    uint64_t h = FNV_OFFSET;
    for (size_t i = 0; i < 11; i++) h = fnv1a(h, &data[i], 1);
    CHECK(h == fnv1a(FNV_OFFSET, data, 11));
}

// CLOCKS
static void test_clocks_never_go_backwards(void) {
    const time_t s1 = now_seconds();
    const uint64_t n1 = now_nanos();
    const time_t s2 = now_seconds();
    const uint64_t n2 = now_nanos();
    CHECK(s2 >= s1);
    CHECK(n2 >= n1);
}

static void test_clocks_agree(void) {
    const time_t s = now_seconds();
    const uint64_t n = now_nanos();
    CHECK((time_t)(n / 1000000000ULL) - s <= 1);
}

// LOGGING
static void test_log_timestamp_format(void) {
    char buf[64];
    const int n = log_timestamp(buf, sizeof buf);
    CHECK(n == 22); // "[YYYY-MM-DD HH:MM:SS] "
    CHECK((int)strlen(buf) == n);
    CHECK(buf[0] == '[' && buf[20] == ']' && buf[21] == ' ');
    CHECK(buf[5] == '-' && buf[8] == '-' && buf[11] == ' ' && buf[14] == ':' && buf[17] == ':');
    CHECK(isdigit((unsigned char)buf[1]) && isdigit((unsigned char)buf[19]));
}

// Like snprintf, a short buffer is truncated but the full width is still returned
static void test_log_timestamp_truncates(void) {
    char buf[5];
    CHECK(log_timestamp(buf, sizeof buf) == 22);
    CHECK(strlen(buf) == 4);
}

int main(void) {
    RUN(test_fnv1a_known_vectors);
    RUN(test_fnv1a_chains);
    RUN(test_clocks_never_go_backwards);
    RUN(test_clocks_agree);
    RUN(test_log_timestamp_format);
    RUN(test_log_timestamp_truncates);

    printf("\n%d/%d checks passed\n", checks - failures, checks);
    return failures ? 1 : 0;
}
