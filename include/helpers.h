#ifndef DNS_HELPERS_H
#define DNS_HELPERS_H
#include <stdint.h>
#include <time.h>

#define FNV_OFFSET 0xcbf29ce484222325ULL

// ANSI colours for log_message
#define LOG_RED    "\033[31m"
#define LOG_GREEN  "\033[32m"
#define LOG_YELLOW "\033[33m"

time_t now_seconds(void);
uint64_t now_nanos(void);
uint64_t fnv1a(uint64_t h, const uint8_t *data, size_t len);
int log_timestamp(char *out, size_t len);
void log_message(const char *prefix, const char *colour, const char *format, ...) __attribute__((format(printf, 3, 4)));

#endif //DNS_HELPERS_H