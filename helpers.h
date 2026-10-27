#ifndef DNS_HELPERS_H
#define DNS_HELPERS_H

extern const char* example_domains[];
extern const int example_domain_length;

long ip(int a, int b, int c, int d);
void print_ip(long ip);

#endif //DNS_HELPERS_H