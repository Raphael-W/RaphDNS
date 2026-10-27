#include <string.h>
#include <stdio.h>
#include "hashmap.h"
#include "helpers.h"

int main(void) {
    const int hashmap_size = 8;
    hashmap cache = create_hashmap(hashmap_size);
    for (long i = 0; i < example_domain_length; i++) {
        hashmap_add(cache, (char*) example_domains[i], ip(192, 168, 0, (int)i + 1));
    }

    entry *valid_cached_entry = hashmap_lookup(cache, "google.com");
    entry *invalid_cached_entry = hashmap_lookup(cache, "incorrect.com");

    print_ip(valid_cached_entry->ip);
    if (invalid_cached_entry == NULL) {printf("miss\n");};


    return 0;
}
