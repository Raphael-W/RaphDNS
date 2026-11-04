#include <stdbool.h>
#include <stdio.h>
#include <string.h>
#include <time.h>

#include "network.h"
#include "blocklist.h"

#define PORT 53

// Seeds rand() and runs the server on PORT, logging every query if passed -v. Returns its exit status
int main(int argc, char **argv) {
    bool log_queries = false;
    if (argc == 2 && strcmp(argv[1], "-v") == 0) {
        log_queries = true;
    }
    else if (argc != 1) {
        fprintf(stderr, "Usage: %s [-v]\n", argv[0]);
        return 1;
    }

    srand(time(NULL)); // Randomise rand() calls

    list *l = list_create(8);
    if (!l) {
        printf("Failed to create empty blocklist");
        return 1;
    }

    int load_status = load_blocklists(BLOCKLIST_DIR, l);
    if (load_status < 0) {
        printf("Failed to load blocklist");
        return 1;
    }

    const int status = network_listen(PORT, l, log_queries);

    return status;
}