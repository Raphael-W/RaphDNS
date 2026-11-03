#include <stdio.h>
#include <time.h>

#include "network.h"
#include "blocklist.h"

#define PORT 53

// Seeds rand() and runs the server on PORT. Returns its exit status
int main(void) {
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

    const int status = network_listen(PORT, l);

    return status;
}