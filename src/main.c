#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/errno.h>

#include "network.h"
#include "blocklist.h"
#include "local.h"

#define DEFAULT_PORT 53
#define DEFAULT_ADDRESS "127.0.0.1"

// Returns the port as an int so that -1 can signal an invalid port
static int parse_port(const char* port_str) {
    char *end;
    errno = 0;
    long long_p = strtol(port_str, &end, 10);

    if (end == port_str)                return -1;  // no digits at all ("abc", "")
    if (*end != '\0')                   return -1;  // trailing junk ("12abc")
    if (errno == ERANGE)                return -1;  // overflowed long
    if (long_p < 1 || long_p > 65535)   return -1;  // outside of port range (uint16)

    return (int)long_p;
}

// Seeds rand() and runs the server on PORT, logging every query if passed -v. Returns its exit status
int main(int argc, char *argv[]) {
    srand(time(NULL)); // Randomise rand() calls

    bool verbose = false;
    char* port_str = 0;
    char* ip = 0;
    char* local = 0;
    int opt;

    // "vp:b:l:h" -> -v (flag), -p <arg>, -b <arg>, -l <arg>, -h (flag)
    while ((opt = getopt(argc, argv, "vp:b:l:h")) != -1) {
        switch (opt) {
            case 'v': verbose = true; break;
            case 'p': port_str = optarg; break;
            case 'b': ip = optarg; break;
            case 'l': local = optarg; break;
            case 'h': printf("usage: %s [-v] [-p port] [-b address] [-l local_records_file]\n", argv[0]); return 0;
            case '?': // unknown option or missing argument (getopt already printed an error)
            default:  return 1;
        }
    }

    const int port = port_str ? parse_port(port_str) : DEFAULT_PORT;
    if (port < 0) { fprintf(stderr, "Invalid port: Must be between 1-65535\n"); return 1; }

    struct sockaddr_in tmp;
    if (ip == NULL) {ip = DEFAULT_ADDRESS;}
    if (inet_pton(AF_INET, ip, &tmp.sin_addr) != 1) { fprintf(stderr, "Invalid address\n"); return 1; }

    // --- LOAD LOCAL RECORDS ---
    local_records *r = local_records_create(1);
    if (!r) {
        printf("Failed to create empty local records list\n");
        return 1;
    }

    if (local) {
        const int local_load_status = load_local_records(local, r);
        if (local_load_status < 0) {
            printf("Failed to load local records\n");
            return 1;
        }
    }

    // --- LOAD BLOCKLISTS ---
    list *l = list_create(8);
    if (!l) {
        printf("Failed to create empty blocklist\n");
        return 1;
    }

    const int blocklist_load_status = load_blocklists(BLOCKLIST_DIR, l);
    if (blocklist_load_status < 0) {
        printf("Failed to load blocklist\n");
        return 1;
    }

    // --- BEGIN LISTENING ---
    const int status = network_listen(port, ip, l, r, verbose);

    return status;
}