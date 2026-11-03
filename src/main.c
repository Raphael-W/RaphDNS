#include <stdio.h>
#include <time.h>

#include "network.h"
#include "resolver.h"

#define PORT 53

// Seeds rand() and runs the server on PORT. Returns its exit status
int main(void) {
    srand(time(NULL)); // Randomise rand() calls
    const int status = network_listen(PORT);

    return status;
}