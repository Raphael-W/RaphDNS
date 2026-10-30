#include "network.h"

#define PORT 53

int main(void) {
    const int status = network_listen(PORT);

    return status;
}