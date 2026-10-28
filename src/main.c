#include "network.h"

#define PORT 5300

int main(void) {
    const int status = network_listen(PORT);

    return status;
}