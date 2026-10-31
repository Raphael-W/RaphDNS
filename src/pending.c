#include "pending.h"
#include <stdlib.h>

static query table[PENDING_SIZE];
static size_t used = 0;

int pending_add(const query *q) {
    if (used == PENDING_SIZE) return -1;

    uint16_t id;
    do {
        id = (uint16_t) arc4random_uniform(65536);
    } while (table[id % PENDING_SIZE].in_use);

    query *slot = &table[id % PENDING_SIZE];
    *slot = *q;
    slot->id = id;
    slot->in_use = true;
    used++;
    return id;
}

query *pending_find(uint16_t id) {
    query *slot = &table[id % PENDING_SIZE];
    return (slot->in_use && slot->id == id) ? slot : NULL;
}

void pending_remove(query *q) {
    if (!q->in_use) return;
    q->in_use = false;
    used--;
}

query *pending_next_expired(time_t now) {
    for (int i = 0; i < PENDING_SIZE; i++) {
        if (table[i].in_use && table[i].expires_at <= now) {
            return &table[i];
        }
    }
    return NULL;
}

time_t pending_earliest(void) {
    time_t earliest = 0;
    for (int i = 0; i < PENDING_SIZE; i++) {
        if (table[i].in_use && (earliest == 0 || table[i].expires_at < earliest)) {
            earliest = table[i].expires_at;
        }
    }
    return earliest;
}