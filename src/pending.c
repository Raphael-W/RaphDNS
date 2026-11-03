#include "pending.h"
#include <stdlib.h>

static query table[PENDING_SIZE];
static size_t used = 0;

// Copies q into the pending table under a random ID, which also decides its slot
// Returns the ID, or -1 if the table is full
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

// Returns the pending query with the given ID, or NULL if there isn't one
query *pending_find(const uint16_t id) {
    query *slot = &table[id % PENDING_SIZE];
    return (slot->in_use && slot->id == id) ? slot : NULL;
}

// Frees up a slot in the pending table
void pending_remove(query *q) {
    if (!q->in_use) return;
    q->in_use = false;
    used--;
}

// Returns the first expired query that isn't waiting on a child lookup, or NULL if there are none
query *pending_next_expired(const time_t now) {
    for (int i = 0; i < PENDING_SIZE; i++) {
        if (!table[i].waiting && table[i].in_use && table[i].expires_at <= now) {
            return &table[i];
        }
    }
    return NULL;
}

// Returns when the next query not waiting on a child lookup will expire, or 0 if there are none
time_t pending_earliest(void) {
    time_t earliest = 0;
    for (int i = 0; i < PENDING_SIZE; i++) {
        if (!table[i].waiting && table[i].in_use && (earliest == 0 || table[i].expires_at < earliest)) {
            earliest = table[i].expires_at;
        }
    }
    return earliest;
}