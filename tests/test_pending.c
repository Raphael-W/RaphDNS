#include "pending.h"
#include "harness.h"

#include <string.h>
#include <arpa/inet.h>

// The pending table is global, so every test removes what it adds

// FIXTURES
static struct sockaddr_in make_client(const char *ip, const uint16_t port) {
    struct sockaddr_in a = {.sin_family = AF_INET, .sin_port = htons(port)};
    inet_pton(AF_INET, ip, &a.sin_addr);
    return a;
}

// ADD / FIND / REMOVE
static void test_add_then_find(void) {
    const query in = {.client_id = 42, .question = {.name = "example.com", .type = 1, .class = 1}};
    const int id = pending_add(&in);
    CHECK(id >= 0);

    query *q = pending_find((uint16_t)id);
    CHECK(q != NULL);
    if (q) {
        CHECK(q->in_use);
        CHECK(q->id == id);
        CHECK(q->client_id == 42);
        CHECK(strcmp(q->question.name, "example.com") == 0);
        pending_remove(q);
    }
    CHECK(pending_find((uint16_t)id) == NULL);
}

// An ID that maps to the same slot but isn't the one stored there must miss
static void test_find_wrong_id_in_same_slot(void) {
    const query in = {0};
    const int id = pending_add(&in);
    const uint16_t other = (uint16_t)(id + PENDING_SIZE);
    CHECK(pending_find(other) == NULL);
    pending_remove(pending_find((uint16_t)id));
}

static void test_remove_twice_is_harmless(void) {
    const query in = {0};
    query *q = pending_find((uint16_t)pending_add(&in));
    pending_remove(q);
    pending_remove(q); // Mustn't decrement the used count again

    // If it had, the table would think it had a free slot when full
    int ids[PENDING_SIZE];
    for (int i = 0; i < PENDING_SIZE; i++) ids[i] = pending_add(&in);
    CHECK(pending_add(&in) == -1);
    for (int i = 0; i < PENDING_SIZE; i++) pending_remove(pending_find((uint16_t)ids[i]));
}

static void test_full_table_rejects_add(void) {
    const query in = {0};
    int ids[PENDING_SIZE];
    bool all_added = true;
    for (int i = 0; i < PENDING_SIZE; i++) {
        ids[i] = pending_add(&in);
        if (ids[i] < 0) all_added = false;
    }
    CHECK(all_added);
    CHECK(pending_add(&in) == -1);

    // Freeing one slot makes room again
    pending_remove(pending_find((uint16_t)ids[0]));
    ids[0] = pending_add(&in);
    CHECK(ids[0] >= 0);
    for (int i = 0; i < PENDING_SIZE; i++) pending_remove(pending_find((uint16_t)ids[i]));
}

// FIND BY CLIENT
static void test_find_client(void) {
    const struct sockaddr_in client = make_client("127.0.0.1", 5000);
    const query in = {.client_id = 7, .client = client};
    query *q = pending_find((uint16_t)pending_add(&in));

    CHECK(pending_find_client(&client, 7) == q);
    CHECK(pending_find_client(&client, 8) == NULL);

    const struct sockaddr_in other_port = make_client("127.0.0.1", 5001);
    const struct sockaddr_in other_ip = make_client("127.0.0.2", 5000);
    CHECK(pending_find_client(&other_port, 7) == NULL);
    CHECK(pending_find_client(&other_ip, 7) == NULL);
    pending_remove(q);
}

// Child lookups (for a nameserver's address) aren't what the client asked for
static void test_find_client_ignores_children(void) {
    const struct sockaddr_in client = make_client("127.0.0.1", 5000);
    query parent_in = {.client_id = 7, .client = client};
    query *parent = pending_find((uint16_t)pending_add(&parent_in));
    pending_remove(parent); // Only the child stays in the table

    const query child_in = {.client_id = 7, .client = client, .parent = parent};
    query *child = pending_find((uint16_t)pending_add(&child_in));
    CHECK(pending_find_client(&client, 7) == NULL);
    pending_remove(child);
}

// EXPIRY
static void test_next_expired(void) {
    const query a_in = {.expires_at = 100};
    const query waiting_in = {.expires_at = 50, .waiting = true};
    query *a = pending_find((uint16_t)pending_add(&a_in));
    query *waiting = pending_find((uint16_t)pending_add(&waiting_in));

    CHECK(pending_next_expired(99) == NULL);
    CHECK(pending_next_expired(100) == a); // Expires at exactly now
    CHECK(pending_next_expired(200) == a); // Waiting queries are skipped
    pending_remove(a);
    CHECK(pending_next_expired(200) == NULL);
    pending_remove(waiting);
}

static void test_earliest(void) {
    CHECK(pending_earliest() == 0);

    const query late_in = {.expires_at = 300};
    const query soon_in = {.expires_at = 100};
    const query waiting_in = {.expires_at = 10, .waiting = true};
    query *late = pending_find((uint16_t)pending_add(&late_in));
    query *soon = pending_find((uint16_t)pending_add(&soon_in));
    query *waiting = pending_find((uint16_t)pending_add(&waiting_in));

    CHECK(pending_earliest() == 100);
    pending_remove(soon);
    CHECK(pending_earliest() == 300);
    pending_remove(late);
    CHECK(pending_earliest() == 0);
    pending_remove(waiting);
}

int main(void) {
    RUN(test_add_then_find);
    RUN(test_find_wrong_id_in_same_slot);
    RUN(test_remove_twice_is_harmless);
    RUN(test_full_table_rejects_add);
    RUN(test_find_client);
    RUN(test_find_client_ignores_children);
    RUN(test_next_expired);
    RUN(test_earliest);

    printf("\n%d/%d checks passed\n", checks - failures, checks);
    return failures ? 1 : 0;
}
