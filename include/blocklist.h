#ifndef DNS_BLOCKLIST_H
#define DNS_BLOCKLIST_H
#include <stdbool.h>
#include <sys/_types/_size_t.h>

#define MAX_LOAD_FACTOR 0.5

typedef struct list {
    char* *names;
    char* *bufs; // File contents that names point into
    size_t buf_count;
    size_t capacity;
    int entry_count;
} list;

list *list_create(size_t size);
void list_free(list *l);
int load_blocklist(const char* filename, list *l);
int load_blocklists(const char* dir_path, list *l);
bool list_blocks(const char *name, const list *l);
void list_resize(list *l, size_t new_size);

#endif //DNS_BLOCKLIST_H
