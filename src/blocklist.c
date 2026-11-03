#include "blocklist.h"
#include "helpers.h"

#include <assert.h>
#include <ctype.h>
#include <dirent.h>
#include <limits.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>

static size_t index_key(const char *name, const list *l) {
    uint64_t h = FNV_OFFSET;
    for (const char *c = name; *c; c++) {
        uint8_t lower = (uint8_t) tolower((unsigned char) *c);
        h = fnv1a(h, &lower, 1);
    }
    return h % l->capacity;
}

static void insert_name(char *name, list *l) {
    size_t index = index_key(name, l);
    size_t distance = 0;
    while (l->names[index]) {
        if (strcasecmp(l->names[index], name) == 0) return; // Already listed
        index = (index + 1) % l->capacity;
        distance +=1;
        assert(distance < l->capacity); // The load factor should always leave an empty slot
    }
    l->names[index] = name;
    l->entry_count++;

    const double load_factor = (double)l->entry_count / (double)l->capacity;
    if (load_factor >= MAX_LOAD_FACTOR) {
        const size_t new_size = l->capacity * 2;
        list_resize(l, new_size);
    }
}

static bool list_contains(const char *name, const list *l) {
    size_t index = index_key(name, l);
    size_t distance = 0;
    while (l->names[index]) {
        if (strcasecmp(l->names[index], name) == 0) return true;
        index = (index + 1) % l->capacity;
        distance +=1;
        if (distance >= l->capacity) return false;
    }
    return false;
}

static char *read_file(const char *path, size_t *out_size) {
    FILE *f = fopen(path, "rb");
    if (!f) return NULL;

    if (fseek(f, 0, SEEK_END) != 0) { fclose(f); return NULL; }
    const long size = ftell(f);
    if (size < 0) { fclose(f); return NULL; }
    rewind(f);

    char *buf = malloc((size_t)size + 1);
    if (!buf) { fclose(f); return NULL; }

    const size_t read = fread(buf, 1, (size_t)size, f);
    fclose(f);
    if (read != (size_t)size) { free(buf); return NULL; }

    buf[size] = '\0';
    *out_size = (size_t)size;
    return buf;
}

list *list_create(const size_t size) {
    list *l = malloc(sizeof *l);
    if (!l) return NULL;

    l->names = calloc(size, sizeof *l->names);
    if (!l->names) { free(l); return NULL; }
    l->bufs = NULL;
    l->buf_count = 0;
    l->entry_count = 0;
    l->capacity = size;
    return l;
}

void list_free(list *l) {
    if (!l) return;
    free(l->names);
    for (size_t i = 0; i < l->buf_count; i++) free(l->bufs[i]);
    free(l->bufs);
    free(l);
}

bool list_blocks(const char *name, const list *l) {
     for (const char *p = name; p; p = strchr(p, '.'), p = p ? p + 1 : NULL) {
         if (list_contains(p, l)) return true;
     }
    return false;
}

void list_resize(list *l, const size_t new_size) {
    char* *new_names = calloc(new_size, sizeof *new_names);
    if (!new_names) return;

    char* *old_names = l->names;
    const size_t old_capacity = l->capacity;

    l->names = new_names;
    l->capacity = new_size;
    l->entry_count = 0;
    for (size_t i = 0; i < old_capacity; i++) {
        if (!old_names[i]) continue;
        insert_name(old_names[i], l);
    }
    free(old_names);
}

int load_blocklist(const char* filename, list *l) {
    size_t file_size;
    char *buf = read_file(filename, &file_size);
    if (!buf) { perror(filename); return -1; }

    char* *bufs = realloc(l->bufs, (l->buf_count + 1) * sizeof *bufs);
    if (!bufs) { free(buf); return -1; }
    bufs[l->buf_count++] = buf;
    l->bufs = bufs;

    char *p = buf;
    char *end = buf + file_size;

    while (p < end) {
        char *line = p;
        char *nl = memchr(p, '\n', end - p);
        if (!nl) nl = end;

        *nl = '\0';
        p = nl + 1;

        size_t len = nl - line;
        if (len > 0 && line[len - 1] == '\r') line[--len] = '\0';
        if (len == 0 || line[0] == '#') continue;

        insert_name(line, l);
    }

    return 0;

}

// Loads every regular, non-hidden file in dir_path into l. A file that fails to load
// doesn't stop the others. Returns 0 on success, or -1 if anything failed to load
int load_blocklists(const char* dir_path, list *l) {
    DIR *dir = opendir(dir_path);
    if (!dir) { perror(dir_path); return -1; }

    int status = 0;
    const struct dirent *entry;
    while ((entry = readdir(dir))) {
        if (entry->d_name[0] == '.') continue;

        char path[PATH_MAX];
        const int len = snprintf(path, sizeof path, "%s/%s", dir_path, entry->d_name);
        if (len < 0 || (size_t)len >= sizeof path) { status = -1; continue; }

        struct stat st;
        if (stat(path, &st) != 0) { perror(path); status = -1; continue; }
        if (!S_ISREG(st.st_mode)) continue;

        if (load_blocklist(path, l) != 0) status = -1;
    }

    closedir(dir);
    return status;
}
