#include "blocklist.h"
#include "harness.h"

#include <dirent.h>
#include <limits.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

// FIXTURES
// Blocklists can only be filled from files, so each test writes its own into a temporary directory
static char tmp_dir[PATH_MAX];

// Writes contents to tmp_dir/name and returns the full path (valid until the next call)
static const char *write_file(const char *name, const char *contents) {
    static char path[PATH_MAX];
    snprintf(path, sizeof path, "%s/%s", tmp_dir, name);
    FILE *f = fopen(path, "w");
    if (f) { fputs(contents, f); fclose(f); }
    return path;
}

// Removes everything in dir (one level of subdirectories deep) and dir itself
static void remove_dir(const char *dir) {
    DIR *d = opendir(dir);
    if (!d) return;
    const struct dirent *e;
    while ((e = readdir(d))) {
        if (strcmp(e->d_name, ".") == 0 || strcmp(e->d_name, "..") == 0) continue;
        char path[PATH_MAX];
        snprintf(path, sizeof path, "%s/%s", dir, e->d_name);
        if (unlink(path) != 0) remove_dir(path);
    }
    closedir(d);
    rmdir(dir);
}

// Returns a list loaded from a file with the given contents
static list *list_from(const char *contents) {
    list *l = list_create(8);
    load_blocklist(write_file("list.txt", contents), l);
    return l;
}

// CREATING
static void test_create_list(void) {
    list *l = list_create(8);
    CHECK(l != NULL);
    if (!l) return;
    CHECK(l->capacity == 8);
    CHECK(l->entry_count == 0);
    CHECK(l->buf_count == 0);
    bool all_empty = true;
    for (size_t i = 0; i < l->capacity; i++) {
        if (l->names[i]) all_empty = false;
    }
    CHECK(all_empty);
    CHECK(!list_blocks("example.com", l));
    list_free(l);
}

static void test_free_null_is_harmless(void) {
    list_free(NULL);
    CHECK(true);
}

// MATCHING
static void test_blocks_listed_name(void) {
    list *l = list_from("ads.example.com\n");
    CHECK(l->entry_count == 1);
    CHECK(list_blocks("ads.example.com", l));
    CHECK(list_blocks("ADS.Example.COM", l));
    CHECK(!list_blocks("example.com", l));
    list_free(l);
}

static void test_blocks_subdomains(void) {
    list *l = list_from("tracker.net\n");
    CHECK(list_blocks("a.tracker.net", l));
    CHECK(list_blocks("a.b.c.tracker.net", l));
    CHECK(!list_blocks("net", l));
    list_free(l);
}

// Only whole labels count: listing tracker.net mustn't block nottracker.net
static void test_does_not_block_lookalikes(void) {
    list *l = list_from("tracker.net\n");
    CHECK(!list_blocks("nottracker.net", l));
    CHECK(!list_blocks("tracker.net.evil.com", l));
    CHECK(!list_blocks("tracker.ne", l));
    list_free(l);
}

// LOADING
static void test_skips_comments_and_blank_lines(void) {
    list *l = list_from("# A comment\n\nads.com\n#notblocked.com\n\n");
    CHECK(l->entry_count == 1);
    CHECK(list_blocks("ads.com", l));
    CHECK(!list_blocks("notblocked.com", l));
    list_free(l);
}

static void test_handles_crlf_line_endings(void) {
    list *l = list_from("one.com\r\ntwo.com\r\n");
    CHECK(l->entry_count == 2);
    CHECK(list_blocks("one.com", l));
    CHECK(list_blocks("two.com", l));
    list_free(l);
}

static void test_loads_last_line_without_newline(void) {
    list *l = list_from("one.com\ntwo.com");
    CHECK(list_blocks("two.com", l));
    list_free(l);
}

static void test_duplicates_counted_once(void) {
    list *l = list_from("ads.com\nADS.COM\nads.com\n");
    CHECK(l->entry_count == 1);
    list_free(l);
}

static void test_grows_when_load_factor_reached(void) {
    list *l = list_create(4);
    load_blocklist(write_file("many.txt", "a.com\nb.com\nc.com\nd.com\ne.com\nf.com\ng.com\nh.com\ni.com\nj.com\n"), l);
    CHECK(l->entry_count == 10);
    CHECK((double)l->entry_count / (double)l->capacity < MAX_LOAD_FACTOR);

    const char *names[] = {"a.com", "b.com", "c.com", "d.com", "e.com", "f.com", "g.com", "h.com", "i.com", "j.com"};
    bool all_blocked = true;
    for (size_t i = 0; i < 10; i++) {
        if (!list_blocks(names[i], l)) all_blocked = false;
    }
    CHECK(all_blocked);
    list_free(l);
}

static void test_load_missing_file_fails(void) {
    list *l = list_create(8);
    char path[PATH_MAX];
    snprintf(path, sizeof path, "%s/does-not-exist.txt", tmp_dir);
    CHECK(load_blocklist(path, l) == -1);
    CHECK(l->entry_count == 0);
    CHECK(l->buf_count == 0);
    list_free(l);
}

// Names from several files end up in the same list
static void test_load_several_files(void) {
    list *l = list_create(8);
    CHECK(load_blocklist(write_file("first.txt", "one.com\n"), l) == 0);
    CHECK(load_blocklist(write_file("second.txt", "two.com\n"), l) == 0);
    CHECK(l->buf_count == 2);
    CHECK(list_blocks("one.com", l));
    CHECK(list_blocks("two.com", l));
    list_free(l);
}

// DIRECTORIES
// Loads regular files, but skips hidden files and subdirectories
static void test_load_directory(void) {
    char dir[PATH_MAX];
    snprintf(dir, sizeof dir, "%s/lists", tmp_dir);
    mkdir(dir, 0700);

    char sub[PATH_MAX];
    snprintf(sub, sizeof sub, "%s/nested", dir);
    mkdir(sub, 0700);

    write_file("lists/ads.txt", "ads.com\n");
    write_file("lists/trackers.txt", "tracker.net\n");
    write_file("lists/.hidden", "hidden.com\n");

    list *l = list_create(8);
    CHECK(load_blocklists(dir, l) == 0);
    CHECK(list_blocks("ads.com", l));
    CHECK(list_blocks("tracker.net", l));
    CHECK(!list_blocks("hidden.com", l));
    CHECK(l->buf_count == 2);
    list_free(l);
}

static void test_load_missing_directory_fails(void) {
    list *l = list_create(8);
    char dir[PATH_MAX];
    snprintf(dir, sizeof dir, "%s/no-such-dir", tmp_dir);
    CHECK(load_blocklists(dir, l) == -1);
    list_free(l);
}

int main(void) {
    const char *base = getenv("TMPDIR");
    snprintf(tmp_dir, sizeof tmp_dir, "%s/dns_blocklist_XXXXXX", base && *base ? base : "/tmp");
    if (!mkdtemp(tmp_dir)) { perror("mkdtemp"); return 1; }

    RUN(test_create_list);
    RUN(test_free_null_is_harmless);

    RUN(test_blocks_listed_name);
    RUN(test_blocks_subdomains);
    RUN(test_does_not_block_lookalikes);

    RUN(test_skips_comments_and_blank_lines);
    RUN(test_handles_crlf_line_endings);
    RUN(test_loads_last_line_without_newline);
    RUN(test_duplicates_counted_once);
    RUN(test_grows_when_load_factor_reached);
    RUN(test_load_missing_file_fails);
    RUN(test_load_several_files);

    RUN(test_load_directory);
    RUN(test_load_missing_directory_fails);

    remove_dir(tmp_dir);
    printf("\n%d/%d checks passed\n", checks - failures, checks);
    return failures ? 1 : 0;
}
