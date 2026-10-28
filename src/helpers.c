#include "helpers.h"

#include <stdio.h>
#include <time.h>

const char* example_domains[] = {
    "google.com", "github.com", "example.com", "youtube.com", "facebook.com",
    "wikipedia.org", "amazon.com", "reddit.com", "twitter.com", "instagram.com",
    "linkedin.com", "netflix.com", "microsoft.com", "apple.com", "stackoverflow.com",
    "cloudflare.com", "bbc.co.uk", "nytimes.com", "spotify.com", "twitch.tv",
    "openai.com", "anthropic.com", "mozilla.org", "python.org", "rust-lang.org",
    "kernel.org", "gnu.org", "debian.org", "ubuntu.com", "archlinux.org",
    "duckduckgo.com", "bing.com", "yahoo.com", "zoom.us", "slack.com",
    "discord.com", "dropbox.com", "paypal.com", "ebay.com", "imdb.com",
    "news.ycombinator.com", "mail.google.com", "docs.google.com", "api.github.com",
    "en.wikipedia.org", "ox.ac.uk", "cam.ac.uk", "mit.edu", "stanford.edu", "localhost",
    "raphaelwreford.com"
};
const int example_domain_length = sizeof example_domains / sizeof example_domains[0];

long ip(const int a, const int b, const int c, const int d) {
    return (a << 24) + (b << 16) + (c << 8) + d;
}

void print_ip(long ip) {
    int a, b, c, d;

    d = (int) (ip & 0xff);
    c = (int) ((ip >> 8) & 0xff);
    b = (int) ((ip >> 16) & 0xff);
    a = (int) ((ip >> 24) & 0xff);

    printf("%d.%d.%d.%d\n", a, b, c, d);
}

time_t now_seconds(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return ts.tv_sec;
}
