#!/bin/sh
# End-to-end test: starts the server and queries it with dig
# Usage: test_dig.sh path/to/dns
# Lookups that need the internet are skipped if the root servers can't be reached

DNS_BIN="$1"
PORT=15353
BLOCKED="ads.10click.com" # From blocklists/

if ! command -v dig > /dev/null; then
    echo "dig not found, skipping"
    exit 77
fi

LOG=$(mktemp)
"$DNS_BIN" -v -p "$PORT" > "$LOG" 2>&1 &
SERVER=$!
trap 'kill $SERVER 2> /dev/null; wait $SERVER 2> /dev/null; rm -f "$LOG"' EXIT

checks=0
failures=0

# Prints the full dig output for a query
query() {
    dig @127.0.0.1 -p "$PORT" +time=5 +tries=1 "$@" 2>&1
}

# Prints just the rcode (NOERROR, NXDOMAIN, ...) from dig output
status_of() {
    echo "$1" | sed -n 's/.*status: \([A-Z]*\).*/\1/p'
}

# Prints "yes" if dig output has at least one answer record
answers_of() {
    if echo "$1" | grep -q "ANSWER: [1-9]"; then echo "yes"; else echo "no"; fi
}

check() {
    checks=$((checks + 1))
    if [ "$2" = "$3" ]; then
        echo "  ok: $1"
    else
        echo "  FAIL: $1 (expected '$3', got '$2')"
        failures=$((failures + 1))
    fi
}

# dig warns rather than fails when it can't parse a reply, so look for that too (e.g. a bad compression pointer)
check_parses() {
    if echo "$2" | grep -qi "malformed\|warning"; then
        check "$1 parses cleanly" "malformed" "clean"
    else
        check "$1 parses cleanly" "clean" "clean"
    fi
}

# Wait for the blocklist to load and the server to start answering
ready=0
for _ in $(seq 1 50); do
    if [ -n "$(status_of "$(dig @127.0.0.1 -p "$PORT" +time=1 +tries=1 "$BLOCKED")")" ]; then
        ready=1; break
    fi
    sleep 0.2
done
if [ "$ready" -eq 0 ]; then
    echo "Server didn't start answering. Log:"
    cat "$LOG"
    exit 1
fi

echo "Offline"
out=$(query "$BLOCKED")
check "blocked domain gets NXDOMAIN" "$(status_of "$out")" "NXDOMAIN"

out=$(query "tracker.$BLOCKED")
check "subdomain of a blocked domain gets NXDOMAIN" "$(status_of "$out")" "NXDOMAIN"

out=$(query +norecurse "not-cached.example.org")
check "uncached query without RD is refused" "$(status_of "$out")" "REFUSED"

out=$(query +opcode=status "example.com")
check "unsupported opcode gets NOTIMP" "$(status_of "$out")" "NOTIMP"

echo "Online"
if ! dig @198.41.0.4 +time=3 +tries=1 . NS > /dev/null 2>&1; then
    echo "  skipped: root servers unreachable"
else
    out=$(query example.com A)
    check "example.com resolves" "$(status_of "$out")" "NOERROR"
    check "example.com has an answer" "$(answers_of "$out")" "yes"
    check_parses "example.com" "$out"

    # Without RD the server only answers from its cache, so NOERROR here means the first answer was cached
    out=$(query +norecurse example.com A)
    check "example.com is answered from the cache" "$(status_of "$out")" "NOERROR"
    check_parses "cached example.com" "$out"

    # NS replies fill the authority and additional sections, so most names in them are compressed
    out=$(query google.com NS)
    check "google.com NS resolves" "$(status_of "$out")" "NOERROR"
    check_parses "google.com NS" "$out"

    # Follows a CNAME to another name
    out=$(query www.github.com A)
    check "www.github.com resolves through its CNAME" "$(status_of "$out")" "NOERROR"
    check_parses "www.github.com" "$out"

    out=$(query does-not-exist.example.com A)
    check "nonexistent name gets NXDOMAIN" "$(status_of "$out")" "NXDOMAIN"
fi

echo
echo "$((checks - failures))/$checks checks passed"
if [ "$failures" -ne 0 ]; then
    echo "Server log:"
    cat "$LOG"
    exit 1
fi
