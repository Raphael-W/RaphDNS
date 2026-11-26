# RaphDNS: a Recursive DNS Resolver

![Query log from running with -v, showing resolved, cached, blocked and rejected queries](docs/screenshot.png)

## Features
- Resolves from the root servers
- Blocks ads, trackers and malware using [HaGeZi's Multi PRO](https://github.com/hagezi/dns-blocklists) blocklist of around 250,000 domains
- Answers local names like `nas.home.arpa` from a hosts-style file, including reverse lookups
- Caches answers until their TTL expires
- Handles many lookups at once on a single thread
- Logs every query with `-v`, colour-coded by outcome

## How it works

When a query arrives, the server checks the blocklist, then the cache, and only then starts a lookup from the root.

**Packet parsing:** A bounds-checked bit reader and writer handle the DNS wire format, so malformed packets are rejected rather than read out of bounds. Compression pointers are followed with a jump limit, which stops a crafted packet from causing an infinite loop.

**Recursive resolution:** Each lookup moves from the root to the TLD to the authoritative server, trying the next server on a timeout or error. It also follows CNAME chains and resolves nameservers that arrive without glue records as child lookups. A query budget shared across each lookup stops circular dependencies from recursing forever.

**Event loop:** A single thread uses `poll()` and non-blocking sockets to handle many lookups at once, so a slow nameserver never holds up other clients. In-flight queries are kept in a fixed-size table, each with its own timeout. Replies are only accepted if the query ID, source address and question all match, which makes spoofing harder.

**Cache:** A chained hash table using FNV-1a, which grows as it fills. Entries are keyed on name, type and class, ignoring case in the name. TTLs count down while a response is cached, and expired entries are evicted during lookups.

**Domain blocking:** Blocklists are loaded at startup into an open-addressing hash table. Each lookup checks the name and all of its parent domains, so blocking `example.com` also blocks `ads.example.com`. CNAME targets are checked too, which catches trackers hidden behind a first-party subdomain. Blocked names get an `NXDOMAIN` response.

## Getting started

Requires CMake 3.20+ and a C17 compiler. Developed on macOS, and tested on macOS and Debian.

```sh
cmake -S . -B build
cmake --build build
sudo ./build/dns    # Port 53 requires root
```

Then, from another terminal:

```sh
dig @127.0.0.1 example.com
```

### Options

| Option         | Description                                               | Default     |
|----------------|-----------------------------------------------------------|-------------|
| `-v`           | Log every query                                           | Off         |
| `-p [port]`    | Port to listen on                                         | `53`        |
| `-b [address]` | IPv4 address to bind to. Use `0.0.0.0` for all interfaces | `127.0.0.1` |
| `-l [file]`    | Hosts-style file of local records (`address name...`)     | None        |
| `-h`           | Show usage and exit                                       |             |

Any file placed in `blocklists/` is loaded at startup, with one domain per line and `#` for comments.

## Performance

Measured on an Apple M4 Pro with the client and server on the same machine, over loopback, with query logging off:

| Measurement                               | Result                              |
|-------------------------------------------|-------------------------------------|
| Cached lookup (p50, one client)           | ~25 µs                              |
| Cached throughput (10 clients, 30 s runs) | ~100,000 queries/sec on one thread  |
| Uncached lookup                           | ~85–260 ms, depending on the domain |

These are best-case figures: nearly all queries are cache hits for 20 domains, with no network between client and server.

## Roadmap

### Caching
- [ ] Cache individual records rather than whole packets
- [ ] Prefetch popular domains shortly before their TTL expires
- [ ] Serve stale answers when upstream servers can't be reached (RFC 8767)

### Security
- [ ] Perform bailiwick checks, only accepting records within the zone the answering server is responsible for
- [ ] Only answer local clients, so the server can't be used as an open resolver
- [ ] Randomise the source port of each upstream query, adding up to 16 bits of entropy against Kaminsky-style cache poisoning
- [ ] Perform 0x20 case randomisation on upstream queries
- [ ] Implement DNSSEC validation

### Protocol
- [ ] Implement TCP fallback
- [ ] Implement IPv6 support
- [ ] Implement QNAME minimisation, sending each server only as much of the name as it needs (RFC 9156)

## Notes
- Now that duplicate queries are dropped (and logged), it has raised a significant issue: clients are retrying their requests because of how long the server takes to respond.
- The underlying issue here is that responses are cached all together. This means that only the exact question hits the cache - everything else starts again from root nameservers.
- By storing response records individually, the server wouldn't have to do as much work.
- From a cold start, resolving `www.google.com` starts from root and resolves down: `root` -> `com` -> `google.com` -> `www.google.com`. A request for `google.com` should then be instant since it was already resolved once before, but instead, resolving has to start again from `root`. In one test, this second resolve took 6 seconds.
- As a side effect, the server gets flooded with repeat retries from clients, assuming their initial request was lost. "No server could possibly take this long, something must be wrong".

## Credits

The included blocklist is [HaGeZi's Multi PRO](https://github.com/hagezi/dns-blocklists).