# rDns

Application code is licensed under the [MIT License](LICENSE). Bundled third-party data retains its original license; see [THIRD-PARTY.md](THIRD-PARTY.md).

Rust DNS resolver and administration console for a single organization. Public names use validating root recursion, DoH upstream pools, or both in parallel. UDP/TCP DNS, DoH, DoT and DoQ share access policies, local rules, filtering, GFWList routing and geographic query logging. The React + Tailwind CSS console is embedded in the binary.

## Build

Requirements: Rust toolchain, Node.js 20+, npm, and C build tools for `ring`/SQLite. The project uses the Cargo sparse mirror at `https://sina.dev/crates-index/`.

```sh
./build.sh
```

The script installs the locked web dependencies, builds `web/dist`, then builds `target/release/rdns` using `Cargo.lock`. `cargo build` alone requires an existing `web/dist` directory because the frontend is embedded at compile time.

For hands-on local use, run `./scripts/run-local.sh`. It builds the app, asks you to set the initial `admin` password, creates a local test certificate, and starts only the loopback management panel. Open `http://127.0.0.1:3000`, set DNS UDP to `127.0.0.1:1053` and enable it in **监听服务**, then query `dig @127.0.0.1 -p 1053 cloudflare.com A +dnssec`. Use Ctrl+C to stop; subsequent starts keep the local database and password. The local instance uses `data/local` for its files. To bind the management panel on every IPv4 interface, run `./scripts/run-local.sh --host 0.0.0.0` and open `http://<server-IP>:3000`. You can also pass a specific interface IP. This option exposes plain HTTP and is intended for trusted networks. DNS listener addresses and client access are configured separately in the console.
Run `./packaging/package.sh` after the release build to create an architecture-labelled tarball and `SHA256SUMS`. CI builds and packages on native Linux x86_64 and ARM64 runners.
Pushes to `main` and the nightly schedule update one rolling `nightly` pre-release with both architecture archives and a combined checksum file. Tags matching `v*` publish an independent formal release for that tag. Pull requests run checks without publishing.

## Configure and run

Create an `rdns` service user and `/var/lib/rdns` owned by that user. Copy `config.example.toml` to `/etc/rdns/config.toml` and set client CIDRs. A new instance starts only the loopback management panel; all DNS listeners are disabled. Use the panel to select addresses and enable protocols. DoH defaults to 443, DoT and DoQ to 853, and plain DNS to 53. Encrypted listeners require PEM paths configured in the certificate page. Keep the admin HTTP listener on loopback and publish it through an authenticated HTTPS reverse proxy if remote administrators need access.

Create the first administrator by passing a nonempty password on standard input:

```sh
sudo -u rdns rdns init-admin /etc/rdns/config.toml admin
rdns /etc/rdns/config.toml
```

On Linux, after placing the binary, configuration and readable PEM files, run `sudo /opt/rDns/rdns service install /opt/rDns/config.toml`. From a directory containing `config.toml`, `sudo /opt/rDns/rdns service install` uses that file automatically. The command creates the `rdns` system account if needed, checks its file and database directory access, installs `/etc/systemd/system/rdns.service`, runs `systemctl daemon-reload`, and enables and starts the service. Running `rdns` without arguments also loads `config.toml` from the current working directory.

Suggested production ports: UDP/TCP 53, DoH 443 (`/dns-query`), DoT TCP 853, DoQ UDP 853. `allowed_clients` seeds the initial whitelist. IPv4 and IPv6 CIDRs are supported. The SQLite database path must be writable by the service account; certificate files only need read access.

On first start, `allowed_clients` seeds the database. Subsequent access policy, upstream, GeoIP and GFWList settings are managed in the console, stored in SQLite and applied without restarting. Existing installations retain their whitelist and validating recursive mode. The legacy `PUT /api/v1/clients` still replaces the whitelist and selects whitelist mode.
Existing TOML listener addresses are enabled on first upgrade, preserving the current deployment; after a listener configuration is saved in the panel, the SQLite setting takes precedence on restart. The panel saves listener changes over authenticated HTTP and receives live status and errors over WebSocket. A new port is bound before settings are saved, so occupied ports leave the current listeners running. Disabling or moving a TCP or DoT listener also closes its existing client connections.

## Cache

Authoritative NS/Glue referrals and DNS answers are persisted as upstream responses in SQLite. Cached recursive responses and DoH responses in local-validation mode are replayed through Hickory's DNSSEC validation; the database is never treated as a validated answer by itself. DoH groups have separate cache namespaces, including endpoint and proxy configuration, and honor HTTP Age. A byte-weighted LRU cache keeps hot responses in memory with a default 64 MiB payload budget. The cache page shows its current weighted size, SQLite entry count/bytes, hits, and the process RSS (which includes Hickory and other runtime memory).

At startup, a background task preloads the 32 most frequent eligible hostname and record-type pairs in the latest 10,000 query log rows, plus A and AAAA records for four starter hostnames. In the TOML `[warmup]` section, set `domains` to your own exact hostnames, `history_limit` to adjust the history sample result count, or `enabled = false` to disable preloading. The task runs two lookups at a time through the configured resolver and leaves client analytics untouched. Cache lifetimes still follow DNS TTLs.

The defaults follow Unbound's TTL limits: positive answers and NS/Glue are capped at 86,400 seconds, negative responses at 3,600 seconds, with no artificial minimum. Every cache entry expires at the earliest of its authoritative TTL, configured limit, and any DNSSEC signature expiration. These limits and the memory budget are configurable in the panel and apply without restarting; changing them clears old cache entries.

## DNS behavior

1. An exact local name takes precedence. A, AAAA, CNAME and TXT records are supported. An exact local name without the requested type returns NOERROR with no answer.
2. A manual allow rule overrides block rules for the name and its subdomains. Manual blocks and subscription blocks return NXDOMAIN.
3. The longest matching conditional forward suffix uses the configured upstream UDP/TCP socket address. If several targets have the same suffix, the lowest remaining rule ID takes precedence. UDP and its TCP fallback share the configured resolution deadline and return SERVFAIL on timeout. Its response is not presented as DNSSEC validated.
4. GFWList matches use their designated DoH group, including its configured proxy. If that path is unavailable, the default DoH group is tried. Both failing returns SERVFAIL; this route never falls back to root recursion. A confirmed DNSSEC failure returns SERVFAIL directly.
5. Remaining names use the selected default mode: validating root recursion, DoH, or recursive-preferred parallel resolution. DNSSEC AD is set only after local validation; local records, conditional forwarding and DoH with local validation disabled clear it.

Public HTTPS/SVCB answers, including their `ech` parameter, pass through the recursive path. rDns does not terminate ECH on its own DoH TLS listener. The chosen rustls server stack does not currently provide server-side ECH support.
The binary bundles an InterNIC root hints snapshot (`resources/named.root`). Set `root_hints` in the configuration to use an updated file without rebuilding.
At startup, rDns uses IPv4 root addresses when an IPv4 route is available, and IPv6 addresses on IPv6-only hosts.

Duplicate allow/block rules and identical forwarding targets return HTTP 409. On upgrade, the database keeps the oldest ID for each duplicate and preserves distinct targets.

Remote filter lists accept one domain per line, `0.0.0.0 domain`, `127.0.0.1 domain`, and Adblock `||domain^` entries. Unsupported list rules are ignored. Updates are size limited to 10 MiB and applied only after successful retrieval and parsing. The background refresher runs hourly; manual refresh is available in the console.
For an internal HTTPS list, set `subscription_ca` to the PEM CA certificate that signed its server certificate. TLS verification remains enabled.

## User portal and personal DoH

Enable the HTTPS DoH listener, then open `/portal` on its public origin. New installations and upgrades start with open registration and the shared `/dns-query` endpoint enabled. In the management console, **用户门户** controls the registration policy (open, approval required, or closed), the public endpoint, providers and users. Closing registration allows existing members to keep signing in. Management accounts and portal accounts use separate sessions and permissions.

Each active member can copy a unique `/dns-<22 characters>` URL and rotate it. The suffix is case-sensitive and consists of uniformly random ASCII letters and digits. A personal URL is a bearer credential for DNS queries; configure reverse-proxy access logs to redact these paths and OAuth callback query strings. Protect the service database and its backups, which contain recoverable personal addresses and provider client secrets. A rotation immediately invalidates the old URL. Disabling a user also revokes their sessions. All DoH requests remain subject to the configured CIDR and region policies.

For email sign-in, open **用户门户 → 邮箱验证码登录**, enable the option and enter the SMTP host, port, TLS mode, sender address and allowed mailbox domains. Supply credentials if the relay requires authentication. Separate domains with commas or spaces and list each permitted subdomain explicitly. The portal checks the domain at both delivery and login. Codes expire after ten minutes, allow five attempts and can be used once. First-time email users follow the current registration policy.

For external sign-in, configure the public HTTPS origin and register its exact `/portal/callback/<provider-id>` URL shown in the console with the provider. OIDC uses issuer discovery and signed ID tokens. For generic OAuth 2.0, configure the authorization, token and user profile endpoints, scopes, client authentication method, and a stable user ID field (top-level key or JSON Pointer). Providers must support authorization code with S256 PKCE. The portal accepts credentials over HTTPS and loads platform trust roots for enterprise providers. Provider IDs and stable identity mappings identify accounts; email addresses are never used for automatic linking.

Members can inspect their own 24-hour, 7-day or 30-day query history within the configured retention period. Administrators can filter analytics by member and entry point. Pre-upgrade rows remain historical. Rotating a URL preserves its member's history.

## DoH upstream pools and parallel resolution

In **解析上游**, create named groups containing one or more HTTPS DoH endpoints. Requests rotate among endpoints; failures try other sources and mark the failed source for a 30-second cooldown. Active sources are preferred, while an all-failed group can still be retried. Connections are pooled. Each group has a total query budget; endpoint attempts share that budget so one stalled source cannot consume all retry time.

Groups can connect directly or use an explicit HTTP, HTTPS or SOCKS5 proxy. SOCKS5 names are resolved at the proxy (`socks5h` behavior). Environment proxy variables are ignored. Optional endpoint bootstrap IPs bypass system DNS for direct connections while preserving TLS hostname verification. Bootstrap overrides do not change proxy-side DNS. Do not point an upstream back to this rDns instance; provide bootstrap IPs when the system resolver itself depends on rDns.

The three default modes are:

- **仅本地递归**: the existing DNSSEC-validating recursive path.
- **仅 DoH 上游**: use the selected default pool.
- **递归优先，DoH 并行兜底**: start both paths, prefer a successful recursive response within the configured priority window (300 ms by default), then use a ready DoH response. If DoH is still pending, return whichever eligible path succeeds. The total request budget defaults to 15 seconds. A known bogus DNSSEC result is never bypassed.

DoH local DNSSEC validation defaults on and uses root trust anchors through Hickory, including DNSKEY/DS queries over the same upstream/proxy path. Disabling it explicitly trusts the configured upstream and always clears AD. Valid NXDOMAIN/NODATA replies are answers, not failover triggers. HTTPS/SVCB records and ECH parameters are preserved.

## Client and regional access

In **客户端**, choose **开放模式** (all source networks), **白名单模式** (only listed networks), or **黑名单模式** (all except listed networks). A whitelist requires at least one CIDR. The existing default remains whitelist mode.

The network condition and regional condition must both pass. Regional rules can allow only, or block, selected countries/regions and provinces. Use an ISO country code such as `CN` or the database country name; a blank province matches the entire country. Province names must match the **来源地区** IP lookup result. Private/reserved IPs and unavailable lookup results follow the explicit unknown-IP choice whenever regional restrictions are enabled. Rejected requests return DNS REFUSED and are logged with the rejection reason.

For DoH behind a reverse proxy, configure **可信代理网段** with only the proxy's addresses, for example `127.0.0.1/32` and `::1/128` for a local Caddy. `X-Forwarded-For` is accepted only from those peers, walked from right to left until the first untrusted hop, and used for both policy and logging. Other peers cannot override their socket source address. Raw DNS, DoT and DoQ use their socket peer.

## GeoIP and GFWList data

**来源地区** manages offline IPv4/IPv6 ip2region XDB v3 databases using the reader adapted from MirrorProxy. The default paths are `geoip/ip2region_v4.xdb` and `geoip/ip2region_v6.xdb` next to the SQLite database. Files must be readable and their parent writable by `rdns`; the default data location is compatible with the packaged systemd write restriction. Download each database from the page, or configure existing absolute paths. Downloads are limited to 80 MiB and validated before atomic replacement. Automatic database updates are optional (0 disables them). Missing files show as unavailable and return an unknown location.

Logs include country, province, city and the selected DoH group; the overview aggregates country/province query counts. Historical rows retain unknown locations rather than inventing a result. GeoIP describes the visible source IP, including a NAT/VPN exit when applicable.

**GFWList** bundles the official snapshot in `resources/gfwlist.txt` and is disabled until a route is configured. It accepts the upstream Base64 AutoProxy format or decoded AutoProxy text, supports domain suffixes, host wildcards, domain exceptions and compatible regular expressions. Positive URL rules apply to their whole hostname because DNS has no URL path. Path-only exceptions and unsupported expressions are counted as unapplied rules in the page; it is not a full PAC/URL matcher. GFWList is separate from blocking subscriptions: a match selects a resolver rather than blocking the domain.

Configure a CDN URL, update interval (default six hours), and designated group. The background scheduler checks due updates every minute. Source changes during a GeoIP or GFWList refresh discard the superseded download. Access-policy saves can complete while the download is in progress. List downloads use the designated group's proxy when one is configured. Only a successfully parsed nonempty update replaces active rules; failed updates and restarts retain the last valid downloaded list. With no downloaded list, the bundled snapshot is used. GFWList's designated group receives at most half the overall request budget when a distinct default group is available, reserving time for that default DoH fallback.

Configuration pages save through the HTTP API. Their WebSocket reconnects automatically and receives shared cache statistics every three seconds. Status notifications preserve unsaved configuration edits. API snapshots expose proxy configuration only to administrators; update audits do not include proxy credentials.

## Management API

All endpoints below are under `/api/v1`. Login returns a bearer token valid for 12 hours. The console stores it in session storage. Management HTTP defaults to loopback; expose it remotely only through HTTPS.

Query logs include `duration_ms`: server processing time from decoding the request through encoding its response, including lookup/cache/filter work, excluding TLS handshakes, network transit and writing the log to SQLite. Historical rows recorded before this field was added return `null` and display `—` in the console.

| Method | Path | Role | Purpose |
| --- | --- | --- | --- |
| POST | `/login` | Public | Exchange username/password for a token |
| POST | `/logout` | Viewer | Revoke current token |
| GET | `/me`, `/stats`, `/logs` | Viewer | Profile and recent activity |
| GET, PUT | `/clients` | Viewer, Admin | Inspect or replace allowed client CIDRs |
| GET, PUT | `/listeners` | Viewer, Admin | Inspect or atomically apply live DNS listener settings |
| GET, PUT | `/cache` | Viewer, Admin | View cache usage and update memory/TTL limits |
| GET, PUT | `/features` | Viewer, Admin | Inspect status or atomically apply access, GeoIP, upstream and GFWList settings; viewers receive a reduced view |
| POST | `/gfwlist/refresh` | Admin | Refresh the saved GFWList source, retaining the active list on failure |
| POST | `/geoip/refresh` | Admin | Download/validate/install `{"ip_version":4}` or `6` |
| POST | `/geoip/lookup` | Viewer | Look up `{"ip":"8.8.8.8"}` and evaluate saved access rules |
| GET | `/ws` | Authenticated | Status stream; admins can send `listeners.update`, `cache.update`, `features.update`, `gfwlist.refresh`, `geoip.refresh` with `request_id` and `settings`; first message is `{"type":"auth","token":"..."}` |
| GET, POST | `/rules` | Viewer, Editor | List and add rules |
| DELETE | `/rules/{id}` | Editor | Remove a rule |
| GET, POST | `/subscriptions` | Viewer, Editor | List and add filter sources |
| POST | `/subscriptions/{id}/refresh` | Editor | Download and atomically replace a source's domains |
| DELETE | `/subscriptions/{id}` | Editor | Remove a source |
| GET, POST | `/accounts` | Admin | List and add accounts |
| DELETE | `/accounts/{id}` | Admin | Delete an account |
| GET | `/audit` | Admin | Recent configuration events |
| GET, PUT | `/certificates` | Admin | View or replace absolute PEM certificate and private key paths; validated paths take effect immediately and persist in SQLite |
| POST | `/certificates/reload` | Admin | Re-read PEM files and switch new TLS connections |

To reload a certificate after an external certificate process has replaced both PEM files:

```sh
curl -X POST -H "Authorization: Bearer $RDNS_TOKEN" http://127.0.0.1:3000/api/v1/certificates/reload
```

The console's certificate page can save new absolute paths. Saving validates the PEM pair, persists the paths, and switches DoH, DoT and DoQ for new connections. The configured TOML paths serve as defaults until paths are saved in the console. The reload endpoint then reads the saved paths. Invalid PEM or mismatched keys produce a non-2xx response and leave the previous paths and certificate in service. Path changes and reload attempts are audited. Existing connections may continue on their established TLS session.

## Verification

Run `cargo test --locked` for unit tests and a local integration test covering all five transports, policy rules, roles, subscription updates, certificate rotation, failure rollback and restart persistence. Run `cargo test --test smoke live_root_dnssec_and_ech -- --ignored --nocapture` where direct DNS access to authoritative servers is available; it checks root recursion, a signed answer's AD bit, the deliberately bogus `dnssec-failed.org` response and an HTTPS record carrying `ech`. Run `cargo test --test smoke console_screenshot -- --ignored --nocapture` with Chromium installed for a browser walkthrough and screenshot at `/tmp/rdns-console-dashboard.png`.
The feature integration smoke includes local TLS DoH pools, round robin/cache and timeout failover, GFWList exceptions/default-group fallback, real HTTP CONNECT and SOCKS5 tunnels, generated IPv4/IPv6 XDB databases, trusted/untrusted forwarded IPs, region rules, roles and restart persistence. Run `npx --no-install playwright-core install chromium` from `web/` or set `RDNS_CHROME` to a local Chromium executable. Run `RDNS_FEATURE_UI=1 python3 tests/features_smoke.py` for HTTP saves, reconnect, session revocation and desktop/mobile checks. Screenshots are written to the system temporary directory.

With a debug binary built, run `RDNS_LATENCY_BASELINE=1 python3 tests/features_smoke.py` to measure client-side UDP P95/P99 over 500 sequential local-rule queries and 500 warm-cache queries. Query logs queue up to 1024 entries and apply backpressure when full. The writer commits up to 64 entries per statement. The stats API reports queue depth, failed entries and the duration of the last batch write in microseconds.
Run `cargo test --locked --test smoke live_doh_dnssec_and_ech -- --ignored --nocapture` for the public DoH/DNSSEC/ECH check. Set `RDNS_TEST_UPSTREAM_PROXY` explicitly if that test needs an HTTP/SOCKS5 proxy; the production application continues to use only its saved per-group proxy configuration.
After `cargo build --release --locked --bin rdns`, run `cargo test --test smoke release_binary_protocols -- --ignored --nocapture` to exercise the exact release binary.

The default root trust anchor is supplied by Hickory. Monitor Hickory security releases and root trust anchor updates before production rollouts.
