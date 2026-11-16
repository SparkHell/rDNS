# rDns

Licensed under the [MIT License](LICENSE).

Rust DNS resolver and administration console for a single organization. Public names are resolved iteratively from root hints with DNSSEC validation. UDP/TCP DNS, DoH, DoT and DoQ share local rules, filtering and query logging. The React + Tailwind CSS console is embedded in the binary.

## Build

Requirements: Rust toolchain, Node.js 20+, npm, and C build tools for `ring`/SQLite. The project uses the Cargo sparse mirror at `https://sina.dev/crates-index/`.

```sh
./build.sh
```

The script installs the locked web dependencies, builds `web/dist`, then builds `target/release/rdns` using `Cargo.lock`. `cargo build` alone requires an existing `web/dist` directory because the frontend is embedded at compile time.

For hands-on local use, run `./scripts/run-local.sh`. It builds the app, asks you to set the initial `admin` password, creates a local test certificate, and runs rDns in the foreground. Open `http://127.0.0.1:3000`, then query `dig @127.0.0.1 -p 1053 cloudflare.com A +dnssec`. Use Ctrl+C to stop; subsequent starts keep the local database and password. The local instance listens only on loopback and uses `data/local` for its files.
Run `./packaging/package.sh` after the release build to create an architecture-labelled tarball and `SHA256SUMS`. CI builds and packages on native Linux x86_64 and ARM64 runners.
Pushes to `main` and the nightly schedule update one rolling `nightly` pre-release with both architecture archives and a combined checksum file. Tags matching `v*` publish an independent formal release for that tag. Pull requests run checks without publishing.

## Configure and run

Create an `rdns` service user and `/var/lib/rdns` owned by that user. Copy `config.example.toml` to `/etc/rdns/config.toml`, set listening addresses and client CIDRs, and place a PEM certificate chain and matching private key at the configured paths. The sample binds all listeners to loopback and uses high ports; deployers may bind the DNS ports to a LAN address. Keep the admin HTTP listener on loopback and publish it through an authenticated HTTPS reverse proxy if remote administrators need access.

Create the first administrator by passing a password of at least 12 characters on standard input:

```sh
sudo -u rdns rdns init-admin /etc/rdns/config.toml admin
rdns /etc/rdns/config.toml
```

On Linux, after placing the binary, configuration and readable PEM files, run `sudo /opt/rDns/rdns service install /opt/rDns/config.toml`. From a directory containing `config.toml`, `sudo /opt/rDns/rdns service install` uses that file automatically. The command creates the `rdns` system account if needed, checks its file and database directory access, installs `/etc/systemd/system/rdns.service`, runs `systemctl daemon-reload`, and enables and starts the service. Running `rdns` without arguments also loads `config.toml` from the current working directory.

Suggested production ports: UDP/TCP 53, DoH 443 (`/dns-query`), DoT TCP 853, DoQ UDP 853. `allowed_clients` must name every authorized client subnet. IPv4 and IPv6 CIDRs are supported. The SQLite database path must be writable by the service account; certificate files only need read access.

On first start, `allowed_clients` seeds the database. Subsequent client allowlist changes are managed in the console or with `PUT /api/v1/clients` and survive restarts.

## DNS behavior

1. An exact local name takes precedence. A, AAAA, CNAME and TXT records are supported. An exact local name without the requested type returns NOERROR with no answer.
2. A manual allow rule overrides block rules for the name and its subdomains. Manual blocks and subscription blocks return NXDOMAIN.
3. The longest matching conditional forward suffix uses the configured upstream UDP/TCP socket address. Its response is not presented as DNSSEC validated.
4. Remaining names use the validating root recursor. Bogus or unavailable validation returns SERVFAIL. DNSSEC AD is set only by the validating recursor; local and forwarded answers clear it.

Public HTTPS/SVCB answers, including their `ech` parameter, pass through the recursive path. rDns does not terminate ECH on its own DoH TLS listener. The chosen rustls server stack does not currently provide server-side ECH support.
The binary bundles an InterNIC root hints snapshot (`resources/named.root`). Set `root_hints` in the configuration to use an updated file without rebuilding.
At startup, rDns uses IPv4 root addresses when an IPv4 route is available, and IPv6 addresses on IPv6-only hosts.

Remote filter lists accept one domain per line, `0.0.0.0 domain`, `127.0.0.1 domain`, and Adblock `||domain^` entries. Unsupported list rules are ignored. Updates are size limited to 10 MiB and applied only after successful retrieval and parsing. The background refresher runs hourly; manual refresh is available in the console.
For an internal HTTPS list, set `subscription_ca` to the PEM CA certificate that signed its server certificate. TLS verification remains enabled.

## Management API

All endpoints below are under `/api/v1`. Login returns a bearer token valid for 12 hours. The console stores it in session storage. Management HTTP binds to loopback; expose it remotely only through HTTPS.

| Method | Path | Role | Purpose |
| --- | --- | --- | --- |
| POST | `/login` | Public | Exchange username/password for a token |
| POST | `/logout` | Viewer | Revoke current token |
| GET | `/me`, `/stats`, `/logs` | Viewer | Profile and recent activity |
| GET, PUT | `/clients` | Viewer, Admin | Inspect or replace allowed client CIDRs |
| GET, POST | `/rules` | Viewer, Editor | List and add rules |
| DELETE | `/rules/{id}` | Editor | Remove a rule |
| GET, POST | `/subscriptions` | Viewer, Editor | List and add filter sources |
| POST | `/subscriptions/{id}/refresh` | Editor | Download and atomically replace a source's domains |
| DELETE | `/subscriptions/{id}` | Editor | Remove a source |
| GET, POST | `/accounts` | Admin | List and add accounts |
| DELETE | `/accounts/{id}` | Admin | Delete an account |
| GET | `/audit` | Admin | Recent configuration events |
| POST | `/certificates/reload` | Admin | Re-read PEM files and switch new TLS connections |

To reload a certificate after an external certificate process has replaced both PEM files:

```sh
curl -X POST -H "Authorization: Bearer $RDNS_TOKEN" http://127.0.0.1:3000/api/v1/certificates/reload
```

The reload endpoint checks all three protocol configurations before switching DoH, DoT and DoQ. Invalid PEM or mismatched keys produce a non-2xx response and leave the previous certificate in service. Every reload attempt is audited. Existing connections may continue on their established TLS session.

## Verification

Run `cargo test --locked` for unit tests and a local integration test covering all five transports, policy rules, roles, subscription updates, certificate rotation, failure rollback and restart persistence. Run `cargo test --test smoke live_root_dnssec_and_ech -- --ignored --nocapture` where direct DNS access to authoritative servers is available; it checks root recursion, a signed answer's AD bit, the deliberately bogus `dnssec-failed.org` response and an HTTPS record carrying `ech`. Run `cargo test --test smoke console_screenshot -- --ignored --nocapture` with Chromium installed for a browser walkthrough and screenshot at `/tmp/rdns-console-dashboard.png`.
After `cargo build --release --locked --bin rdns`, run `cargo test --test smoke release_binary_protocols -- --ignored --nocapture` to exercise the exact release binary.

The default root trust anchor is supplied by Hickory. Monitor Hickory security releases and root trust anchor updates before production rollouts.
