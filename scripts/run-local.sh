#!/usr/bin/env bash
set -euo pipefail

usage() {
  echo "Usage: $0 [--host IP]"
  echo "  --host IP   Management HTTP bind address (default 127.0.0.1)"
}
bind_host=127.0.0.1
allow_remote=false
case "${1:-}" in
  -h|--help) usage; exit 0 ;;
  --host)
    if [[ $# != 2 || ! $2 =~ ^[0-9a-fA-F:.]+$ ]]; then usage >&2; exit 2; fi
    bind_host=$2
    allow_remote=true
    ;;
  '') ;;
  *) usage >&2; exit 2 ;;
esac
authority=$bind_host
if [[ $bind_host == *:* ]]; then authority="[$bind_host]"; fi

cd "$(dirname "$0")/.."
runtime_dir="${RDNS_LOCAL_DIR:-$PWD/data/local}"
mkdir -p "$runtime_dir"
chmod 700 "$runtime_dir"

if [[ ! -s "$runtime_dir/server.crt" || ! -s "$runtime_dir/server.key" ]]; then
  openssl req -x509 -newkey rsa:2048 -nodes -days 30 \
    -subj '/CN=localhost' -addext 'subjectAltName=DNS:localhost,IP:127.0.0.1' \
    -addext 'basicConstraints=critical,CA:FALSE' \
    -keyout "$runtime_dir/server.key" -out "$runtime_dir/server.crt" >/dev/null 2>&1
  chmod 600 "$runtime_dir/server.key"
fi

cat > "$runtime_dir/config.toml" <<EOF
database = "$runtime_dir/rdns.sqlite3"
admin = "$authority:3000"
allow_remote_admin = $allow_remote
allowed_clients = ["127.0.0.0/8", "::1/128"]
certificate = "$runtime_dir/server.crt"
private_key = "$runtime_dir/server.key"
query_log_days = 7
EOF
chmod 600 "$runtime_dir/config.toml"

if [[ ! -d web/node_modules ]]; then
  npm --prefix web ci --no-audit --no-fund
fi
npm --prefix web run build
cargo build --locked --bin rdns

if [[ ! -f "$runtime_dir/admin.initialized" ]]; then
  read -r -s -p 'Set local admin password: ' local_admin_password
  printf '\n'
  printf '%s\n' "$local_admin_password" | target/debug/rdns init-admin "$runtime_dir/config.toml" admin
  unset local_admin_password
  touch "$runtime_dir/admin.initialized"
  chmod 600 "$runtime_dir/admin.initialized"
fi

printf 'Management HTTP listening on %s:3000 (user: admin)\n' "$authority"
case "$bind_host" in
  0.0.0.0|::) printf 'Console: open http://<server-IP>:3000/admin in your browser.\n' ;;
  *) printf 'Portal: http://%s:3000/ · Console: http://%s:3000/admin\n' "$authority" "$authority" ;;
esac
printf 'DNS listeners start disabled. In 监听服务, set DNS UDP to 127.0.0.1:1053 and enable it.\n'
printf 'Then query: dig @127.0.0.1 -p 1053 cloudflare.com A +dnssec\n'
printf 'Local test certificate: %s\n' "$runtime_dir/server.crt"
printf 'Press Ctrl+C to stop.\n'
exec target/debug/rdns "$runtime_dir/config.toml"
