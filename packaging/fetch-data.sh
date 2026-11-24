#!/usr/bin/env bash
set -euo pipefail
destination=$1
mkdir -p "$destination/geoip" "$destination/licenses"
download() {
  curl --fail --silent --show-error --location --retry 3 --connect-timeout 15 \
    --max-time 300 "$1" --output "$destination/$2"
  test -s "$destination/$2"
}

ip2region=https://raw.githubusercontent.com/lionsoul2014/ip2region/master
registry=https://adguardteam.github.io/HostlistsRegistry/assets
download "$ip2region/data/ip2region_v4.xdb" geoip/ip2region_v4.xdb
download "$ip2region/data/ip2region_v6.xdb" geoip/ip2region_v6.xdb
download "$ip2region/LICENSE.md" licenses/ip2region.txt
download https://raw.githubusercontent.com/gfwlist/gfwlist/master/gfwlist.txt gfwlist.txt
download "$registry/filter_1.txt" adguard-dns.txt
download "$registry/filter_2.txt" adaway.txt
download https://raw.githubusercontent.com/AdguardTeam/HostlistsRegistry/main/LICENSE licenses/AdGuard-HostlistsRegistry.txt
download https://raw.githubusercontent.com/AdAway/adaway.github.io/master/LICENSE.md licenses/AdAway.md
python3 - "$destination" <<'PY'
import base64
import pathlib
import struct
import sys

root = pathlib.Path(sys.argv[1])
for version in (4, 6):
    path = root / 'geoip' / f'ip2region_v{version}.xdb'
    assert 524544 < path.stat().st_size <= 80 * 1024 * 1024, path
    with path.open('rb') as stream:
        header = stream.read(20)
    assert struct.unpack_from('<H', header, 0)[0] == 3, path
    assert struct.unpack_from('<HH', header, 16) == (version, 4), path
assert base64.b64decode(b''.join((root / 'gfwlist.txt').read_bytes().split()), validate=True).startswith(b'[AutoProxy')
for name in ('adguard-dns.txt', 'adaway.txt'):
    rules = (root / name).read_text(encoding='utf-8-sig')
    assert sum(line.startswith(('||', '0.0.0.0 ', '127.0.0.1 ')) for line in rules.splitlines()) > 1000, name
PY
