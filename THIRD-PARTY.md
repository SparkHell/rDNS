# Third-party data and algorithms

## GFWList

`resources/gfwlist.txt` is an unmodified Base64-encoded snapshot from
https://github.com/gfwlist/gfwlist (`master/gfwlist.txt`), retrieved 2026-11-17.
Its decoded header identifies the last modification as 2026-11-13.
The list is licensed under LGPL-2.1; its license is preserved verbatim in
`resources/gfwlist-LICENSE.txt`. The application code's MIT license does not
replace the data's license. The default update URL and source may be changed
in the administration console.

The original source, readable decoded data (`list.txt`) and update history are
available at https://github.com/gfwlist/gfwlist. Decode the bundled snapshot
with `base64 --decode resources/gfwlist.txt`.

## ip2region XDB reader

`src/geoip.rs` adapts the offline XDB v3 reader from the adjacent MirrorProxy
repository, whose algorithm is adapted from the official ip2region Rust
binding: https://github.com/lionsoul2014/ip2region, Apache-2.0 OR MIT.
The reader retains that provenance in its source header. Release archives include the upstream IPv4 and IPv6 XDB files from the
`data/` directory and the upstream license. The databases are separate files
and retain their upstream terms.

## AdGuard DNS Filter and AdAway

Release archives include the two published lists from the
[AdGuard Host Lists Registry](https://github.com/AdguardTeam/HostlistsRegistry)
and the Registry and AdAway license notices. The raw lists retain their
embedded source and license notices. rDns reads supported DNS rules from the
files at startup when SQLite has no previously downloaded AdGuard rules.
