#!/usr/bin/env python3
"""Optional public DoH/DNSSEC check; RDNS_TEST_UPSTREAM_PROXY selects a proxy."""
import os
from pathlib import Path
import subprocess
import tempfile
import time
from smoke import BIN, api, port, udp, query, rcode

with tempfile.TemporaryDirectory(prefix='rdns-doh-live-') as tmp:
    folder = Path(tmp)
    admin, dns = port(), port()
    config = folder / 'config.toml'
    config.write_text(f'database="{folder}/db.sqlite3"\nadmin="127.0.0.1:{admin}"\ndns_udp="127.0.0.1:{dns}"\nallowed_clients=["127.0.0.0/8"]\n')
    subprocess.run([str(BIN), 'init-admin', str(config), 'admin'], input=b'x', check=True, stdout=subprocess.DEVNULL)
    log = (folder / 'server.log').open('w+')
    process = subprocess.Popen([str(BIN), str(config)], stdout=log, stderr=log)
    try:
        base = f'http://127.0.0.1:{admin}'
        for _ in range(100):
            try:
                token = api(base, '/login', {'username':'admin','password':'x'})['token']
                break
            except OSError:
                time.sleep(.05)
        else:
            raise AssertionError('test instance did not start')
        settings = api(base, '/features', token=token)['settings']
        settings['resolution'].update(mode='doh', group='public', validate_dnssec=True, timeout_ms=30000)
        settings['groups'] = [{'name':'public', 'servers':[
            {'url':'https://dns.google/dns-query', 'bootstrap_ips':['8.8.8.8']},
            {'url':'https://cloudflare-dns.com/dns-query', 'bootstrap_ips':['1.1.1.1']}],
            'proxy':os.environ.get('RDNS_TEST_UPSTREAM_PROXY',''), 'timeout_ms':15000}]
        api(base, '/features', settings, token, 'PUT')
        signed = udp(query('cloudflare.com'), dns, timeout=35)
        assert rcode(signed)==0 and signed[3]&32 and int.from_bytes(signed[6:8])>0, 'valid DNSSEC answer was not authenticated'
        bogus = udp(query('dnssec-failed.org'), dns, timeout=35)
        assert rcode(bogus)==2 and int.from_bytes(bogus[6:8])==0, 'invalid signatures did not fail closed'
        ech = udp(query('sina.dev',65), dns, timeout=35)
        assert rcode(ech)==0 and b'ech.sina.dev' in ech, 'published HTTPS/ECH config was lost'
        negative = udp(query('rdns-no-such-184436.cloudflare.com'), dns, timeout=35)
        assert rcode(negative) in [0,3] and int.from_bytes(negative[6:8])==0, 'negative DNSSEC answer failed'
        print('PASS: public DoH local DNSSEC validation, invalid-signature SERVFAIL, HTTPS/ECH and valid negative response')
    finally:
        process.terminate()
        process.wait(timeout=5)
