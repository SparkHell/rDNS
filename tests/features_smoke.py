#!/usr/bin/env python3
"""Exercise access/GeoIP, DoH pools, GFWList fallback and actual proxy tunnels."""
import base64
from collections import Counter
from contextlib import closing
import concurrent.futures
import http.server
import json
import os
from pathlib import Path
import select
import socket
import socketserver
import sqlite3
import ssl
import struct
import subprocess
import tempfile
import threading
import time
import urllib.request

from smoke import BIN, api, certificate, expect_http_error, port, query, rcode, udp, read_exact


def xdb(version):
    head = bytearray(256 + 256 * 256 * 8)
    struct.pack_into('<HHI', head, 0, 3, 1, int(time.time()))
    struct.pack_into('<HH', head, 16, version, 4)
    if version == 4:
        first, last = socket.inet_aton('8.8.0.0')[::-1], socket.inet_aton('8.8.255.255')[::-1]
        prefix = 8 * 256 + 8
    else:
        first = socket.inet_pton(socket.AF_INET6, '2001:4860::')
        last = socket.inet_pton(socket.AF_INET6, '2001:4860:ffff:ffff:ffff:ffff:ffff:ffff')
        prefix = 0x2001
    text = '中国|广东省|深圳市|电信|CN'.encode()
    start = len(head)
    record = first + last + struct.pack('<HI', len(text), start + len(first) * 2 + 6)
    struct.pack_into('<II', head, 8, start, start)
    struct.pack_into('<II', head, 256 + prefix * 8, start, start)
    return bytes(head) + record + text


class Handler(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        self.server.counts['GET'+self.path] += 1
        if self.path == getattr(self.server, 'paused_path', None):
            self.server.download_started.set()
            assert self.server.resume_download.wait(8)
        data = self.server.resources.get(self.path, b'<html>invalid</html>')
        self.send_response(200)
        self.send_header('Content-Length', str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def do_POST(self):
        packet = self.rfile.read(int(self.headers['Content-Length']))
        self.server.counts[self.path] += 1
        assert self.headers['Content-Type'] == 'application/dns-message'
        if self.path in ['/fail', '/bad']:
            self.send_error(503)
            return
        if self.path == '/slow':
            time.sleep(0.5)
        question = packet[12:]
        p = 12
        while packet[p]:
            p += packet[p] + 1
        qtype = struct.unpack_from('!H', packet, p + 1)[0]
        # Keep only the question: EDNS follows it on validating requests.
        question = packet[12:p+5]
        self.server.questions[question] += 1
        if qtype == 28:
            value = socket.inet_pton(socket.AF_INET6, '2001:db8::1')
        elif qtype == 65:
            value = b'\0\1\0' + struct.pack('!HH', 5, 5) + b'\0\3ech'
        elif qtype == 2:
            value = b'\x02ns\x04test\0'
        else:
            value = socket.inet_aton('198.51.100.21' if self.path == '/one' else '198.51.100.22')
        answer = packet[:2] + struct.pack('!5H', 0x81a0, 1, 1, 0, 0) + question
        answer += b'\xc0\x0c' + struct.pack('!HHIH', qtype, 1, 60, len(value)) + value
        self.send_response(200)
        self.send_header('Content-Type', 'application/dns-message')
        self.send_header('Content-Length', str(len(answer)))
        self.end_headers()
        try:
            self.wfile.write(answer)
        except (ConnectionError, ssl.SSLError):
            pass

    def log_message(self, *_):
        pass


def relay(a, b):
    with b:
        while True:
            ready, _, _ = select.select([a, b], [], [], 4)
            if not ready:
                return
            for source in ready:
                data = source.recv(65536)
                if not data:
                    return
                (b if source is a else a).sendall(data)


class Proxy(socketserver.BaseRequestHandler):
    def handle(self):
        stream = self.request
        stream.settimeout(5)
        if self.server.kind == 'http':
            header = b''
            while not header.endswith(b'\r\n\r\n'):
                header += read_exact(stream, 1)
            assert header.startswith(b'CONNECT localhost:')
            self.server.requests.append(header.split(b'\r\n')[0].decode())
            stream.sendall(b'HTTP/1.1 200 Connection established\r\n\r\n')
        else:
            assert read_exact(stream, 1) == b'\x05'
            methods = read_exact(stream, 1)[0]
            read_exact(stream, methods)
            stream.sendall(b'\x05\x00')
            assert read_exact(stream, 4) == b'\x05\x01\x00\x03', 'SOCKS must resolve the domain at the proxy'
            host = read_exact(stream, read_exact(stream, 1)[0]).decode()
            assert host == 'localhost'
            read_exact(stream, 2)
            self.server.requests.append(host)
            stream.sendall(b'\x05\x00\x00\x01\x7f\x00\x00\x01\x00\x00')
        remote = socket.create_connection(('127.0.0.1', self.server.upstream_port), timeout=5)
        relay(stream, remote)


class ProxyServer(socketserver.ThreadingTCPServer):
    allow_reuse_address = True
    daemon_threads = True


def run():
    with tempfile.TemporaryDirectory(prefix='rdns-features-') as tmp:
        directory = Path(tmp)
        cert, key = certificate(directory, 'localhost')
        dns_port, admin_port, doh_port = port(), port(), port()
        server = http.server.ThreadingHTTPServer(('127.0.0.1', 0), Handler)
        server.counts = Counter()
        server.questions = Counter()
        server.resources = {'/list': base64.b64encode(b'[AutoProxy 0.2.9]\n||blocked.target.test\n@@||safe.blocked.target.test\n'), '/v4': xdb(4), '/v6': xdb(6)}
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.load_cert_chain(cert, key)
        server.socket = context.wrap_socket(server.socket, server_side=True)
        threading.Thread(target=server.serve_forever, daemon=True).start()
        base_upstream = f'https://localhost:{server.server_port}'
        proxies = []
        for kind in ['http', 'socks5']:
            proxy = ProxyServer(('127.0.0.1', 0), Proxy)
            proxy.kind, proxy.requests, proxy.upstream_port = kind, [], server.server_port
            threading.Thread(target=proxy.serve_forever, daemon=True).start()
            proxies.append(proxy)
        # Keep recursion offline so a public NXDOMAIN cannot win the parallel lookup.
        (directory / 'named.root').write_text(
            'A.ROOT-SERVERS.NET. 3600 A 127.0.0.201\n'
            'B.ROOT-SERVERS.NET. 3600 A 127.0.0.202\n'
        )
        config = directory / 'config.toml'
        config.write_text(
            f'database="db.sqlite3"\nadmin="127.0.0.1:{admin_port}"\n'
            f'dns_udp="127.0.0.1:{dns_port}"\ndoh="127.0.0.1:{doh_port}"\n'
            f'certificate="{cert.name}"\nprivate_key="{key.name}"\nsubscription_ca="{cert.name}"\n'
            'allowed_clients=["127.0.0.0/8"]\nroot_hints="named.root"\n'
        )
        with config.open('a') as f:
            f.write('[warmup]\nenabled=false\nhistory_limit=1\ndomains=["startup.test"]\n')
        # Seed the previous rules schema, including nullable duplicate keys.
        with closing(sqlite3.connect(directory / 'db.sqlite3')) as db, db:
            db.execute('CREATE TABLE rules (id INTEGER PRIMARY KEY, kind TEXT NOT NULL, domain TEXT NOT NULL, record_type TEXT, value TEXT, ttl INTEGER, UNIQUE(kind,domain,record_type,value))')
            for kind, value in [('allow', None), ('block', None), ('forward', '127.0.0.1:53')]:
                db.executemany('INSERT INTO rules(kind,domain,value) VALUES(?,?,?)', [(kind, 'legacy.test', value)] * 2)
            db.execute("INSERT INTO rules(kind,domain,value) VALUES('forward','legacy.test','127.0.0.2:53')")
        subprocess.run([str(BIN), 'init-admin', str(config), 'admin'], input=b'x', check=True, stdout=subprocess.DEVNULL)
        output = (directory / 'server.log').open('w+')
        process = subprocess.Popen([str(BIN), str(config)], stdout=output, stderr=output)
        base = f'http://127.0.0.1:{admin_port}'
        try:
            for _ in range(100):
                try:
                    token = api(base, '/login', {'username': 'admin', 'password': 'x'})['token']
                    break
                except (OSError, KeyError):
                    time.sleep(.05)
            else:
                raise AssertionError('service did not start')
            migrated = api(base, '/rules', token=token)
            assert sorted(r['id'] for r in migrated) == [1, 3, 5, 7], migrated
            for rule in migrated:
                expect_http_error(409, lambda: api(base, '/rules', rule, token))
            def status(): return api(base, '/features', token=token)
            settings = status()['settings']
            original = json.loads(json.dumps(settings))
            def save(): return api(base, '/features', settings, token, 'PUT')
            def doh(packet, method='POST', forwarded='8.8.8.8'):
                headers = {'Content-Type': 'application/dns-message', 'X-Forwarded-For':forwarded}
                url = f'https://localhost:{doh_port}/dns-query'
                if method == 'GET': url += '?dns=' + base64.urlsafe_b64encode(packet).decode().rstrip('=')
                request = urllib.request.Request(url, data=packet if method=='POST' else None, headers=headers, method=method)
                with urllib.request.urlopen(request, context=ssl.create_default_context(cafile=str(cert)), timeout=5) as response:
                    return response.read()
            def group(name, paths, proxy=''):
                return {'name': name, 'servers': [{'url': base_upstream+p, 'bootstrap_ips': ['127.0.0.1']} for p in paths], 'proxy': proxy, 'timeout_ms': 1000}
            settings['access']['mode'] = 'open'
            settings['groups'] = [group('default', ['/one', '/two']), group('special', ['/fail'])]
            settings['resolution'].update(mode='doh', group='default', validate_dnssec=False)
            settings['gfwlist'].update(url=base_upstream+'/list', group='special')
            settings['geo'].update(ipv4_url=base_upstream+'/v4', ipv6_url=base_upstream+'/v6')
            save()
            for i in range(4):
                answer = udp(query(f'rr{i}.test'), dns_port)
                assert rcode(answer) == 0 and not (answer[3] & 0x20), 'unvalidated upstream AD must be cleared'
            assert server.counts['/one'] == 2 and server.counts['/two'] == 2, server.counts
            groups_before = sorted(status()['groups'], key=lambda g: g['name'])
            settings['access']['cidrs'] = ['127.0.0.1/32']
            save()
            assert sorted(status()['groups'], key=lambda g: g['name']) == groups_before
            root = query('.', 2)
            for answer in [udp(root, dns_port), doh(root)]:
                assert rcode(answer) == 0 and answer[12:17] == root[12:] and b'\x02ns\x04test\0' in answer
            before = sum(server.counts.values())
            assert rcode(udp(query('rr0.test'), dns_port)) == 0
            assert sum(server.counts.values()) == before, 'DoH answer cache missed'
            if os.environ.get('RDNS_LATENCY_BASELINE') == '1':
                api(base, '/rules', {'kind':'local', 'domain':'local.test', 'record_type':'A', 'value':'192.0.2.1'}, token)
                for name in ['local.test', 'rr0.test']:
                    packet = query(name)
                    samples = []
                    for _ in range(500):
                        start = time.perf_counter_ns()
                        assert rcode(udp(packet, dns_port)) == 0
                        samples.append((time.perf_counter_ns() - start) / 1e6)
                    samples.sort()
                    print(f'{name} UDP milliseconds (500 sequential): P95={samples[474]:.3f} P99={samples[494]:.3f}')
                return
            https = udp(query('ech.test', 65), dns_port)
            assert rcode(https) == 0 and b'ech' in https, 'HTTPS/ECH record lost'

            # An obsolete download cannot publish after its source changes, and
            # a paused network read must not block unrelated settings writes.
            for path, field, key, endpoint, payload in [
                ('/list', 'gfwlist', 'url', '/gfwlist/refresh', {}),
                ('/v4', 'geo', 'ipv4_url', '/geoip/refresh', {'ip_version': 4}),
            ]:
                server.paused_path = path
                server.download_started, server.resume_download = threading.Event(), threading.Event()
                before = status()
                with concurrent.futures.ThreadPoolExecutor() as executor:
                    old = executor.submit(expect_http_error, 502, lambda: api(base, endpoint, payload, token))
                    try:
                        assert server.download_started.wait(3)
                        settings[field][key] = base_upstream + '/invalid'
                        save()
                        settings[field][key] = base_upstream + path
                        save()
                    finally:
                        server.resume_download.set()
                    old.result()
                server.paused_path = None
                after = status()
                assert after['geo_meta'] == before['geo_meta'] and after['gfwlist'] == before['gfwlist']
                assert after['geo']['ipv4']['available'] == before['geo']['ipv4']['available']
            server.paused_path = '/list'
            server.download_started, server.resume_download = threading.Event(), threading.Event()
            with concurrent.futures.ThreadPoolExecutor() as executor:
                refresh = executor.submit(api, base, '/gfwlist/refresh', {}, token)
                try:
                    assert server.download_started.wait(3)
                    settings['access']['cidrs'] = ['127.0.0.0/8']
                    save()
                finally:
                    server.resume_download.set()
                assert refresh.result()['gfwlist']['count'] == 2
            server.paused_path = None
            settings['gfwlist']['enabled'] = True
            save()
            assert rcode(udp(query('blocked.target.test'), dns_port)) == 0
            logs = api(base, '/logs', token=token)
            assert logs[0]['outcome'] == 'gfw_fallback_doh' and logs[0]['upstream'] == 'default', logs[0]
            assert server.counts['/fail'] == 1
            special = next(g for g in status()['groups'] if g['name'] == 'special')
            assert special['servers'][0]['failures'] > 0 and special['servers'][0]['cooldown_until'] > 0
            save()
            assert next(g for g in status()['groups'] if g['name'] == 'special') == special
            udp(query('safe.blocked.target.test'), dns_port)
            assert server.counts['/fail'] == 1, 'GFWList exception ignored'
            settings['groups'][1] = group('special', ['/one'])
            save()
            udp(query('sub.blocked.target.test'), dns_port)
            assert api(base, '/logs', token=token)[0]['outcome'] == 'gfw_doh'
            settings['groups'][1] = group('special', ['/slow'])
            settings['resolution']['timeout_ms'] = 300
            save()
            assert rcode(udp(query('timeout.blocked.target.test'), dns_port)) == 0, 'special group consumed default fallback budget'
            assert api(base, '/logs', token=token)[0]['outcome'] == 'gfw_fallback_doh'
            settings['groups'][1] = group('special', ['/one'])
            settings['resolution']['timeout_ms'] = 15000
            old_count = status()['gfwlist']['count']
            settings['gfwlist']['url'] = base_upstream+'/invalid'
            save()
            expect_http_error(502, lambda: api(base, '/gfwlist/refresh', {}, token))
            assert status()['gfwlist']['count'] == old_count, 'bad update replaced active GFWList'

            settings['gfwlist']['enabled'] = False
            for proxy in proxies:
                settings['groups'][0] = group('default', ['/two'], f'{proxy.kind}://127.0.0.1:{proxy.server_address[1]}')
                save()
                assert rcode(udp(query(f'{proxy.kind}.test'), dns_port)) == 0
                assert proxy.requests, f'{proxy.kind} proxy was bypassed'
            settings['groups'][0] = group('default', ['/fail', '/two'])
            save()
            assert rcode(udp(query('failover.test'), dns_port)) == 0
            settings['groups'][0] = group('default', ['/slow', '/two'])
            settings['groups'][0]['timeout_ms'] = 300
            save()
            assert rcode(udp(query('timeoutfailover.test'), dns_port)) == 0, 'timed-out source prevented failover'
            settings['groups'][0] = group('default', ['/fail'])
            settings['gfwlist']['enabled'] = True
            settings['groups'][1] = group('special', ['/fail'])
            save()
            assert rcode(udp(query('noresult.blocked.target.test'), dns_port)) == 2, 'failed GFW routes must not recurse'
            settings['gfwlist']['enabled'] = False
            settings['groups'][0] = group('default', ['/two'])
            save()
            settings['resolution']['mode'] = 'parallel'
            settings['resolution']['priority_ms'] = 25
            save()
            answer = udp(query('parallel.test'), dns_port)
            assert rcode(answer) == 0 and socket.inet_aton('198.51.100.22') in answer, 'parallel lookup missed the /two DoH answer'
            settings['resolution']['mode'] = 'doh'
            save()

            for version in [4, 6]: api(base, '/geoip/refresh', {'ip_version': version}, token)
            assert status()['geo']['ipv4']['available'] and status()['geo']['ipv6']['available']
            # The loaded reader must survive an unrelated settings save even
            # if the backing file is temporarily unavailable.
            ipv4_path = Path(settings['geo']['ipv4_path'])
            offline_path = ipv4_path.with_suffix('.offline')
            ipv4_path.rename(offline_path)
            try:
                settings['access']['cidrs'] = ['127.0.0.1/32']
                save()
                assert api(base, '/geoip/lookup', {'ip':'8.8.8.8'}, token)['location']['country_code'] == 'CN'
            finally:
                offline_path.rename(ipv4_path)
            for ip in ['8.8.8.8', '2001:4860:4860::8888']:
                result = api(base, '/geoip/lookup', {'ip': ip}, token)
                assert result['location']['country_code'] == 'CN' and result['location']['province'] == '广东省', result
            settings['geo']['ipv4_url'] = base_upstream+'/invalid'
            save()
            expect_http_error(502, lambda: api(base, '/geoip/refresh', {'ip_version': 4}, token))
            assert status()['geo']['ipv4']['available'], 'invalid XDB replaced active reader'

            settings['access']['mode'] = 'blacklist'
            settings['access']['cidrs'] = ['127.0.0.0/8']
            save()
            assert rcode(udp(query('denied.test'), dns_port)) == 5
            assert api(base, '/logs', token=token)[0]['outcome'] == 'client_blacklist'
            settings['access'].update(mode='whitelist', cidrs=['10.0.0.0/8'])
            save()
            assert rcode(udp(query('denied2.test'), dns_port)) == 5
            settings['access'].update(mode='open', region_mode='allow', regions=[{'country':'CN','province':'广东省'}], allow_unknown=False)
            save()
            assert rcode(udp(query('unknown.test'), dns_port)) == 5
            assert rcode(doh(query('spoofed.test'))) == 5, 'untrusted forwarding header bypassed access rules'
            settings['access']['trusted_proxies'] = ['127.0.0.1/32']
            save()
            for method in ['GET','POST']:
                assert rcode(doh(query(f'geo{method}.test'), method)) == 0, 'trusted proxy source IP was ignored'
                log = api(base, '/logs', token=token)[0]
                assert log['client']=='8.8.8.8' and log['province']=='广东省', log
            settings['access']['regions'] = [{'country':'CN','province':'浙江省'}]
            save()
            assert rcode(doh(query('wrongprovince.test'))) == 5
            settings['access'].update(region_mode='block', regions=[{'country':'CN','province':''}])
            save()
            assert rcode(doh(query('countryblocked.test'))) == 5
            settings['access'].update(region_mode='allow', regions=[{'country':'CN','province':'广东省'}])
            settings['access']['allow_unknown'] = True
            save()
            assert rcode(udp(query('unknownallowed.test'), dns_port)) == 0
            assert process.poll() is None, 'settings change restarted the service'
            assert any(region['province']=='广东省' for region in api(base, '/stats', token=token)['regions'])

            # REST role enforcement and persistence across process restart.
            api(base, '/accounts', {'username':'viewer','password':'x','role':'viewer'}, token)
            viewer = api(base, '/login', {'username':'viewer','password':'x'})['token']
            expect_http_error(403, lambda: api(base, '/features', settings, viewer, 'PUT'))
            assert 'groups' not in api(base, '/features', token=viewer)['settings']
            hot = query('recent-hot.test', 65)
            seed = query('startup.test')
            for _ in range(12):
                assert rcode(udp(hot, dns_port)) == 0
            assert not server.questions[seed[12:]]
            process.terminate(); process.wait(timeout=5)
            config.write_text(config.read_text().replace('enabled=false', 'enabled=true'))
            with closing(sqlite3.connect(directory/'db.sqlite3')) as db, db:
                db.execute('DELETE FROM cache_entries')
                # Limit history to a controlled sample even during optional latency runs.
                db.execute("DELETE FROM query_log WHERE domain != 'recent-hot.test'")
            process = subprocess.Popen([str(BIN), str(config)], stdout=output, stderr=output)
            for _ in range(100):
                try:
                    if status()['settings']['access']['allow_unknown']: break
                except OSError: pass
                time.sleep(.05)
            else: raise AssertionError('settings were not persisted')
            for _ in range(100):
                if ('DNS startup warmup finished' in (directory/'server.log').read_text()
                        and server.questions[hot[12:]] == 2 and server.questions[seed[12:]] == 1):
                    break
                time.sleep(.05)
            else: raise AssertionError('startup lookups did not reach the DoH upstream')
            for packet in [hot, seed]:
                before = server.questions[packet[12:]]
                assert rcode(udp(packet, dns_port)) == 0
                assert server.questions[packet[12:]] == before, 'first client query missed warmed cache'
            assert status()['gfwlist']['count'] == old_count
            assert api(base, '/geoip/lookup', {'ip':'8.8.8.8'}, token)['location']['country_code'] == 'CN'
            # The scheduler must refresh a due source on startup without a manual request.
            settings['gfwlist'].update(enabled=True, url=base_upstream+'/list')
            save()
            server.resources['/list'] = base64.b64encode(b'[AutoProxy 0.2.9]\n||scheduled.target.test\n')
            previous_updates = server.counts['GET/list']
            with closing(sqlite3.connect(directory/'db.sqlite3')) as connection, connection:
                connection.execute("UPDATE runtime_settings SET value=? WHERE key='gfwlist_meta'", (json.dumps({'attempted_at':0}),))
            process.terminate(); process.wait(timeout=5)
            process = subprocess.Popen([str(BIN), str(config)], stdout=output, stderr=output)
            for _ in range(100):
                try:
                    if status()['gfwlist']['count']==1 and server.counts['GET/list'] > previous_updates: break
                except OSError: pass
                time.sleep(.05)
            else: raise AssertionError('scheduled GFWList update did not run')
            assert rcode(udp(query('scheduled.target.test'), dns_port))==0
            assert api(base, '/logs', token=token)[0]['outcome']=='gfw_fallback_doh', 'scheduled list match did not use the configured default DoH fallback'
            if os.environ.get('RDNS_FEATURE_UI') == '1':
                cache_before = api(base, '/cache', token=token)['settings']
                subprocess.run(['node', str(Path(__file__).with_name('feature-ui-smoke.mjs'))], check=True,
                    env={**os.environ, 'RDNS_UI_BASE':base, 'RDNS_UI_UPSTREAM':base_upstream})
                assert api(base, '/cache', token=token)['settings'] == cache_before
            print('PASS: DoH round robin/cache/ECH, GFWList exceptions/fallback/retained updates, HTTP+SOCKS5 tunnels, IPv4+IPv6 XDB, access modes/regions, roles and restart persistence')
        except Exception:
            output.flush(); output.seek(0)
            print(output.read()[-6000:])
            raise
        finally:
            process.terminate(); process.wait(timeout=5)
            output.close()
            server.shutdown()
            for proxy in proxies: proxy.shutdown()


if __name__ == '__main__':
    run()
