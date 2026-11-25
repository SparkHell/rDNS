#!/usr/bin/env python3
"""Run a temporary local rDns instance through DNS and management requests."""

from concurrent.futures import ThreadPoolExecutor
import hashlib
import base64
import http.server
import json
import os
import sqlite3
from pathlib import Path
import shutil
import socket
import ssl
import struct
import subprocess
import tempfile
import threading
import time
import urllib.error
import urllib.request


ROOT = Path(__file__).resolve().parents[1]
BIN = Path(os.environ.get("RDNS_BIN", ROOT / "target/debug/rdns"))
PASSWORD = "temporary-smoke-password-123"


def port():
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


def certificate(directory, name, dns_names="DNS:localhost"):
    cert, key = directory / f"{name}.crt", directory / f"{name}.key"
    subprocess.run(
        ["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-days", "1",
         "-subj", f"/CN={name}", "-addext", f"subjectAltName={dns_names}",
         "-addext", "basicConstraints=critical,CA:FALSE", "-addext", "extendedKeyUsage=serverAuth",
         "-keyout", str(key), "-out", str(cert)],
        check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
    )
    return cert, key


def query(name, qtype=1):
    labels = b"".join(bytes([len(label)]) + label.encode() for label in ([] if name == "." else name.rstrip(".").split(".")))
    return struct.pack("!HHHHHH", 0x1234, 0x0100, 1, 0, 0, 0) + labels + b"\0" + struct.pack("!HH", qtype, 1)


def rcode(packet):
    assert packet[:2] == b"\x12\x34", "DNS ID mismatch"
    assert packet[4:6] == b"\0\1", "response must contain the original question"
    return packet[3] & 0x0F


def api(base, path, payload=None, token=None, method=None):
    headers = {"Content-Type": "application/json"}
    if token:
        headers["Authorization"] = f"Bearer {token}"
    request = urllib.request.Request(
        base + "/api/v1" + path,
        data=json.dumps(payload).encode() if payload is not None else None,
        headers=headers,
        method=method,
    )
    with urllib.request.urlopen(request, timeout=5) as response:
        return json.loads(response.read())


def udp(packet, port_number, timeout=5):
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
        sock.settimeout(timeout)
        sock.sendto(packet, ("127.0.0.1", port_number))
        return sock.recvfrom(65535)[0]


def tcp(packet, port_number, tls=False):
    with socket.create_connection(("127.0.0.1", port_number), timeout=5) as raw:
        if tls:
            context = ssl._create_unverified_context()
            with context.wrap_socket(raw, server_hostname="localhost") as stream:
                stream.sendall(struct.pack("!H", len(packet)) + packet)
                size = struct.unpack("!H", stream.recv(2))[0]
                return read_exact(stream, size)
        raw.sendall(struct.pack("!H", len(packet)) + packet)
        size = struct.unpack("!H", raw.recv(2))[0]
        return read_exact(raw, size)


def read_exact(stream, size):
    chunks = []
    while size:
        part = stream.recv(size)
        assert part, "socket closed early"
        chunks.append(part)
        size -= len(part)
    return b"".join(chunks)


def peer_fingerprint(port_number):
    context = ssl._create_unverified_context()
    with socket.create_connection(("127.0.0.1", port_number), timeout=5) as raw:
        with context.wrap_socket(raw, server_hostname="localhost") as stream:
            return hashlib.sha256(stream.getpeercert(binary_form=True)).hexdigest()


def expect_http_error(expected, call):
    try:
        call()
    except urllib.error.HTTPError as error:
        assert error.code == expected, f"expected HTTP {expected}, got {error.code}"
    else:
        raise AssertionError(f"expected HTTP {expected}")


def fake_forwarder(sock):
    sock.settimeout(8)
    try:
        request, peer = sock.recvfrom(4096)
        time.sleep(0.05)
        answer = request[:2] + struct.pack("!HHHHH", 0x81A0, 1, 1, 0, 0) + request[12:]
        answer += b"\xc0\x0c" + struct.pack("!HHIH", 1, 1, 60, 4) + socket.inet_aton("198.51.100.7")
        sock.sendto(answer, peer)
    finally:
        sock.close()


def check_tcp_fallback(base, token, dns_port):
    settings = api(base, "/features", token=token)["settings"]
    with socket.socket() as listener, socket.socket(type=socket.SOCK_DGRAM) as upstream:
        listener.bind(("127.0.0.1", 0))
        listener.listen()
        listener.settimeout(5)
        upstream.bind(listener.getsockname())
        upstream.settimeout(5)
        api(base, "/rules", {"kind":"forward", "domain":"fallback.example", "value":f"127.0.0.1:{listener.getsockname()[1]}"}, token)
        def serve(stall):
            wire, peer = upstream.recvfrom(4096)
            upstream.sendto(wire[:2] + struct.pack("!H", 0x8300) + wire[4:], peer)
            with listener.accept()[0] as stream:
                stream.settimeout(5)
                assert read_exact(stream, int.from_bytes(read_exact(stream, 2), "big")) == wire
                answer = wire[:2] + struct.pack("!5H", 0x8180, 1, 1, 0, 0) + wire[12:]
                answer += b'\xc0\x0c' + struct.pack("!HHIH", 1, 1, 60, 4) + socket.inet_aton("192.0.2.33")
                stream.sendall(len(answer).to_bytes(2, "big") + (answer[:1] if stall else answer))
                if stall:
                    assert stream.recv(1) == b""
        with ThreadPoolExecutor() as executor:
            api(base, "/features", {**settings, "resolution":{**settings["resolution"], "priority_ms":0, "timeout_ms":500}}, token, "PUT")
            try:
                for stall in [False, True]:
                    served = executor.submit(serve, stall)
                    answer = udp(query("fallback.example"), dns_port, timeout=3)
                    assert rcode(answer) == (2 if stall else 0)
                    if not stall: assert socket.inet_aton("192.0.2.33") in answer
                    served.result()
            finally:
                api(base, "/features", settings, token, "PUT")


def check_connection_stop(base, token, packet, port_number, kind):
    settings = api(base, "/listeners", token=token)["settings"]
    with socket.create_connection(("127.0.0.1", port_number), timeout=3) as raw:
        stream = ssl._create_unverified_context().wrap_socket(raw, server_hostname="localhost") if kind == "dot" else raw
        with stream:
            stream.sendall(len(packet).to_bytes(2, "big") + packet)
            assert rcode(read_exact(stream, int.from_bytes(read_exact(stream, 2), "big"))) == 0
            api(base, "/listeners", {**settings, kind:{**settings[kind], "enabled":False}}, token, "PUT")
            try:
                assert stream.recv(1) == b""
            except (ConnectionResetError, ConnectionAbortedError, ssl.SSLEOFError):
                pass
    api(base, "/listeners", settings, token, "PUT")


class FilterHandler(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        if getattr(self.server, "started", None) is not None:
            self.server.started.set()
            assert self.server.resume.wait(8)
        body = self.server.filter_body
        self.send_response(200)
        self.send_header("Content-Type", "text/plain")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_POST(self):
        packet = self.rfile.read(int(self.headers["Content-Length"]))
        question = query("dnssec-failed.org")[12:]
        assert self.path == "/dns-query" and packet[12:].startswith(question)
        answer = packet[:2] + struct.pack("!5H", 0x81a0, 1, 1, 0, 0) + question
        answer += struct.pack("!HHHIH", 0xc00c, 1, 1, 60, 4) + socket.inet_aton("192.0.2.90")
        self.send_response(200)
        self.send_header("Content-Type", "application/dns-message")
        self.send_header("Content-Length", str(len(answer)))
        self.end_headers()
        self.wfile.write(answer)

    def log_message(self, *_args):
        pass


def run():
    assert BIN.exists(), "run cargo build first"
    with tempfile.TemporaryDirectory(prefix="rdns-smoke-") as tmp:
        directory = Path(tmp)
        cert1, key1 = certificate(directory, "first")
        cert2, key2 = certificate(directory, "second")
        live_cert, live_key = directory / "live.crt", directory / "live.key"
        shutil.copyfile(cert1, live_cert)
        shutil.copyfile(key1, live_key)
        dns_port, doh_port, dot_port, doq_port, admin_port, list_port = [port() for _ in range(6)]
        filter_http = http.server.ThreadingHTTPServer(("127.0.0.1", list_port), FilterHandler)
        filter_http.filter_body = b"0.0.0.0 ads.subscription.invalid\n"
        filter_context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        filter_context.load_cert_chain(cert1, key1)
        filter_http.socket = filter_context.wrap_socket(filter_http.socket, server_side=True)
        filter_thread = threading.Thread(target=filter_http.serve_forever, daemon=True)
        filter_thread.start()
        config = directory / "config.toml"
        config.write_text(
            'database = "rdns.sqlite3"\n'
            f'dns_udp = "127.0.0.1:{dns_port}"\n'
            f'dns_tcp = "127.0.0.1:{dns_port}"\n'
            f'doh = "127.0.0.1:{doh_port}"\n'
            f'dot = "127.0.0.1:{dot_port}"\n'
            f'doq = "127.0.0.1:{doq_port}"\n'
            f'admin = "127.0.0.1:{admin_port}"\n'
            'allowed_clients = ["127.0.0.0/8"]\n'
            f'certificate = "{live_cert.name}"\nprivate_key = "{live_key.name}"\nsubscription_ca = "{cert1.name}"\n',
            encoding="utf-8",
        )
        subprocess.run([str(BIN), "init-admin", str(config), "admin"], input=PASSWORD.encode(), check=True, stdout=subprocess.DEVNULL)
        log = directory / "server.log"
        with log.open("wb") as output:
            server = subprocess.Popen([str(BIN), str(config)], stdout=output, stderr=subprocess.STDOUT, env={**os.environ, "RUST_LOG": "rdns=debug,warn"})
            try:
                base = f"http://127.0.0.1:{admin_port}"
                for _ in range(100):
                    if server.poll() is not None:
                        raise AssertionError(f"server exited early:\n{log.read_text()[-2000:]}")
                    try:
                        token = api(base, "/login", {"username": "admin", "password": PASSWORD})["token"]
                        break
                    except (urllib.error.URLError, ConnectionError):
                        time.sleep(0.1)
                else:
                    raise AssertionError(f"server did not start:\n{log.read_text()[-2000:]}")

                api(base, "/rules", {"kind": "local", "domain": "internal.example", "record_type": "A", "value": "192.0.2.10", "ttl": 300}, token)
                api(base, "/rules", {"kind": "block", "domain": "ads.example"}, token)
                if screenshot := os.environ.get("RDNS_SCREENSHOT"):
                    subprocess.run(["node", str(ROOT / "tests/ui.mjs"), base, token, screenshot], check=True, timeout=30)
                packet = query("internal.example")
                expected_ip = socket.inet_aton("192.0.2.10")
                for transport, answer in [
                    ("UDP", udp(packet, dns_port)),
                    ("TCP", tcp(packet, dns_port)),
                    ("DoT", tcp(packet, dot_port, tls=True)),
                ]:
                    assert rcode(answer) == 0 and expected_ip in answer, f"{transport} local answer failed"

                check_connection_stop(base, token, packet, dns_port, "dns_tcp")
                check_connection_stop(base, token, packet, dot_port, "dot")
                check_tcp_fallback(base, token, dns_port)
                context = ssl._create_unverified_context()
                request = urllib.request.Request(
                    f"https://127.0.0.1:{doh_port}/dns-query", data=packet,
                    headers={"Content-Type": "application/dns-message"}, method="POST",
                )
                with urllib.request.urlopen(request, context=context, timeout=5) as response:
                    answer = response.read()
                assert rcode(answer) == 0 and expected_ip in answer, "DoH local answer failed"
                encoded = base64.urlsafe_b64encode(packet).rstrip(b"=").decode()
                with urllib.request.urlopen(f"https://127.0.0.1:{doh_port}/dns-query?dns={encoded}", context=context, timeout=5) as response:
                    assert expected_ip in response.read(), "DoH GET local answer failed"
                subprocess.run([os.environ["RDNS_DOQ_PROBE"], f"127.0.0.1:{doq_port}", str(live_cert)], check=True)
                assert rcode(udp(query("ads.example"), dns_port)) == 3, "blacklist did not return NXDOMAIN"

                with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as forward_socket:
                    forward_socket.bind(("127.0.0.1", 0))
                    upstream_port = forward_socket.getsockname()[1]
                    thread = threading.Thread(target=fake_forwarder, args=(forward_socket,), daemon=True)
                    thread.start()
                    api(base, "/rules", {"kind": "forward", "domain": "corp.example", "value": f"127.0.0.1:{upstream_port}"}, token)
                    forwarded = udp(query("host.corp.example"), dns_port)
                    assert rcode(forwarded) == 0 and socket.inet_aton("198.51.100.7") in forwarded
                    assert forwarded[3] & 0x20 == 0, "forwarded answer retained untrusted AD bit"
                    forward_log = api(base, "/logs", token=token)[0]
                    assert forward_log["outcome"] == "forward" and forward_log["duration_ms"] >= 50, "query duration omitted upstream wait"
                    thread.join(timeout=2)

                assert api(base, "/clients", token=token) == ["127.0.0.0/8"]
                api(base, "/clients", {"cidrs": ["192.0.2.0/24"]}, token, method="PUT")
                assert rcode(udp(packet, dns_port)) == 5, "disallowed client was accepted"
                api(base, "/clients", {"cidrs": ["127.0.0.0/8"]}, token, method="PUT")
                assert rcode(udp(packet, dns_port)) == 0, "restored client allowlist did not apply"

                api(base, "/accounts", {"username": "viewer", "password": PASSWORD, "role": "viewer"}, token)
                viewer = api(base, "/login", {"username": "viewer", "password": PASSWORD})["token"]
                assert api(base, "/stats", token=viewer)["total"] > 0
                expect_http_error(403, lambda: api(base, "/certificates/reload", token=viewer, method="POST"))
                expect_http_error(403, lambda: api(base, "/clients", {"cidrs": ["127.0.0.0/8"]}, viewer, method="PUT"))
                expect_http_error(403, lambda: api(base, "/cache", api(base, "/cache", token=token)["settings"], viewer, method="PUT"))
                expect_http_error(403, lambda: api(base, "/listeners", api(base, "/listeners", token=token)["settings"], viewer, method="PUT"))

                sub = api(base, "/subscriptions", {"url": f"https://localhost:{list_port}/block.txt"}, token)["id"]
                filter_http.started, filter_http.resume = threading.Event(), threading.Event()
                with ThreadPoolExecutor() as executor:
                    refresh = executor.submit(api, base, f"/subscriptions/{sub}/refresh", None, token, "POST")
                    try:
                        assert filter_http.started.wait(4)
                        api(base, "/rules", {"kind":"block","domain":"concurrent.example"}, token)
                    finally:
                        filter_http.resume.set()
                    assert refresh.result()["count"] == 1
                assert any(r["domain"] == "concurrent.example" for r in api(base, "/rules", token=token))
                assert rcode(udp(query("concurrent.example"), dns_port)) == 3
                assert rcode(udp(query("ads.subscription.invalid"), dns_port)) == 3
                assert api(base, "/logs", token=token)[0]["outcome"] == "blocked"
                assert api(base, "/logs", token=token)[0]["duration_ms"] >= 0
                filter_http.filter_body = b""
                expect_http_error(502, lambda: api(base, f"/subscriptions/{sub}/refresh", token=token, method="POST"))
                assert rcode(udp(query("ads.subscription.invalid"), dns_port)) == 3
                assert api(base, "/subscriptions", token=token)[0]["last_error"]

                if os.environ.get("RDNS_LIVE_DNS") == "1":
                    public = udp(query("cloudflare.com"), dns_port, timeout=20)
                    print(f"cloudflare.com: rcode={rcode(public)} AD={bool(public[3] & 0x20)} answers={int.from_bytes(public[6:8], 'big')}")
                    assert rcode(public) == 0, f"public root recursion returned RCODE {rcode(public)}\n{log.read_text()[-3000:]}"
                    unsigned_response = subprocess.run(
                        ["dig", "+tcp", "+time=20", "+tries=1", "+noall", "+answer", "-p", str(dns_port), "@127.0.0.1", "cloudflare.com", "A"],
                        capture_output=True, text=True, timeout=25, check=True,
                    )
                    assert "RRSIG" not in unsigned_response.stdout, "RRSIG leaked without DNSSEC DO bit"
                    question = bytearray(query("dnssec-failed.org"))
                    question[11] = 1
                    question.extend(struct.pack("!BHHIH", 0, 41, 1232, 0, 0))
                    bogus = udp(question, dns_port, timeout=20)
                    print(f"dnssec-failed.org: rcode={rcode(bogus)} AD={bool(bogus[3] & 0x20)} answers={int.from_bytes(bogus[6:8], 'big')}")
                    assert rcode(bogus) == 0 and int.from_bytes(bogus[6:8], "big"), log.read_text()[-3000:]
                    assert not bogus[3] & 0x20, "unverified answer must clear AD"
                    assert bogus.endswith((b"\x00\x0f\x00\x02\x00\x05", b"\x00\x0f\x00\x02\x00\x06")), "missing DNSSEC EDE"
                    assert any(row["domain"] == "dnssec-failed.org" and row["outcome"] == "recursive_dnssec_unverified"
                               for row in api(base, "/logs", token=token)), "missing unverified result in DNS logs"
                    ech = subprocess.run(
                        ["dig", "+tcp", "+short", "+time=20", "+tries=1", "-p", str(dns_port), "@127.0.0.1", "cloudflare-ech.com", "HTTPS"],
                        capture_output=True, text=True, timeout=25, check=True,
                    )
                    assert "ech=" in ech.stdout.lower(), f"ECH HTTPS record absent: {ech.stdout.strip()}\n{log.read_text()[-3000:]}"
                    with sqlite3.connect(directory / "rdns.sqlite3") as database:
                        cached = dict(database.execute("SELECT kind,COUNT(*) FROM cache_entries GROUP BY kind"))
                    assert cached.get("delegation", 0) > 0 and cached.get("answer", 0) > 0, f"missing persisted NS/answer records: {cached}"
                    stats = api(base, "/cache", token=token)
                    assert stats["disk_entries"] >= cached.get("delegation", 0) + cached.get("answer", 0)
                    assert stats["process_rss_bytes"] > 0
                    print(f"SQLite persisted cache: {cached}")
                    print("PASS: root recursion, DNSSEC failure and public ECH HTTPS record")

                    original_features = api(base, "/features", token=token)["settings"]
                    features = json.loads(json.dumps(original_features))
                    features["resolution"].update(mode="parallel", group="fixture", priority_ms=5000,
                                                  validate_dnssec=True)
                    features["groups"].append({
                        "name": "fixture",
                        "servers": [{"url": f"https://localhost:{list_port}/dns-query",
                                     "bootstrap_ips": ["127.0.0.1"]}],
                    })
                    try:
                        api(base, "/features", features, token, "PUT")
                        answer = udp(query("dnssec-failed.org"), dns_port)
                        assert rcode(answer) == 0 and answer.endswith(socket.inet_aton("192.0.2.90"))
                        assert not answer[3] & 0x20, "DoH fallback must clear upstream AD"
                        latest = api(base, "/logs", token=token)[0]
                        assert (latest["outcome"], latest["upstream"]) == ("doh", "fixture"), latest
                    finally:
                        api(base, "/features", original_features, token, "PUT")
                    print("PASS: parallel mode returns the DoH answer after recursive DNSSEC failure")

                first = peer_fingerprint(dot_port)
                first_doh = peer_fingerprint(doh_port)
                shutil.copyfile(cert2, live_cert)
                shutil.copyfile(key2, live_key)
                assert api(base, "/certificates/reload", token=token, method="POST")["ok"]
                second = peer_fingerprint(dot_port)
                assert first != second, "DoT still serves the old certificate"
                assert first_doh != peer_fingerprint(doh_port), "DoH still serves the old certificate"
                subprocess.run([os.environ["RDNS_DOQ_PROBE"], f"127.0.0.1:{doq_port}", str(live_cert)], check=True)
                shutil.copyfile(key1, live_key)
                expect_http_error(400, lambda: api(base, "/certificates/reload", token=token, method="POST"))
                assert peer_fingerprint(dot_port) == second, "mismatched key changed certificate"
                shutil.copyfile(key2, live_key)
                live_cert.write_bytes(b"invalid certificate")
                expect_http_error(400, lambda: api(base, "/certificates/reload", token=token, method="POST"))
                assert peer_fingerprint(dot_port) == second, "failed reload changed certificate"
                assert first_doh != peer_fingerprint(doh_port), "failed reload changed DoH certificate"
                subprocess.run([os.environ["RDNS_DOQ_PROBE"], f"127.0.0.1:{doq_port}", str(cert2)], check=True)
                assert api(base, "/certificates", token=token) == {"certificate": str(live_cert), "private_key": str(live_key)}
                expect_http_error(403, lambda: api(base, "/certificates", token=viewer))
                expect_http_error(403, lambda: api(base, "/certificates", {"certificate": str(cert1), "private_key": str(key1)}, viewer, method="PUT"))
                expect_http_error(400, lambda: api(base, "/certificates", {"certificate": str(cert1), "private_key": str(key2)}, token, method="PUT"))
                assert peer_fingerprint(dot_port) == second, "invalid path update changed active certificate"
                paths = api(base, "/certificates", {"certificate": str(cert1), "private_key": str(key1)}, token, method="PUT")
                assert paths == {"certificate": str(cert1), "private_key": str(key1)}
                assert peer_fingerprint(dot_port) == first, "saving paths did not switch DoT certificate"
                assert peer_fingerprint(doh_port) == first_doh, "saving paths did not switch DoH certificate"
                subprocess.run([os.environ["RDNS_DOQ_PROBE"], f"127.0.0.1:{doq_port}", str(cert1)], check=True)
                events = api(base, "/audit", token=token)
                assert sum(item["action"] == "certificate.reload" for item in events) >= 2
                server.terminate()
                server.wait(timeout=5)
                server = subprocess.Popen([str(BIN), str(config)], stdout=output, stderr=subprocess.STDOUT)
                for _ in range(100):
                    try:
                        assert api(base, "/login", {"username": "viewer", "password": PASSWORD})["token"]
                        break
                    except (urllib.error.URLError, ConnectionError):
                        time.sleep(0.1)
                else:
                    raise AssertionError(f"server did not restart:\n{log.read_text()[-2000:]}")
                assert socket.inet_aton("192.0.2.10") in udp(packet, dns_port), "local rule not restored"
                assert rcode(udp(query("ads.subscription.invalid"), dns_port)) == 3, "subscription state not restored"
                assert peer_fingerprint(dot_port) == first, "certificate paths were not restored after restart"
                assert api(base, "/certificates", token=token) == paths
                if os.environ.get("RDNS_LIVE_DNS") == "1":
                    assert api(base, "/cache", token=token)["disk_entries"] > 0, "SQLite cache lost after restart"
                print("PASS: UDP, TCP, DoH GET/POST, DoT, DoQ, rules, subscription, roles, certificate paths, reload and restart persistence")
            finally:
                filter_http.shutdown()
                filter_http.server_close()
                server.terminate()
                try:
                    server.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    server.kill()
                    server.wait()


def listener_run():
    with tempfile.TemporaryDirectory(prefix="rdns-listener-") as tmp:
        directory = Path(tmp)
        dns_port, admin_port, occupied_port = [port() for _ in range(3)]
        config = directory / "config.toml"
        config.write_text(
            'database = "rdns.sqlite3"\n'
            f'admin = "127.0.0.1:{admin_port}"\n'
            'allowed_clients = ["127.0.0.0/8"]\n', encoding="utf-8",
        )
        subprocess.run([str(BIN), "init-admin", str(config), "admin"], input=PASSWORD.encode(), check=True, stdout=subprocess.DEVNULL)
        log = directory / "server.log"
        with log.open("wb") as output:
            server = subprocess.Popen([str(BIN), str(config)], stdout=output, stderr=subprocess.STDOUT)
            try:
                base = f"http://127.0.0.1:{admin_port}"
                for _ in range(100):
                    if server.poll() is not None: raise AssertionError(log.read_text())
                    try:
                        token = api(base, "/login", {"username":"admin","password":PASSWORD})["token"]
                        break
                    except urllib.error.URLError:
                        time.sleep(0.1)
                else: raise AssertionError("admin listener did not start")
                initial = api(base, "/listeners", token=token)
                assert not any(setting["enabled"] for setting in initial["settings"].values())
                assert not any(initial["running"].values())
                assert initial["settings"]["dns_udp"]["address"] == "0.0.0.0:53"
                cache = api(base, "/cache", token=token)
                assert cache["settings"]["memory_mib"] == 64
                jobs = cache["automation"]["settings"]
                assert jobs == dict(ns=False,radar=False,global_top_1000=False,regions=[],local_hot_enabled=False,warm_domain_limit=1000,local_window_hours=24,local_min_queries=3)
                enabled = api(base, "/cache/automation", dict(jobs,ns=True), token, method="PUT")["automation"]
                assert enabled["root"]["count"] > 1000
                assert api(base, "/cache/automation", jobs, token, method="PUT")["automation"]["root"] is None
                cache_settings = {**cache["settings"], "memory_mib":8, "ns_max_ttl":3600}
                assert api(base, "/cache", cache_settings, token, method="PUT")["settings"] == cache_settings
                expect_http_error(409, lambda: api(base, "/listeners", {
                    **initial["settings"], "dot":{"enabled":True,"address":f"127.0.0.1:{dns_port}"}
                }, token, method="PUT"))
                api(base, "/rules", {"kind":"local","domain":"internal.example","record_type":"A","value":"192.0.2.10"}, token)
                desired = {**initial["settings"], "dns_udp":{"enabled":True,"address":f"127.0.0.1:{dns_port}"}}
                result = api(base, "/listeners", desired, token, method="PUT")
                assert result["running"]["dns_udp"]
                assert socket.inet_aton("192.0.2.10") in udp(query("internal.example"), dns_port)
                with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as occupied:
                    occupied.bind(("127.0.0.1", occupied_port))
                    expect_http_error(409, lambda: api(base, "/listeners", {
                        **desired, "dns_udp":{"enabled":True,"address":f"127.0.0.1:{occupied_port}"}
                    }, token, method="PUT"))
                assert socket.inet_aton("192.0.2.10") in udp(query("internal.example"), dns_port)
                disabled = api(base, "/listeners", {**desired, "dns_udp":{"enabled":False,"address":f"127.0.0.1:{dns_port}"}}, token, method="PUT")
                assert not disabled["running"]["dns_udp"]
                server.terminate(); server.wait(timeout=5)
                server = subprocess.Popen([str(BIN), str(config)], stdout=output, stderr=subprocess.STDOUT)
                for _ in range(100):
                    try:
                        snapshot = api(base, "/listeners", token=token)
                        break
                    except urllib.error.URLError:
                        time.sleep(0.1)
                else: raise AssertionError("service did not restart")
                assert not snapshot["settings"]["dns_udp"]["enabled"]
                assert api(base, "/cache", token=token)["settings"] == cache_settings
                print("PASS: default listeners off, certificate prerequisite, live enable/disable, port conflict, cache settings and persistence")
            finally:
                server.terminate()
                try: server.wait(timeout=5)
                except subprocess.TimeoutExpired: server.kill(); server.wait()


if __name__ == "__main__":
    listener_run() if os.environ.get("RDNS_LISTENER_TEST") == "1" else run()
