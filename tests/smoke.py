#!/usr/bin/env python3
"""Run a temporary local rDns instance through DNS and management requests."""

import hashlib
import base64
import http.server
import json
import os
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


def certificate(directory, name):
    cert, key = directory / f"{name}.crt", directory / f"{name}.key"
    subprocess.run(
        ["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-days", "1",
         "-subj", f"/CN={name}", "-addext", "subjectAltName=DNS:localhost",
         "-addext", "basicConstraints=critical,CA:FALSE", "-addext", "extendedKeyUsage=serverAuth",
         "-keyout", str(key), "-out", str(cert)],
        check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
    )
    return cert, key


def query(name, qtype=1):
    labels = b"".join(bytes([len(label)]) + label.encode() for label in name.split("."))
    return struct.pack("!HHHHHH", 0x1234, 0x0100, 1, 0, 0, 0) + labels + b"\0" + struct.pack("!HH", qtype, 1)


def rcode(packet):
    assert packet[:2] == b"\x12\x34", "DNS ID mismatch"
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
        answer = request[:2] + struct.pack("!HHHHH", 0x81A0, 1, 1, 0, 0) + request[12:]
        answer += b"\xc0\x0c" + struct.pack("!HHIH", 1, 1, 60, 4) + socket.inet_aton("198.51.100.7")
        sock.sendto(answer, peer)
    finally:
        sock.close()


class FilterHandler(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        body = self.server.filter_body
        self.send_response(200)
        self.send_header("Content-Type", "text/plain")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

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
            f'database = "{directory / "rdns.sqlite3"}"\n'
            f'dns_udp = "127.0.0.1:{dns_port}"\n'
            f'dns_tcp = "127.0.0.1:{dns_port}"\n'
            f'doh = "127.0.0.1:{doh_port}"\n'
            f'dot = "127.0.0.1:{dot_port}"\n'
            f'doq = "127.0.0.1:{doq_port}"\n'
            f'admin = "127.0.0.1:{admin_port}"\n'
            'allowed_clients = ["127.0.0.0/8"]\n'
            f'certificate = "{live_cert}"\nprivate_key = "{live_key}"\nsubscription_ca = "{cert1}"\n',
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

                sub = api(base, "/subscriptions", {"url": f"https://localhost:{list_port}/block.txt"}, token)["id"]
                assert api(base, f"/subscriptions/{sub}/refresh", token=token, method="POST")["count"] == 1
                assert rcode(udp(query("ads.subscription.invalid"), dns_port)) == 3
                assert api(base, "/logs", token=token)[0]["outcome"] == "blocked"
                filter_http.filter_body = b""
                expect_http_error(502, lambda: api(base, f"/subscriptions/{sub}/refresh", token=token, method="POST"))
                assert rcode(udp(query("ads.subscription.invalid"), dns_port)) == 3
                assert api(base, "/subscriptions", token=token)[0]["last_error"]

                if os.environ.get("RDNS_LIVE_DNS") == "1":
                    public = udp(query("cloudflare.com"), dns_port, timeout=20)
                    print(f"cloudflare.com: rcode={rcode(public)} AD={bool(public[3] & 0x20)} answers={int.from_bytes(public[6:8], 'big')}")
                    assert rcode(public) == 0, f"public root recursion returned RCODE {rcode(public)}\n{log.read_text()[-3000:]}"
                    bogus = udp(query("dnssec-failed.org"), dns_port, timeout=20)
                    print(f"dnssec-failed.org: rcode={rcode(bogus)} AD={bool(bogus[3] & 0x20)} answers={int.from_bytes(bogus[6:8], 'big')}")
                    assert rcode(bogus) == 2, f"bogus DNSSEC domain returned RCODE {rcode(bogus)}\n{log.read_text()[-3000:]}"
                    ech = subprocess.run(
                        ["dig", "+tcp", "+short", "+time=20", "+tries=1", "-p", str(dns_port), "@127.0.0.1", "cloudflare-ech.com", "HTTPS"],
                        capture_output=True, text=True, timeout=25, check=True,
                    )
                    assert "ech=" in ech.stdout.lower(), f"ECH HTTPS record absent: {ech.stdout.strip()}\n{log.read_text()[-3000:]}"
                    print("PASS: root recursion, DNSSEC failure and public ECH HTTPS record")

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
                events = api(base, "/audit", token=token)
                assert sum(item["action"] == "certificate.reload" for item in events) >= 2
                server.terminate()
                server.wait(timeout=5)
                shutil.copyfile(cert2, live_cert)
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
                print("PASS: UDP, TCP, DoH GET/POST, DoT, DoQ, rules, subscription, roles, certificate reload and restart persistence")
            finally:
                filter_http.shutdown()
                filter_http.server_close()
                server.terminate()
                try:
                    server.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    server.kill()
                    server.wait()


if __name__ == "__main__":
    run()
