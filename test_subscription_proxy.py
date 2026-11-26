import base64
import http.client
import json
import threading
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from tempfile import TemporaryDirectory

from subscription_proxy import SubscriptionServer, rewrite_profile


HOSTNAME = "vpn.example.com"
PREFIX = "Full tunnel |"
PROFILE = {
    "remarks": f"{PREFIX} Example",
    "outbounds": [{"tag": "proxy", "protocol": "vless", "settings": {
        "address": HOSTNAME, "port": 443, "id": "test-user-uuid",
    }}],
    "routing": {"rules": [{"type": "field", "outboundTag": "direct"}]},
    "dns": {"servers": ["https://dns.google/dns-query", {
        "address": "https+local://8.8.8.8/dns-query", "domains": ["domain:example.com"],
    }]},
}
OTHER = {"remarks": "Автовыбор", "outbounds": [], "routing": {"rules": []}}


class Origin(BaseHTTPRequestHandler):
    def log_message(self, format, *args):
        pass

    def respond(self):
        if self.headers.get("X-Hwid") != "test-device":
            self.send_error(403)
            return
        if self.path == "/clash/test":
            kind, body = "text/yaml", b"proxies: []"
        else:
            kind = "text/plain" if self.path.startswith("/json_sub/") else "application/json"
            body = json.dumps([PROFILE, OTHER]).encode()
        self.send_response(200)
        self.send_header("Content-Type", kind)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Subscription-Userinfo", "upload=12; download=34; total=56")
        self.send_header("Profile-Update-Interval", "1")
        self.send_header("X-Received-Path", self.path)
        routing = self.headers.get("X-Test-Routing")
        if routing:
            self.send_header("Routing", routing)
        self.end_headers()
        if self.command == "GET":
            self.wfile.write(body)

    do_GET = do_HEAD = respond


class SubscriptionProxyTest(unittest.TestCase):
    def start(self, server):
        worker = threading.Thread(target=server.serve_forever, daemon=True)
        worker.start()
        self.addCleanup(server.server_close)
        self.addCleanup(worker.join)
        self.addCleanup(server.shutdown)
        return server

    def test_rewrite_and_pass_through(self):
        origin = self.start(ThreadingHTTPServer(("127.0.0.1", 0), Origin))
        proxy = self.start(SubscriptionServer(("127.0.0.1", 0), origin.server_port, HOSTNAME, PREFIX))

        def request(path, method="GET", headers=None):
            conn = http.client.HTTPConnection("127.0.0.1", proxy.server_port, timeout=3)
            try:
                conn.request(method, path, headers=headers or {})
                response = conn.getresponse()
                return response.status, response.headers, response.read()
            finally:
                conn.close()

        headers = {"X-Hwid": "test-device"}
        path = "/subscription/client?example=one"
        status, received, data = request(path, headers=headers)
        self.assertEqual(status, 200)
        self.assertEqual(received["X-Received-Path"], path)
        self.assertEqual(received["Subscription-Userinfo"], "upload=12; download=34; total=56")
        self.assertEqual(received["Profile-Update-Interval"], "1")
        self.assertEqual(int(received["Content-Length"]), len(data))
        full, other = json.loads(data)
        self.assertEqual(other, OTHER)
        self.assertEqual(full["remarks"], PROFILE["remarks"])
        self.assertEqual(full["outbounds"], PROFILE["outbounds"])
        self.assertEqual(full["routing"]["rules"], [
            {"type": "field", "network": "tcp,udp", "outboundTag": "proxy"}
        ])
        self.assertTrue(full["dns"]["servers"][1]["skipFallback"])
        self.assertEqual(rewrite_profile(data, HOSTNAME, PREFIX), data)
        self.assertEqual(request(path)[0], 403)
        self.assertEqual(request(path, "HEAD", headers)[2], b"")
        self.assertEqual(request("/clash/test", headers=headers)[2], b"proxies: []")
        status, received, plain_json = request("/json_sub/client", headers=headers)
        self.assertEqual((status, received["Content-Type"], plain_json), (200, "text/plain", data))

        without_target = json.dumps([OTHER]).encode()
        self.assertEqual(rewrite_profile(without_target, HOSTNAME, PREFIX), without_target)
        original = json.dumps(PROFILE).encode()
        self.assertEqual(rewrite_profile(original, "other.example.com", PREFIX), original)
        self.assertEqual(rewrite_profile(original, HOSTNAME, "Other |"), original)
        self.assertEqual(json.loads(rewrite_profile(original, HOSTNAME, PREFIX)), full)

    def test_geo_files_and_happ_update_header(self):
        with TemporaryDirectory() as directory:
            path = Path(directory)
            version = path / "1700000000"
            version.mkdir()
            for name in ("geosite.dat", "geoip.dat"):
                (version / name).write_bytes(name.encode())
            (path / "current").write_text(version.name, encoding="ascii")
            origin = self.start(ThreadingHTTPServer(("127.0.0.1", 0), Origin))
            proxy = self.start(SubscriptionServer(
                ("127.0.0.1", 0), origin.server_port, HOSTNAME, PREFIX, geodata_dir=path,
            ))

            def request(path, method="GET", headers=None):
                connection = http.client.HTTPConnection("127.0.0.1", proxy.server_port, timeout=3)
                try:
                    connection.request(method, path, headers=headers or {})
                    response = connection.getresponse()
                    return response.status, response.headers, response.read()
                finally:
                    connection.close()

            for name in ("geosite.dat", "geoip.dat"):
                status, headers, data = request("/geo/" + name)
                self.assertEqual((status, data), (200, name.encode()))
                self.assertEqual(headers["Content-Type"], "application/octet-stream")
                self.assertEqual(headers["Cache-Control"], "no-store")
                status, headers, data = request("/geo/" + name + "?download=1", "HEAD")
                self.assertEqual((status, headers["Content-Length"], data), (200, str(len(name)), b""))
            self.assertEqual(request("/geo/../current")[0], 404)

            routing = {
                "Name": "Test 🌿",
                "Geositeurl": proxy.geodata_url + "geosite.dat",
                "Geoipurl": proxy.geodata_url + "geoip.dat",
                "LastUpdated": 1690000000,
            }

            def request_routing(profile):
                payload = base64.b64encode(json.dumps(profile, ensure_ascii=False).encode()).decode()
                uri = "happ://routing/onadd/" + payload
                _, headers, _ = request("/subscription/test", headers={
                    "X-Hwid": "test-device", "X-Test-Routing": uri,
                })
                return json.loads(base64.b64decode(headers["Routing"].removeprefix("happ://routing/onadd/")))

            self.assertEqual(request_routing(routing), {**routing, "LastUpdated": 1700000000})
            external = {**routing, "Geoipurl": "https://other.example.com/geoip.dat"}
            self.assertEqual(request_routing(external), external)


    def test_local_resolvers_are_matched_by_mode(self):
        profile = json.loads(json.dumps(PROFILE))
        servers = [
            "https://1.1.1.1/dns-query",
            {"address": "https+local://1.1.1.1/dns-query", "timeoutMs": 2000},
            "https+local://1.0.0.1/dns-query",
            "tcp+local://1.1.1.1",
            "localhost",
        ]
        profile["dns"]["servers"] = servers
        rewritten = json.loads(rewrite_profile(json.dumps(profile).encode(), HOSTNAME, PREFIX))["dns"]["servers"]
        self.assertEqual(rewritten[0], servers[0])
        self.assertEqual(rewritten[1]["timeoutMs"], 2000)
        for before, after in zip(servers[1:], rewritten[1:]):
            self.assertEqual(after["address"], before["address"] if isinstance(before, dict) else before)
            self.assertEqual(after["domains"], [f"full:{HOSTNAME}"])
            self.assertTrue(after["skipFallback"])


if __name__ == "__main__":
    unittest.main()
