import http.client
import json
import threading
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

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
