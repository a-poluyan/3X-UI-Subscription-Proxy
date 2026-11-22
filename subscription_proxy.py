"""Route a selected 3x-ui JSON subscription profile entirely through VLESS."""

import argparse
import http.client
import json
import ssl
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer


MAX_BODY = 8 * 1024 * 1024
TIMEOUT = 12
MAX_CONNECTIONS = 32

HOP_HEADERS = {
    "connection", "keep-alive", "proxy-authenticate", "proxy-authorization",
    "proxy-connection", "te", "trailer", "transfer-encoding", "upgrade",
}
BODY_VALIDATORS = {"etag", "content-md5", "content-digest", "digest", "accept-ranges"}


def matches_profile(profile, hostname, profile_prefix):
    return isinstance(profile, dict) and str(profile.get("remarks", "")).startswith(profile_prefix) and any(
        outbound.get("tag") == "proxy"
        and outbound.get("protocol") == "vless"
        and outbound.get("settings", {}).get("address") == hostname
        and outbound.get("settings", {}).get("port") == 443
        for outbound in profile.get("outbounds", [])
    )


def rewrite_profile(body, hostname, profile_prefix):
    try:
        data = json.loads(body)
        entries = data if isinstance(data, list) else [data]
        profile = next((item for item in entries if matches_profile(item, hostname, profile_prefix)), None)
        if profile is None:
            return body
        profile.setdefault("routing", {})["rules"] = [
            {"type": "field", "network": "tcp,udp", "outboundTag": "proxy"}
        ]
        servers = profile.get("dns", {}).get("servers", [])
        for index, resolver in enumerate(servers):
            address = resolver.get("address") if isinstance(resolver, dict) else resolver
            if not isinstance(address, str):
                continue
            scheme, separator, _ = address.lower().partition("://")
            if address.lower() != "localhost" and not (separator and scheme.endswith("+local")):
                continue
            if isinstance(resolver, str):
                resolver = servers[index] = {"address": address}
            resolver["domains"] = [f"full:{hostname}"]
            resolver["skipFallback"] = True
        return json.dumps(data, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
    except (ValueError, TypeError, AttributeError):
        # A response outside the expected 3x-ui schema is served verbatim.
        return body


def forwarded_headers(headers):
    connection_tokens = {
        token.strip().lower()
        for value in headers.get_all("Connection", [])
        for token in value.split(",")
    }
    return [
        (key, value) for key, value in headers.items()
        if key.lower() not in HOP_HEADERS | connection_tokens
    ]


class SubscriptionHandler(BaseHTTPRequestHandler):
    def log_message(self, format, *args):
        # Request URLs contain personal subscription IDs.
        pass

    def forward(self):
        if not self.path.startswith("/") or self.path.startswith("//"):
            self.send_error(400)
            return

        headers = {
            key: value for key, value in forwarded_headers(self.headers)
            if key.lower() not in {"accept-encoding", "content-length", "forwarded"}
            and not key.lower().startswith("x-forwarded-")
        }
        headers["Accept-Encoding"] = "identity"
        headers["X-Forwarded-For"] = self.client_address[0]
        headers["X-Forwarded-Proto"] = "https" if self.server.public_tls else "http"
        connection = http.client.HTTPConnection("127.0.0.1", self.server.origin_port, timeout=TIMEOUT)
        try:
            if self.server.origin_tls:
                connection.connect()
                connection.sock = self.server.origin_tls.wrap_socket(
                    connection.sock, server_hostname=self.server.hostname
                )
            connection.request(self.command, self.path, headers=headers)
            with connection.getresponse() as upstream:
                status = upstream.status
                response_headers = forwarded_headers(upstream.headers)
                content_type = upstream.headers.get_content_type()
                is_json = (
                    (
                        content_type == "application/json"
                        or (self.path.startswith("/json_sub/") and content_type == "text/plain")
                    )
                    and upstream.headers.get("Content-Encoding", "identity").lower() == "identity"
                )
                no_body = self.command == "HEAD" or status in (204, 304)
                body = b"" if no_body else upstream.read(MAX_BODY + 1)
        except (OSError, http.client.HTTPException, ValueError):
            self.send_error(502, "Subscription backend unavailable")
            return
        finally:
            connection.close()

        if len(body) > MAX_BODY:
            self.send_error(502, "Subscription response exceeds size limit")
            return

        updated = body
        if self.command == "GET" and status == 200 and is_json and self.path.startswith(("/subscription/", "/json_sub/")):
            updated = rewrite_profile(body, self.server.hostname, self.server.profile_prefix)

        self.send_response_only(status)
        for key, value in response_headers:
            if not no_body and key.lower() == "content-length":
                continue
            if updated != body and key.lower() in BODY_VALIDATORS:
                continue
            self.send_header(key, value)
        if not no_body:
            self.send_header("Content-Length", str(len(updated)))
        self.send_header("Connection", "close")
        self.end_headers()
        if not no_body:
            self.wfile.write(updated)

    do_GET = do_HEAD = forward


class SubscriptionServer(ThreadingHTTPServer):
    def __init__(self, address, origin_port, hostname, profile_prefix, *, origin_tls=None, public_tls=None):
        super().__init__(address, SubscriptionHandler)
        self.origin_port = origin_port
        self.hostname = hostname
        self.profile_prefix = profile_prefix
        self.origin_tls = origin_tls
        self.public_tls = public_tls
        self.connections = threading.BoundedSemaphore(MAX_CONNECTIONS)

    def process_request(self, request, client_address):
        if not self.connections.acquire(blocking=False):
            self.shutdown_request(request)
            return
        try:
            super().process_request(request, client_address)
        except Exception:
            self.connections.release()
            raise

    def process_request_thread(self, request, client_address):
        try:
            request.settimeout(TIMEOUT)
            if self.public_tls:
                request = self.public_tls.wrap_socket(request, server_side=True)
            super().process_request_thread(request, client_address)
        except OSError:
            self.shutdown_request(request)
        finally:
            self.connections.release()

    def handle_error(self, request, client_address):
        # Suppress tracebacks for disconnected clients.
        pass


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--listen", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=12096)
    parser.add_argument("--origin-port", type=int, default=2096)
    parser.add_argument("--hostname", required=True, help="DNS name on the 3x-ui certificate and VLESS profile")
    parser.add_argument("--profile-prefix", required=True, help="Start of the selected profile name")
    parser.add_argument("--cert")
    parser.add_argument("--key")
    args = parser.parse_args()
    if bool(args.cert) != bool(args.key):
        parser.error("--cert and --key must be provided together")
    if args.listen not in ("127.0.0.1", "localhost") and not args.cert:
        parser.error("a public listener requires --cert and --key")
    if args.port == args.origin_port:
        parser.error("the public and origin ports must differ")
    if not args.hostname.strip() or not args.profile_prefix.strip():
        parser.error("--hostname and --profile-prefix must be non-empty")
    public_tls = None
    if args.cert:
        public_tls = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        public_tls.load_cert_chain(args.cert, args.key)
    with SubscriptionServer(
        (args.listen, args.port), args.origin_port, args.hostname, args.profile_prefix,
        origin_tls=ssl.create_default_context(), public_tls=public_tls,
    ) as server:
        server.serve_forever()


if __name__ == "__main__":
    main()
