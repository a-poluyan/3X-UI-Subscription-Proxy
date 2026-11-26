"""Route a selected 3x-ui JSON subscription profile entirely through VLESS."""

import argparse
import base64
import http.client
import json
import os
import shutil
import ssl
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs

from geodata_sets import GEODATA_FIELDS, SET_ID, compatible_set, selection_revision


MAX_BODY = 8 * 1024 * 1024
TIMEOUT = 12
MAX_CONNECTIONS = 32

HOP_HEADERS = {
    "connection", "keep-alive", "proxy-authenticate", "proxy-authorization",
    "proxy-connection", "te", "trailer", "transfer-encoding", "upgrade",
}
BODY_VALIDATORS = {"etag", "content-md5", "content-digest", "digest", "accept-ranges"}


def geodata_version(directory):
    if directory is not None:
        try:
            return int((directory / "current").read_text(encoding="ascii"))
        except (OSError, ValueError):
            pass
    return 0


def refresh_routing(value, directory, geodata_url, *, body=None, subscription_path=None):
    prefix = "happ://routing/"
    if not value.startswith(prefix):
        return value
    action, _, payload = value.removeprefix(prefix).partition("/")
    if action not in {"add", "onadd"}:
        return value
    try:
        decoded = base64.b64decode(payload + "=" * (-len(payload) % 4), altchars=b"-_", validate=True)
        profile = json.loads(decoded)
    except ValueError:
        return value
    if not isinstance(profile, dict) or any(
        profile.get(field) != geodata_url + name for name, field in GEODATA_FIELDS.items()
    ):
        return value

    previous = profile.get("LastUpdated")
    try:
        previous_time = int(previous)
    except (TypeError, ValueError):
        previous_time = 0
    publication = geodata_version(directory)
    multiplier = 1000 if previous_time >= 10 ** 12 else 1
    version = publication
    identifier = None
    if publication > 0 and body is not None:
        sets = directory / "sets"
        if sets.is_dir():
            identifier = compatible_set(sets, directory / str(publication), profile, body)
            selection = identifier or f"full:{publication}"
            baseline = previous_time // multiplier if identifier else max(publication, previous_time // multiplier)
            try:
                version = selection_revision(sets, subscription_path, selection, baseline)
            except (OSError, ValueError):
                identifier = None
    if identifier:
        for name, field in GEODATA_FIELDS.items():
            profile[field] = f"{geodata_url}{name}?set={identifier}"

    timestamp = max(previous_time, version * multiplier)
    if not identifier and timestamp <= previous_time:
        return value
    profile["LastUpdated"] = timestamp if type(previous) is int else str(timestamp)
    encoded = base64.b64encode(json.dumps(profile, ensure_ascii=False, separators=(",", ":")).encode()).decode()
    return f"{prefix}{action}/{encoded}"


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

    def send_geodata(self, name, query):
        directory = self.server.geodata_dir
        values = parse_qs(query, keep_blank_values=True).get("set")
        if name not in GEODATA_FIELDS or (values and (len(values) != 1 or not SET_ID.fullmatch(values[0]))):
            self.send_error(404)
            return
        if values:
            folder = directory / "sets" / values[0]
        else:
            folder = directory / str(geodata_version(directory))
        try:
            source = (folder / name).open("rb")
        except FileNotFoundError:
            self.send_error(404)
            return
        with source:
            self.send_response(200)
            self.send_header("Content-Type", "application/octet-stream")
            self.send_header("Content-Length", str(os.fstat(source.fileno()).st_size))
            self.send_header("Cache-Control", "public, max-age=31536000, immutable" if values else "no-store")
            self.end_headers()
            if self.command == "GET":
                shutil.copyfileobj(source, self.wfile)

    def forward(self):
        if not self.path.startswith("/") or self.path.startswith("//"):
            self.send_error(400)
            return

        path, _, query = self.path.partition("?")
        if self.server.geodata_dir is not None and path.startswith("/geo/"):
            self.send_geodata(path.removeprefix("/geo/"), query)
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
        json_subscription = (
            self.command == "GET" and status == 200 and is_json
            and path.startswith(("/subscription/", "/json_sub/"))
        )
        if json_subscription:
            updated = rewrite_profile(body, self.server.hostname, self.server.profile_prefix)
        happ_json = json_subscription and "happ" in self.headers.get("User-Agent", "").lower()

        self.send_response_only(status)
        for key, value in response_headers:
            if not no_body and key.lower() == "content-length":
                continue
            if updated != body and key.lower() in BODY_VALIDATORS:
                continue
            if status == 200 and key.lower() == "routing" and self.server.geodata_dir is not None:
                value = refresh_routing(
                    value, self.server.geodata_dir, self.server.geodata_url,
                    body=updated if happ_json else None, subscription_path=path,
                )
            self.send_header(key, value)
        if not no_body:
            self.send_header("Content-Length", str(len(updated)))
        self.send_header("Connection", "close")
        self.end_headers()
        if not no_body:
            self.wfile.write(updated)

    do_GET = do_HEAD = forward


class SubscriptionServer(ThreadingHTTPServer):
    def __init__(self, address, origin_port, hostname, profile_prefix, *, origin_tls=None, public_tls=None, geodata_dir=None):
        super().__init__(address, SubscriptionHandler)
        self.origin_port = origin_port
        self.hostname = hostname
        self.profile_prefix = profile_prefix
        self.origin_tls = origin_tls
        self.public_tls = public_tls
        self.geodata_dir = geodata_dir
        scheme = "https" if public_tls else "http"
        self.geodata_url = f"{scheme}://{hostname}:{self.server_port}/geo/"
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
    parser.add_argument("--geodata-dir", type=Path, help="Directory of published GeoIP and GeoSite files")
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
        origin_tls=ssl.create_default_context(), public_tls=public_tls, geodata_dir=args.geodata_dir,
    ) as server:
        server.serve_forever()


if __name__ == "__main__":
    main()
