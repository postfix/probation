#!/usr/bin/env python3
"""A recording Conan 2 remote for the native lane (tests/conan_native.rs): it speaks the REST API the Conan 2 client uses (ping, login,
credential check, revision lists, file lists, files, binary search, uploads) over a directory, so a REAL `conan create` and `conan
upload` leave real recipe and package files behind for the firewall's fake upstream to serve.

    conan_recorder.py PORT STORE [LOG]

Every request is appended to LOG (one JSON object per line: method, path, Authorization, headers). The login accepts any Basic
credential and answers the token `recorder-token`; an upload needs that token as a Bearer."""
import http.server
import json
import os
import re
import socketserver
import sys
import time

PORT, STORE = int(sys.argv[1]), sys.argv[2]
LOG = sys.argv[3] if len(sys.argv) > 3 else None
TOKEN = "recorder-token"
os.makedirs(STORE, exist_ok=True)


def stamp(t):
    return time.strftime("%Y-%m-%dT%H:%M:%S", time.gmtime(t)) + ".000+0000"


class Handler(http.server.BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def log_message(self, *args):
        pass

    def record(self):
        if LOG:
            with open(LOG, "a") as out:
                out.write(json.dumps({"method": self.command, "path": self.path, "authorization": self.headers.get("Authorization"), "headers": dict(self.headers)}) + "\n")

    def send(self, status, body=b"", content_type="application/json", headers=()):
        if isinstance(body, str):
            body = body.encode()
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        for name, value in headers:
            self.send_header(name, value)
        self.end_headers()
        if self.command != "HEAD":
            self.wfile.write(body)

    def path_of(self):
        return self.path.split("?", 1)[0]

    def authorized(self):
        return self.headers.get("Authorization") == f"Bearer {TOKEN}"

    def do_GET(self):
        self.record()
        path = self.path_of()
        if path in ("/v1/ping", "/v2/ping"):
            return self.send(200, b"", "text/plain", [("X-Conan-Server-Capabilities", "revisions")])
        if path == "/v2/users/authenticate":
            if (self.headers.get("Authorization") or "").startswith("Basic "):
                return self.send(200, TOKEN, "text/plain")
            return self.send(401, b"", "text/plain")
        if path == "/v2/users/check_credentials":
            return self.send(200, b"", "text/plain") if self.authorized() else self.send(401, b"", "text/plain")
        if path == "/v2/conans/search":
            return self.send(200, json.dumps({"results": self.references()}))
        match = re.fullmatch(r"/v2/conans/([^/]+)/([^/]+)/([^/]+)/([^/]+)(/.*)?", path)
        if not match:
            return self.send(404)
        name, version, user, channel, rest = match.groups()
        base = os.path.join(STORE, name, version, user, channel)
        reference = f"{name}/{version}@{user}/{channel}"
        rest = rest or ""
        if rest in ("/revisions", "/latest"):
            return self.revisions(os.path.join(base, "revisions"), "reference", reference, rest == "/latest")
        m = re.fullmatch(r"/revisions/([^/]+)/(files|search)(?:/(.+))?", rest)
        if m:
            rrev, kind, file = m.groups()
            directory = os.path.join(base, "revisions", rrev)
            if kind == "files":
                return self.files(directory, file)
            packages = os.path.join(directory, "packages")
            ids = sorted(os.listdir(packages)) if os.path.isdir(packages) else []
            return self.send(200, json.dumps({pkgid: {"settings": {}, "options": {}, "requires": []} for pkgid in ids}))
        m = re.fullmatch(r"/revisions/([^/]+)/packages/([^/]+)(/latest|/revisions|/revisions/([^/]+)/files(?:/(.+))?)", rest)
        if m:
            rrev, pkgid, tail, prev, file = m.groups()
            directory = os.path.join(base, "revisions", rrev, "packages", pkgid)
            if tail in ("/latest", "/revisions"):
                return self.revisions(os.path.join(directory, "revisions"), "packageReference", f"{reference}#{rrev}:{pkgid}", tail == "/latest")
            return self.files(os.path.join(directory, "revisions", prev), file)
        self.send(404)

    do_HEAD = do_GET

    def references(self):
        found = []
        for name in sorted(os.listdir(STORE)):
            for version in sorted(os.listdir(os.path.join(STORE, name))):
                for user in sorted(os.listdir(os.path.join(STORE, name, version))):
                    for channel in sorted(os.listdir(os.path.join(STORE, name, version, user))):
                        found.append(f"{name}/{version}@{user}/{channel}")
        return found

    def revisions(self, directory, head, reference, latest):
        if not os.path.isdir(directory):
            return self.send(404)
        entries = sorted(((os.path.getmtime(os.path.join(directory, r)), r) for r in os.listdir(directory)), reverse=True)
        if not entries:
            return self.send(404)
        listed = [{"revision": r, "time": stamp(t)} for t, r in entries]
        return self.send(200, json.dumps(listed[0] if latest else {head: reference, "revisions": listed}))

    def files(self, directory, file):
        if not os.path.isdir(directory):
            return self.send(404)
        if file is None:
            names = sorted(n for n in os.listdir(directory) if os.path.isfile(os.path.join(directory, n)))
            return self.send(200, json.dumps({"files": {n: {} for n in names}}))
        target = os.path.join(directory, file)
        if not os.path.isfile(target):
            return self.send(404)
        with open(target, "rb") as handle:
            return self.send(200, handle.read(), "application/octet-stream")

    def do_PUT(self):
        self.record()
        length = int(self.headers.get("Content-Length") or 0)
        body = self.rfile.read(length)
        if not self.authorized():
            return self.send(401, b"", "text/plain", [("WWW-Authenticate", 'Bearer realm="conan"')])
        match = re.fullmatch(r"/v2/conans/([^/]+)/([^/]+)/([^/]+)/([^/]+)/(.+)/files/(.+)", self.path_of())
        if not match:
            return self.send(404)
        name, version, user, channel, middle, file = match.groups()
        target = os.path.join(STORE, name, version, user, channel, *middle.split("/"), file)
        os.makedirs(os.path.dirname(target), exist_ok=True)
        with open(target, "wb") as handle:
            handle.write(body)
        self.send(201, b"", "text/plain")


class Server(http.server.ThreadingHTTPServer):
    def server_bind(self):
        # HTTPServer.server_bind calls socket.getfqdn between bind and listen, which can stall for a long time on macOS.
        socketserver.TCPServer.server_bind(self)
        self.server_name, self.server_port = "127.0.0.1", self.server_address[1]


Server(("127.0.0.1", PORT), Handler).serve_forever()
