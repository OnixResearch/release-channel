#!/usr/bin/env python3
"""Local mechanism rail only: NOT production or administrator separation.
Usage: local.py /absolute/pilot-binary /absolute/openssl-binary
Uses the actual pinned Distribution image and a separate TLS static metadata PUT server.
All artifacts and trust roots are temporary absolute paths; cleanup follows execution.
"""
import http.server
import json
import pathlib
import socket
import ssl
import subprocess
import sys
import tempfile
import threading
import time

IMAGE = "registry@sha256:d4032d4cc323c1731c707931ecada07a53076eac38e3b61ae57533f170f2c6c3"
LIMIT = 1048576


def certificate(directory, openssl):
    key = directory / "server.key"
    cert = directory / "server.pem"
    der = directory / "root.der"
    root = directory / "root.pem"
    rootkey = directory / "root.key"
    csr = directory / "server.csr"
    extensions = directory / "server.ext"
    extensions.write_text("basicConstraints=critical,CA:FALSE\n"
                          "keyUsage=critical,digitalSignature,keyEncipherment\n"
                          "extendedKeyUsage=serverAuth\nsubjectAltName=IP:127.0.0.1\n")
    commands = [
        [openssl, "req", "-x509", "-newkey", "rsa:2048", "-nodes",
         "-keyout", str(rootkey), "-out", str(root), "-days", "1", "-subj", "/CN=pilot-root",
         "-addext", "basicConstraints=critical,CA:TRUE", "-addext", "keyUsage=critical,keyCertSign,cRLSign"],
        [openssl, "req", "-new", "-newkey", "rsa:2048", "-nodes", "-keyout", str(key),
         "-out", str(csr), "-subj", "/CN=localhost"],
        [openssl, "x509", "-req", "-in", str(csr), "-CA", str(root), "-CAkey", str(rootkey),
         "-CAcreateserial", "-out", str(cert), "-days", "1", "-extfile", str(extensions)],
        [openssl, "x509", "-in", str(root), "-outform", "DER", "-out", str(der)]]
    for command in commands:
        subprocess.run(command, check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    return key, cert, der


def profile(port):
    return {
        "schema_version": 1, "profile_id": "local-mechanism.v1",
        "destination": {"id": "local-mechanism.v1", "hosts": [{"kind": "exact", "value": "127.0.0.1"}],
                        "ports": [port], "address": {"allow_loopback": True, "allow_private": False,
                        "allow_link_local": False, "allow_multicast": False, "allow_unspecified": False}},
        "tls": {"id": "local-explicit-root.v1", "minimum_version": "1.3"},
        "redirect": {"max_hops": 0, "allow_cross_authority": False,
                     "forward_credentials_same_authority": False},
        "retry": {"max_attempts": 1, "delay_ms": 0},
        "deadlines": {"resolve_ms": 2000, "connect_ms": 2000, "tls_ms": 2000,
                      "first_byte_ms": 2000, "body_ms": 2000, "idle_ms": 2000, "total_ms": 10000},
        "resources": {"request_body_bytes": LIMIT, "wire_response_bytes": LIMIT,
                      "decoded_response_bytes": LIMIT, "retained_prefix_bytes": LIMIT,
                      "header_bytes": 65536, "header_count": 128, "chunk_bytes": LIMIT,
                      "decompression_ratio": 1, "resolver_candidates": 8, "connections": 1,
                      "credential_bytes": 1024},
        "non_claims": ["does not authorize egress", "does not establish remote trust or response truth",
                       "does not prove operation idempotency",
                       "does not replace consumer credentials or release policy"]}


def endpoint(port, root, identity, oci):
    return {"identity": [identity] * 32, "url": f"https://127.0.0.1:{port}" + ("" if oci else "/metadata"),
            "repository": "release-channel-pilot" if oci else None, "profile": profile(port),
            "roots": [str(root)], "authorization_env": None}


def mirror(directory, key, cert):
    class Handler(http.server.BaseHTTPRequestHandler):
        protocol_version = "HTTP/1.1"

        def location(self):
            name = self.path.removeprefix("/metadata/")
            if len(name) != 73 or not name.endswith(".metadata"):
                return None
            if any(c not in "0123456789abcdef" for c in name[:-9]):
                return None
            return directory / name

        def do_PUT(self):
            path = self.location()
            count = int(self.headers.get("Content-Length", "-1"))
            if path is None or not 0 <= count <= LIMIT:
                self.send_error(400)
                return
            data = self.rfile.read(count)
            if len(data) != count:
                self.send_error(400)
                return
            path.write_bytes(data)
            self.send_response(201)
            self.send_header("Content-Length", "0")
            self.end_headers()

        def do_GET(self):
            path = self.location()
            if path is None or not path.is_file():
                self.send_error(404)
                return
            data = path.read_bytes()
            self.send_response(200)
            self.send_header("Content-Type", "application/vnd.onix.release-channel.metadata.v1")
            self.send_header("Content-Length", str(len(data)))
            self.end_headers()
            self.wfile.write(data)

        def log_message(self, *_args):
            pass

    server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.minimum_version = ssl.TLSVersion.TLSv1_3
    context.load_cert_chain(cert, key)
    server.socket = context.wrap_socket(server.socket, server_side=True)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    return server


def registry(directory, key, cert):
    subprocess.run(["docker", "image", "inspect", IMAGE], check=True, stdout=subprocess.DEVNULL)
    result = subprocess.run(["docker", "run", "--rm", "-d", "-p", "127.0.0.1::5000",
        "-v", f"{directory}:/pilot:ro", "-e", "REGISTRY_HTTP_ADDR=0.0.0.0:5000",
        "-e", "REGISTRY_HTTP_RELATIVEURLS=false",
        "-e", f"REGISTRY_HTTP_TLS_CERTIFICATE=/pilot/{cert.name}",
        "-e", f"REGISTRY_HTTP_TLS_KEY=/pilot/{key.name}", IMAGE], check=True,
        capture_output=True, text=True)
    container = result.stdout.strip()
    try:
        result = subprocess.run(["docker", "port", container, "5000/tcp"], check=True,
                                capture_output=True, text=True)
        return container, int(result.stdout.strip().rsplit(":", 1)[1])
    except Exception:
        subprocess.run(["docker", "stop", container], check=True, stdout=subprocess.DEVNULL)
        raise


def ready(port):
    deadline = time.monotonic() + 10
    while time.monotonic() < deadline:
        try:
            with socket.create_connection(("127.0.0.1", port), timeout=1):
                return
        except OSError:
            time.sleep(0.05)
    raise RuntimeError("Distribution endpoint failed readiness")


def run(binary, openssl, directory):
    oci = directory / "oci"
    cache = directory / "mirror"
    oci.mkdir()
    cache.mkdir()
    okey, ocert, oroot = certificate(oci, openssl)
    mkey, mcert, mroot = certificate(cache, openssl)
    server = mirror(cache, mkey, mcert)
    container = None
    try:
        container, port = registry(oci, okey, ocert)
        ready(port)
        metadata = directory / "payload.metadata"
        metadata.write_bytes(b"local-transport-mechanism-only\x00\x01\xff")
        config = {"metadata": str(metadata),
                  "oci_upload": endpoint(port, oroot, 1, True),
                  "oci_readback": endpoint(port, oroot, 1, True),
                  "mirror_upload": endpoint(server.server_port, mroot, 2, False),
                  "mirror_readback": endpoint(server.server_port, mroot, 2, False)}
        path = directory / "operator.json"
        path.write_text(json.dumps(config))
        subprocess.run([binary, str(path)], check=True)
        print("LOCAL MECHANISM ONLY: shared host/admin; not production independence or channel CAS")
    finally:
        server.shutdown()
        server.server_close()
        if container:
            subprocess.run(["docker", "stop", container], check=True, stdout=subprocess.DEVNULL)


def main():
    if len(sys.argv) != 3 or any(not pathlib.Path(p).is_absolute() for p in sys.argv[1:]):
        raise SystemExit(__doc__)
    with tempfile.TemporaryDirectory(prefix="channel-transports-") as directory:
        run(sys.argv[1], sys.argv[2], pathlib.Path(directory))


if __name__ == "__main__":
    main()
