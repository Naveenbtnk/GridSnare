#!/usr/bin/env python3
"""Modbus/TCP traffic generator for the Section 12 test plan.

Every test case in SPEC.md Section 12 begins with "send a request to the honeypot",
so the requests live in one place instead of being inlined into each test. This is
the "lab test script" those rows refer to.

Deliberately stdlib-only: `socket` + `struct` are enough to speak Modbus/TCP, and a
test dependency on a Modbus library would mean the tests could pass against a
library's idea of the protocol rather than against the bytes the decoy actually
receives.

A missing reply is not an error. Conpot answers some functions with an exception
frame and ignores others, and what the tests care about is that a request reached
the decoy and was captured on the wire. Callers get None and decide for themselves.

Usable two ways:

    # from a test
    from lab_traffic import read_holding_registers

    # by hand, from inside the lab network
    docker compose --profile test run --rm tests python tests/lab_traffic.py read --address 0 --quantity 10
"""

from __future__ import annotations

import argparse
import socket
import struct
import sys
import time
from typing import Dict, List, Optional, Sequence, Tuple

# MBAP header: transaction id, protocol id (0 for Modbus), length, unit id.
MBAP = struct.Struct(">HHHB")

READ_HOLDING_REGISTERS = 3
READ_COILS = 1
READ_DISCRETE_INPUTS = 2
READ_INPUT_REGISTERS = 4
WRITE_SINGLE_COIL = 5
WRITE_SINGLE_REGISTER = 6
WRITE_MULTIPLE_REGISTERS = 16
READ_DEVICE_IDENTIFICATION = 43  # 0x2B — not on any sane allow-list; used by TC-3

_TRANSACTION_ID = 0


def _next_transaction_id() -> int:
    """Monotonic transaction id. A real master varies it; keeping it moving means
    the capture is not accidentally exercising one fixed value."""
    global _TRANSACTION_ID
    _TRANSACTION_ID = (_TRANSACTION_ID + 1) % 0xFFFF
    return _TRANSACTION_ID or 1


def send_request(
    host: str,
    port: int,
    unit_id: int,
    pdu: bytes,
    timeout: float = 5.0,
) -> Optional[bytes]:
    """Send one Modbus/TCP request. Returns the reply bytes, or None on timeout."""
    frame = MBAP.pack(_next_transaction_id(), 0, len(pdu) + 1, unit_id) + pdu
    with socket.create_connection((host, port), timeout) as sock:
        sock.sendall(frame)
        sock.settimeout(timeout)
        try:
            return sock.recv(512)
        except (socket.timeout, TimeoutError, ConnectionError):
            return None


def classic_read(host: str, port: int, address: int = 0, quantity: int = 10,
                 unit_id: int = 1, timeout: float = 5.0) -> Optional[bytes]:
    """FC 3 — read holding registers. TC-1's "benign Modbus read request"."""
    return send_request(host, port, unit_id,
                        struct.pack(">BHH", READ_HOLDING_REGISTERS, address, quantity), timeout)


def read_coils(host: str, port: int, address: int = 0, quantity: int = 8,
               unit_id: int = 1, timeout: float = 5.0) -> Optional[bytes]:
    """FC 1 — read coils. On the allow-list, so it is baseline-safe."""
    return send_request(host, port, unit_id,
                        struct.pack(">BHH", READ_COILS, address, quantity), timeout)


def write_single_register(host: str, port: int, address: int, value: int,
                          unit_id: int = 1, timeout: float = 5.0) -> Optional[bytes]:
    """FC 6 — write a single holding register. Used by TC-4's out-of-range write."""
    return send_request(host, port, unit_id,
                        struct.pack(">BHH", WRITE_SINGLE_REGISTER, address, value), timeout)


def write_multiple_registers(host: str, port: int, address: int, values: Sequence[int],
                             unit_id: int = 1, timeout: float = 5.0) -> Optional[bytes]:
    """FC 16 — write several holding registers."""
    payload = b"".join(struct.pack(">H", value) for value in values)
    pdu = struct.pack(">BHHB", WRITE_MULTIPLE_REGISTERS, address, len(values), len(payload)) + payload
    return send_request(host, port, unit_id, pdu, timeout)


def read_device_identification(host: str, port: int, unit_id: int = 1,
                               timeout: float = 5.0) -> Optional[bytes]:
    """FC 43 / MEI 0x0E — device identification. TC-3's out-of-allow-list function
    code: recognisable ICS reconnaissance, and never on a legitimate poll pattern."""
    pdu = struct.pack(">BBB", READ_DEVICE_IDENTIFICATION, 0x0E, 0x01)
    return send_request(host, port, unit_id, pdu, timeout)


def send_function_code(host: str, port: int, function_code: int, payload: bytes = b"",
                       unit_id: int = 1, timeout: float = 5.0) -> Optional[bytes]:
    """Send an arbitrary function code with a raw payload, for cases where the
    interesting part is the function code itself."""
    return send_request(host, port, unit_id, bytes([function_code]) + payload, timeout)


def reply_function_code(reply: Optional[bytes]) -> Optional[int]:
    """Function code of a reply, or None when there was no reply."""
    if not reply or len(reply) < 8:
        return None
    return reply[7]


def is_exception_reply(reply: Optional[bytes]) -> bool:
    """True when Modbus answered with an exception frame (function code | 0x80).

    An exception still proves the decoy read and processed the request, which is
    all DR-1 cares about — a decoy that answers "illegal data address" is working.
    """
    code = reply_function_code(reply)
    return code is not None and bool(code & 0x80)


def describe_reply(reply: Optional[bytes]) -> str:
    """Short human-readable form of a reply, for test evidence output."""
    if not reply:
        return "no reply"
    code = reply_function_code(reply)
    if is_exception_reply(reply):
        return f"exception reply (fc=0x{code:02X}, code=0x{reply[8]:02X})" if len(reply) > 8 \
            else f"exception reply (fc=0x{code:02X})"
    return f"reply (fc={code}, {len(reply)} bytes)"


def baseline_reads(
    host: str,
    port: int,
    addresses: Sequence[Tuple[str, int]],
    interval_seconds: float,
    duration_seconds: float,
    unit_id: int = 1,
    on_send=None,
) -> List[Dict[str, object]]:
    """Run TC-2's "expected/whitelisted Modbus traffic pattern" for a duration.

    Only allow-listed read functions are used, at a fixed interval, so the pattern
    is the baseline the rule set is supposed to stay quiet about. The interval is
    what keeps it under DR-6's requests-per-minute limit, so the caller can assert
    that the pattern is legal before blaming the engine for firing.

    Returns one record per request: which read, when it went out, what came back.
    """
    sent: List[Dict[str, object]] = []
    started = time.monotonic()
    index = 0
    while time.monotonic() - started < duration_seconds:
        kind, address = addresses[index % len(addresses)]
        started_send = time.monotonic()
        if kind == "coils":
            reply = read_coils(host, port, address=address, unit_id=unit_id)
        else:
            reply = classic_read(host, port, address=address, quantity=10, unit_id=unit_id)
        record = {
            "index": index,
            "function": "coils" if kind == "coils" else "holding",
            "address": address,
            "at_monotonic": started_send,
            "reply": describe_reply(reply),
        }
        sent.append(record)
        if on_send is not None:
            on_send(record)
        index += 1
        # Sleep only the remainder of the interval, so a slow reply does not make
        # the pattern drift into a faster burst (which would trip DR-6 itself).
        remaining = interval_seconds - (time.monotonic() - started_send)
        if remaining > 0:
            time.sleep(remaining)
    return sent


def _parse_args(argv: Optional[Sequence[str]] = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Send Modbus/TCP traffic to the lab decoy")
    parser.add_argument("--host", default="172.20.0.2", help="decoy address on scada_net")
    parser.add_argument("--port", type=int, default=5020, help="Conpot's testing-config Modbus port")
    parser.add_argument("--unit", type=int, default=1, help="Modbus unit / slave id")
    parser.add_argument("--timeout", type=float, default=5.0)

    sub = parser.add_subparsers(dest="command", required=True)

    read = sub.add_parser("read", help="FC 3 read holding registers")
    read.add_argument("--address", type=int, default=0)
    read.add_argument("--quantity", type=int, default=10)

    coils = sub.add_parser("read-coils", help="FC 1 read coils")
    coils.add_argument("--address", type=int, default=0)
    coils.add_argument("--quantity", type=int, default=8)

    write = sub.add_parser("write", help="FC 6 write single register")
    write.add_argument("--address", type=int, required=True)
    write.add_argument("--value", type=int, required=True)

    multi = sub.add_parser("write-multi", help="FC 16 write multiple registers")
    multi.add_argument("--address", type=int, required=True)
    multi.add_argument("--values", type=int, nargs="+", required=True)

    ident = sub.add_parser("identify", help="FC 43 read device identification")
    ident.add_argument("--mei", type=int, default=0x0E)

    raw = sub.add_parser("raw", help="any function code, empty-capable payload")
    raw.add_argument("--function", type=int, required=True)
    raw.add_argument("--payload-hex", default="")

    return parser.parse_args(argv)


def main(argv: Optional[Sequence[str]] = None) -> int:
    args = _parse_args(argv)
    # Only the `raw` subparser defines --payload-hex, so read it defensively: an
    # unconditional attribute access would make every other command fail with
    # AttributeError before a packet is ever sent.
    raw_payload = getattr(args, "payload_hex", "")
    payload = bytes.fromhex(raw_payload) if raw_payload else b""

    if args.command == "read":
        reply = classic_read(args.host, args.port, args.address, args.quantity, args.unit, args.timeout)
    elif args.command == "read-coils":
        reply = read_coils(args.host, args.port, args.address, args.quantity, args.unit, args.timeout)
    elif args.command == "write":
        reply = write_single_register(args.host, args.port, args.address, args.value, args.unit, args.timeout)
    elif args.command == "write-multi":
        reply = write_multiple_registers(args.host, args.port, args.address, args.values, args.unit, args.timeout)
    elif args.command == "identify":
        reply = send_function_code(args.host, args.port, READ_DEVICE_IDENTIFICATION,
                                   struct.pack(">BB", args.mei, 0x01), args.unit, args.timeout)
    else:
        reply = send_function_code(args.host, args.port, args.function, payload, args.unit, args.timeout)

    print(f"sent to {args.host}:{args.port} unit={args.unit} command={args.command} -> {describe_reply(reply)}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
