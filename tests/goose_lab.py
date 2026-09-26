#!/usr/bin/env python3
"""GridSnare — GOOSE lab tool: capture, decode and inject IEC 61850 GOOSE frames.

Two jobs, both needed by SPEC.md Section 20:

  * ``capture`` — listen on a lab interface, decode every GOOSE frame
    (EtherType 0x88B8) and print the fields SPEC.md 20.2 names: StNum, SqNum,
    source MAC, GoCB reference and timestamp.
  * ``send`` — put a GOOSE frame on the wire with chosen values, including ones a
    legitimate publisher would never produce (a forged source MAC, a replayed
    StNum/SqNum, an off-profile interval).

Why this exists next to the decoy
---------------------------------
The decoy's own logs cannot verify the decoy. Something independent has to read the
bytes that actually left the interface, from a different host on the segment, and
say what they contain. That is what ``capture`` is for, and it is how the Phase 2
acceptance evidence is produced.

The wire format itself lives in ``goose/goose_frame.py``, shared with the decoy's
subscriber and the GOOSE traffic monitor, so there is one implementation of the frame
layout rather than three. SPEC.md 20.4 is explicit that the test plan's
*legitimate and anomalous sequences* are generated with libiec61850's own publisher
API; that is the decoy's job. This module covers the raw side: replay and forgery.

Run it from inside the lab network:

    docker run --rm --network gridsnare_scada_net --cap-add NET_RAW \\
      -v "$(pwd):/repo:ro" python:3.12-slim \\
      python /repo/tests/goose_lab.py --interface eth0 capture --seconds 12
"""

from __future__ import annotations

import argparse
import json
import socket
import sys
import time
from pathlib import Path
from typing import Optional, Sequence

# The codec lives with the service that owns the format. Resolved relative to this
# file so the tool works whether the repo is mounted at /app, /repo or anywhere else.
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from goose.goose_frame import (  # noqa: E402
    DecodeError,
    apply_stripped_vlan,
    build_goose_frame,
    decode_goose_frame,
    open_capture_socket,
    recv_frame,
)


def capture(
    interface: str,
    seconds: float,
    limit: int,
    as_json: bool,
    dump_pdu: bool,
) -> int:
    try:
        sock = open_capture_socket(interface)
    except PermissionError:
        print(
            f"capture needs CAP_NET_RAW to open a raw socket on {interface}",
            file=sys.stderr,
        )
        return 4
    except OSError as exc:
        print(f"could not capture on {interface}: {exc}", file=sys.stderr)
        return 4

    print(
        f"listening on {interface} for GOOSE (ethertype 0x88b8) for {seconds:g}s"
        + (f" or {limit} frame(s)" if limit else ""),
        flush=True,
    )

    sock.settimeout(1.0)
    deadline = time.monotonic() + seconds
    seen = 0
    other = 0
    started = time.monotonic()

    try:
        while time.monotonic() < deadline and (limit == 0 or seen < limit):
            try:
                frame, stripped_tci = recv_frame(sock)
            except socket.timeout:
                continue
            try:
                decoded = decode_goose_frame(frame)
            except DecodeError:
                other += 1
                continue

            apply_stripped_vlan(decoded, stripped_tci)
            seen += 1

            pdu = decoded["pdu"]
            if as_json:
                print(json.dumps(decoded, sort_keys=True), flush=True)
                continue

            vlan = decoded["vlan"]
            vlan_text = (
                f"{vlan['priority']}/vid{vlan['id']}"
                + ("(auxdata)" if decoded["vlan_source"] == "auxdata" else "")
                if vlan else "untagged"
            )
            print(
                f"[{time.monotonic() - started:6.2f}s] "
                f"src={decoded['src_mac']} dst={decoded['dst_mac']} "
                f"vlan={vlan_text} appId={decoded['app_id_hex']} "
                f"gocb={pdu.get('gocb_ref')!r} "
                f"stNum={pdu.get('st_num')} sqNum={pdu.get('sq_num')} "
                f"TAL={pdu.get('time_allowed_to_live_ms')}ms "
                f"confRev={pdu.get('conf_rev')} ents={pdu.get('num_dataset_entries')} "
                f"t={pdu.get('t_utc', {}).get('iso')}",
                flush=True,
            )
            if dump_pdu:
                print(json.dumps(pdu, indent=2, sort_keys=True), flush=True)
    finally:
        sock.close()

    print(f"captured {seen} GOOSE frame(s); {other} non-GOOSE frame(s) ignored", flush=True)
    return 0 if seen else 1


def send(interface: str, frame: bytes, count: int, interval_ms: float, src_mac: str) -> int:
    try:
        sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW)
        sock.bind((interface, 0))
    except PermissionError:
        print(f"send needs CAP_NET_RAW on {interface}", file=sys.stderr)
        return 4
    except OSError as exc:
        print(f"could not open {interface}: {exc}", file=sys.stderr)
        return 4

    print(
        f"sending {count} GOOSE frame(s) on {interface} as {src_mac} "
        f"({len(frame)} bytes each, {interval_ms:g}ms apart)",
        flush=True,
    )
    try:
        for index in range(count):
            sock.send(frame)
            if interval_ms and index + 1 < count:
                time.sleep(interval_ms / 1000.0)
    finally:
        sock.close()
    print(f"sent {count} frame(s)", flush=True)
    return 0


def _parse_args(argv: Optional[Sequence[str]]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Capture, decode and inject IEC 61850 GOOSE frames (SPEC.md Section 20)"
    )
    parser.add_argument("--interface", default="eth0", help="lab interface (default: eth0)")
    sub = parser.add_subparsers(dest="command", required=True)

    cap = sub.add_parser("capture", help="listen for and decode GOOSE frames")
    cap.add_argument("--seconds", type=float, default=15.0)
    cap.add_argument("--count", type=int, default=0, help="stop after N GOOSE frames (0 = time only)")
    cap.add_argument("--json", action="store_true", help="one JSON object per frame")
    cap.add_argument("--dump-pdu", action="store_true", help="pretty-print each decoded PDU")

    send_cmd = sub.add_parser("send", help="inject a GOOSE frame with chosen fields")
    send_cmd.add_argument("--dst-mac", default="01:0c:cd:01:00:01")
    send_cmd.add_argument(
        "--src-mac",
        default="02:00:5e:00:53:99",
        help="source MAC to put in the frame; a forged value is the point of TC-10",
    )
    send_cmd.add_argument("--app-id", type=int, default=12289)
    send_cmd.add_argument("--gocb-ref", default="GSDECOY/PROT/LLN0$GO$gcbProtTrip")
    send_cmd.add_argument("--dataset-ref", default="GSDECOY/PROT/LLN0$dsProtTrip")
    send_cmd.add_argument("--goid", default="GSDECOY/PROT$gcbProtTrip")
    send_cmd.add_argument("--st-num", type=int, default=1)
    send_cmd.add_argument("--sq-num", type=int, default=1)
    send_cmd.add_argument("--conf-rev", type=int, default=1)
    send_cmd.add_argument("--tal", type=int, default=4000, help="timeAllowedToLive in ms")
    send_cmd.add_argument("--trip", type=int, choices=(0, 1), default=1)
    send_cmd.add_argument("--operations", type=int, default=1)
    send_cmd.add_argument("--vlan-id", type=int, default=None)
    send_cmd.add_argument("--count", type=int, default=1)
    send_cmd.add_argument("--interval-ms", type=float, default=0.0)
    return parser.parse_args(argv)


def main(argv: Optional[Sequence[str]] = None) -> int:
    args = _parse_args(argv)

    if args.command == "capture":
        return capture(args.interface, args.seconds, args.count, args.json, args.dump_pdu)

    frame = build_goose_frame(
        dst_mac=args.dst_mac,
        src_mac=args.src_mac,
        app_id=args.app_id,
        gocb_ref=args.gocb_ref,
        dataset_ref=args.dataset_ref,
        goid=args.goid,
        st_num=args.st_num,
        sq_num=args.sq_num,
        conf_rev=args.conf_rev,
        time_allowed_to_live_ms=args.tal,
        trip=bool(args.trip),
        operations=args.operations,
        vlan_id=args.vlan_id,
    )
    # Decode what we are about to send, so a malformed encoder is caught here rather
    # than showing up as a mysterious absence on the wire.
    check = decode_goose_frame(frame)
    print(
        f"frame encodes as gocb={check['pdu'].get('gocb_ref')!r} "
        f"stNum={check['pdu'].get('st_num')} sqNum={check['pdu'].get('sq_num')} "
        f"appId={check['app_id_hex']} entries={len(check['pdu'].get('all_data', []))}",
        flush=True,
    )
    return send(args.interface, frame, args.count, args.interval_ms, args.src_mac)


if __name__ == "__main__":
    sys.exit(main())
