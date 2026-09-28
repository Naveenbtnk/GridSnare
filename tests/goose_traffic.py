#!/usr/bin/env python3
"""GOOSE lab traffic generator for the Section 20.6 test plan.

Every case in SPEC.md 20.6 begins by putting GOOSE frames on the lab segment — a forged
trip, a replayed sequence, a spoofed source MAC, a flood — so the frames live in one
place instead of being inlined into each test. This is the GOOSE counterpart of
``tests/lab_traffic.py``, which does the same job for Modbus.

Two jobs:

  * ``capture`` — listen on the lab interface and decode every GOOSE frame it sees, so a
    case can assert what a publisher actually put on the wire rather than only what the
    store recorded. That distinction is the point: SPEC.md 18 forbids reporting more than
    was observed, and a test that reads the store is trusting the path it is testing.
  * ``inject`` — put a frame on the wire with chosen field values, including ones no
    legitimate publisher would produce: a forged source MAC, a replayed StNum/SqNum pair,
    a retransmission rate the configured profile cannot reach.

Why this sits next to the decoy and the publisher
-------------------------------------------------
The decoy's and the publisher's own logs cannot verify either device; something
independent has to read the bytes that left the interface and say what they contain.
``capture`` is that, and ``inject`` is the other half — a test can only claim a rule
fired on an anomaly if the anomaly really went out on the segment.

The wire format itself lives in ``goose/goose_frame.py``, shared with both publishers,
the GOOSE traffic monitor and ``tests/goose_lab.py``, so there is one implementation of
the frame layout rather than four. This module adds no encoding of its own.

Needs CAP_NET_RAW
-----------------
Both jobs open an AF_PACKET socket, which is why the `tests` service in
docker-compose.yml is granted that capability. Without it every function here raises
``InjectionUnavailable`` with that as the reason, rather than failing obscurely deep in
a socket call — a case that cannot put frames on the wire has nothing to assert and must
say so instead of passing.
"""

from __future__ import annotations

import fcntl
import socket
import struct
import sys
import time
from dataclasses import dataclass, replace
from pathlib import Path
from typing import Any, Dict, List, Optional, Sequence

# The codec lives with the services that own the format. Resolved from __file__ so the
# module works whether the repo is mounted at /app, /repo or anywhere else.
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from goose.goose_frame import (  # noqa: E402  (import after the sys.path bootstrap)
    DecodeError,
    apply_stripped_vlan,
    build_goose_frame,
    decode_goose_frame,
    open_capture_socket,
    recv_frame,
)


class InjectionUnavailable(RuntimeError):
    """This container cannot open a raw socket (it needs CAP_NET_RAW)."""


@dataclass(frozen=True)
class Endpoint:
    """The identity a GOOSE frame claims: which control block, from which MAC.

    Every field here is something a rule keys on — GR-2 on the (control block, source
    MAC) pair, GR-4 on the control block, GR-1 on the sequence within a pair — so a case
    that wants to forge or replay one changes exactly this and nothing else. The framing
    fields are part of the identity too: a frame whose APPID or destination differs from
    the device it claims to be would be a different finding, so they are carried along
    rather than left to each test to remember.
    """

    name: str
    gocb_ref: str
    dataset_ref: str
    goid: str
    src_mac: str
    app_id: int
    dst_mac: str
    conf_rev: int
    time_allowed_to_live_ms: int

    def with_src_mac(self, src_mac: str) -> "Endpoint":
        """The same control block, claimed by a different link address.

        This is the whole of a spoofing case (TC-10) and the whole of a forgery against
        the decoy (TC-7): the control block stays real, and the MAC is what does not
        belong to it.
        """
        return replace(self, src_mac=src_mac)


SIOCGIFADDR = 0x8915


def interface_addresses() -> Dict[str, str]:
    """Every interface in this container that holds an IPv4 address, by name."""
    probe = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    found: Dict[str, str] = {}
    try:
        for _index, name in socket.if_nameindex():
            try:
                request = struct.pack("256s", name.encode()[:15])
                address = fcntl.ioctl(probe.fileno(), SIOCGIFADDR, request)[20:24]
            except OSError:
                continue                      # no IPv4 on this interface (e.g. `lo` down)
            found[name] = socket.inet_ntoa(address)
    finally:
        probe.close()
    return found


def interface_for_address(address: str) -> Optional[str]:
    """The interface carrying `address`, or None if no interface carries it.

    Selected by address rather than by name because a multi-network container's
    interface names are not the ones docker-compose.yml lists: measured in this lab, the
    `tests` service comes up with eth0 on the dashboard network (172.21.0.x) and eth1 on
    the monitored segment (172.20.0.x), and the order has been observed to vary between
    runs. Injecting on the wrong one still succeeds at the socket level — the frame simply
    never reaches the monitored segment — so a name-based choice would make these cases
    pass or fail by luck. config.yaml already says which address this runner holds on the
    segment, so the address is what decides.
    """
    for name, candidate in interface_addresses().items():
        if candidate == address:
            return name
    return None


def _require(section: Any, key: str) -> Any:
    if not isinstance(section, dict) or key not in section:
        raise KeyError(
            f"config.yaml is missing {key!r}; the GOOSE cases read the publisher and "
            "decoy identities from configuration rather than hardcoding them"
        )
    return section[key]


def decoy_endpoint(config: Dict[str, Any]) -> Endpoint:
    """The decoy IED's published identity (``goose:`` in config.yaml).

    The source MAC comes from ``engine.goose.decoy_src_mac`` rather than the decoy's own
    section, because that is the value GR-4 compares against — the rule and the forged
    frame must agree about who the decoy is, or a forgery case would pass for the wrong
    reason.
    """
    section = _require(config, "goose")
    engine_goose = _require(_require(config, "engine"), "goose")
    return Endpoint(
        name="decoy IED",
        gocb_ref=str(section["gocb_ref"]),
        dataset_ref=str(section["dataset_ref"]),
        goid=str(section["goid"]),
        src_mac=str(engine_goose["decoy_src_mac"]).lower(),
        app_id=int(section["app_id"]),
        dst_mac=str(section["dst_mac"]),
        conf_rev=int(section["conf_rev"]),
        time_allowed_to_live_ms=int(section["time_allowed_to_live_ms"]),
    )


def publisher_endpoint(config: Dict[str, Any]) -> Endpoint:
    """The legitimate publisher's identity (``goose_publisher:`` in config.yaml).

    TC-8 and TC-9 need this device specifically: Section 11's whole point is that a
    baseline has to come from a real asset, so the case has to know which publisher
    qualifies. Its MAC is asserted against ``engine.goose.known_publishers`` by the cases
    that use it, so a config drift shows up as a failed assertion rather than as a test
    that quietly watches the wrong device.
    """
    section = _require(config, "goose_publisher")
    return Endpoint(
        name="legitimate publisher",
        gocb_ref=str(section["gocb_ref"]),
        dataset_ref=str(section["dataset_ref"]),
        goid=str(section["goid"]),
        src_mac=str(section["src_mac"]).lower(),
        app_id=int(section["app_id"]),
        dst_mac=str(section["dst_mac"]),
        conf_rev=int(section["conf_rev"]),
        time_allowed_to_live_ms=int(section["time_allowed_to_live_ms"]),
    )


def known_publishers(config: Dict[str, Any]) -> Dict[str, List[str]]:
    """GR-2's allow-list, normalised the way the rule normalises it."""
    raw = _require(_require(_require(config, "engine"), "goose"), "known_publishers")
    return {
        str(gocb_ref): [str(mac).strip().lower() for mac in macs]
        for gocb_ref, macs in raw.items()
    }


# ---------------------------------------------------------------------------
# building and sending
# ---------------------------------------------------------------------------

# Frames are built with the same encoder the monitor decodes with, so a case cannot
# "pass" because two implementations of the wire format agreed with each other.
def build(endpoint: Endpoint, st_num: int, sq_num: int, trip: bool = True,
          operations: int = 1, vlan_id: Optional[int] = None) -> bytes:
    """Encode one GOOSE frame claiming `endpoint`'s identity at (st_num, sq_num)."""
    return build_goose_frame(
        dst_mac=endpoint.dst_mac,
        src_mac=endpoint.src_mac,
        app_id=endpoint.app_id,
        gocb_ref=endpoint.gocb_ref,
        dataset_ref=endpoint.dataset_ref,
        goid=endpoint.goid,
        st_num=st_num,
        sq_num=sq_num,
        conf_rev=endpoint.conf_rev,
        time_allowed_to_live_ms=endpoint.time_allowed_to_live_ms,
        trip=trip,
        operations=operations,
        vlan_id=vlan_id,
    )


def sequence(endpoint: Endpoint, first_st: int, first_sq: int, count: int,
             st_step: int = 0, sq_step: int = 1, trip: bool = True) -> List[bytes]:
    """`count` frames advancing as a real publisher's do.

    Used for the legitimate half of a case — a conforming sequence from a publisher's
    identity — and for a flood, where the same shape repeated far too fast is the
    anomaly GR-3 looks for rather than a sequence GR-1 would flag.
    """
    return [
        build(endpoint, first_st + index * st_step, first_sq + index * sq_step, trip=trip)
        for index in range(count)
    ]


def open_injector(interface: str) -> socket.socket:
    """Open a raw socket for injecting frames. Raises InjectionUnavailable with the reason."""
    try:
        sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW)
        sock.bind((interface, 0))
    except PermissionError as exc:
        raise InjectionUnavailable(
            f"cannot inject GOOSE frames on {interface}: {exc}. The cases need CAP_NET_RAW "
            "(docker-compose.yml grants it to the `tests` service); without it they cannot "
            "produce the anomaly they assert on, so failing here is the honest outcome."
        ) from exc
    except OSError as exc:
        raise InjectionUnavailable(
            f"cannot open {interface} to inject GOOSE frames: {exc}. Check that the "
            "interface exists in this container (`ip link`) and that config.yaml's "
            "tests.goose_interface names it."
        ) from exc
    return sock


def send_frames(sock: socket.socket, frames: Sequence[bytes],
                interval_seconds: float = 0.0) -> int:
    """Send frames back to back, or spaced by `interval_seconds`. Returns the count sent.

    ``interval_seconds=0`` is deliberate for the timing-anomaly case: the anomaly is a
    publisher transmitting faster than its configured profile allows, so the test pushes
    frames as fast as the socket takes them rather than pacing them.
    """
    sent = 0
    for index, frame in enumerate(frames):
        sock.send(frame)
        sent += 1
        if interval_seconds and index + 1 < len(frames):
            time.sleep(interval_seconds)
    return sent


# ---------------------------------------------------------------------------
# capturing
# ---------------------------------------------------------------------------

def capture(interface: str, seconds: float) -> List[Dict[str, Any]]:
    """Decode every GOOSE frame seen on `interface` for `seconds`.

    Returns the decoder's own dictionaries (``src_mac``, ``dst_mac``, ``app_id``, and the
    decoded PDU under ``pdu``), the same shape ``goose_lab.py capture --json`` prints, so
    what a test asserts on is the bytes that were on the wire.

    Raises InjectionUnavailable if the socket cannot be opened — capturing needs
    CAP_NET_RAW for the same reason injecting does.
    """
    try:
        sock = open_capture_socket(interface)
    except PermissionError as exc:
        raise InjectionUnavailable(
            f"cannot capture GOOSE frames on {interface}: {exc}. The cases need CAP_NET_RAW "
            "(see docker-compose.yml)."
        ) from exc
    except OSError as exc:
        raise InjectionUnavailable(
            f"cannot capture on {interface}: {exc}. Check that the interface exists in "
            "this container and that tests.goose_interface names it."
        ) from exc

    sock.settimeout(1.0)
    deadline = time.monotonic() + seconds
    frames: List[Dict[str, Any]] = []
    try:
        while time.monotonic() < deadline:
            try:
                frame, stripped_tci = recv_frame(sock)
            except socket.timeout:
                continue
            except OSError:
                # The socket went away underneath us; nothing captured after this point
                # can be claimed, so stop rather than spin.
                break
            try:
                decoded = decode_goose_frame(frame)
            except DecodeError:
                # Not GOOSE or too malformed to decode. Counted by not being returned:
                # this helper reports GOOSE frames, and judging malformed traffic is the
                # engine's job (GR-1), working from the monitor's capture.
                continue
            apply_stripped_vlan(decoded, stripped_tci)
            frames.append(decoded)
    finally:
        sock.close()
    return frames


def frames_for(frames: Sequence[Dict[str, Any]], endpoint: Endpoint) -> List[Dict[str, Any]]:
    """The frames in `frames` that claim `endpoint`'s identity."""
    return [
        frame for frame in frames
        if str(frame.get("src_mac", "")).lower() == endpoint.src_mac
        and (frame.get("pdu") or {}).get("gocb_ref") == endpoint.gocb_ref
    ]


def describe_bytes(frame: bytes) -> str:
    """Short human-readable form of an *encoded* frame, for test evidence output.

    Decoded rather than described from the values the caller meant to set: printing what a
    case intended is not evidence that the bytes actually carry it, and the whole point of
    a case like TC-7 is that the frame on the wire says what the case claims it says.
    """
    return describe(decode_goose_frame(frame))


def describe(frame: Dict[str, Any]) -> str:
    """Short human-readable form of a decoded frame, for test evidence output."""
    pdu = frame.get("pdu") or {}
    return (
        f"src={frame.get('src_mac')} gocb={pdu.get('gocb_ref')} "
        f"stNum={pdu.get('st_num')} sqNum={pdu.get('sq_num')} "
        f"appId={frame.get('app_id_hex')} at={pdu.get('t_utc', {}).get('iso')}"
    )


def sequence_of(frames: Sequence[Dict[str, Any]]) -> List[Any]:
    """The (stNum, sqNum) pairs of captured frames, in capture order."""
    return [((frame.get("pdu") or {}).get("st_num"), (frame.get("pdu") or {}).get("sq_num"))
            for frame in frames]
