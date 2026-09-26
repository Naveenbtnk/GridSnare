#!/usr/bin/env python3
"""GridSnare — IEC 61850 GOOSE wire format: decode, encode, capture (SPEC.md 20.2).

One implementation of the GOOSE frame format, shared by everything that needs it:

  * ``goose/decoy_ied.py`` — the decoy IED's **subscribing** half
  * ``tests/goose_lab.py`` — the lab's capture/inject CLI, and the Phase 2 test plan
  * (planned) ``goose/goose_monitor.py`` — the Phase 2 GOOSE traffic monitor

Deliberately **not** libiec61850
--------------------------------
The decoy publishes through the library's ``GoosePublisher`` so its frames are the
library's encoding of a real control block. This module is the opposite: an
independent implementation of the same wire format, written from the PDU layout in
IEC 61850-8-1. Two independent encoders producing the same field values is evidence;
one encoder agreeing with itself is not. It is also raw enough to do the jobs the
library will not — replaying captured bytes, forging a source MAC, emitting
deliberately malformed sequence numbers.

The decoy's receive path uses this module rather than ``GooseReceiver``: the library's
receive path delivers nothing on this build, while a plain raw socket in the same image
sees the decoy's frames.

Frame layout (IEC 61850-8-1):
    Ethernet: dst(6) src(6) [0x8100 TCI(2)] ethertype(2) = 0x88B8
    GOOSE header: APPID(2) Length(2) Reserved1(2) Reserved2(2)
    GOOSE PDU: BER, tag 0x61, containing the tagged fields below
"""

from __future__ import annotations

import socket
import struct
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Tuple

GOOSE_ETHERTYPE = 0x88B8
VLAN_ETHERTYPE = 0x8100

# BER context-specific tags used by the GOOSE PDU (IEC 61850-8-1 Table 55).
GOOSE_PDU_TAG = 0x61
TAG_GOCB_REF = 0x80
TAG_TIME_ALLOWED_TO_LIVE = 0x81
TAG_DAT_SET = 0x82
TAG_GO_ID = 0x83
TAG_T = 0x84
TAG_ST_NUM = 0x85
TAG_SQ_NUM = 0x86
TAG_TEST = 0x87
TAG_CONF_REV = 0x88
TAG_NDS_COM = 0x89
TAG_NUM_DAT_SET_ENTRIES = 0x8A
TAG_ALL_DATA = 0xAB

FIELD_NAMES = {
    TAG_GOCB_REF: "gocb_ref",
    TAG_TIME_ALLOWED_TO_LIVE: "time_allowed_to_live_ms",
    TAG_DAT_SET: "dataset_ref",
    TAG_GO_ID: "goid",
    TAG_T: "t_utc",
    TAG_ST_NUM: "st_num",
    TAG_SQ_NUM: "sq_num",
    TAG_TEST: "test",
    TAG_CONF_REV: "conf_rev",
    TAG_NDS_COM: "nds_com",
    TAG_NUM_DAT_SET_ENTRIES: "num_dataset_entries",
    TAG_ALL_DATA: "all_data",
}

# AF_PACKET constants; not all of these are exposed by every Python build.
ETH_P_ALL = 0x0003
SOL_PACKET = 263
PACKET_ADD_MEMBERSHIP = 1
PACKET_MR_PROMISC = 1
PACKET_AUXDATA = 8

# struct tpacket_auxdata (linux/if_packet.h): status, len, snaplen, mac, net,
# vlan_tci, vlan_tpid. Used to recover a VLAN tag the kernel removed before we saw it.
_AUXDATA_FORMAT = "=IIIHHHH"
_AUXDATA_SIZE = struct.calcsize(_AUXDATA_FORMAT)


class DecodeError(Exception):
    """Raised when a frame is not the GOOSE frame it claims to be."""


# ---------------------------------------------------------------------------
# BER
# ---------------------------------------------------------------------------


def read_tlv(data: bytes, offset: int) -> Tuple[int, bytes, int]:
    """Read one BER TLV. Returns (tag, value, next offset).

    Only the definite-length forms a GOOSE PDU uses are supported; an indefinite
    length is rejected rather than guessed at.
    """
    if offset >= len(data):
        raise DecodeError(f"truncated BER: wanted a tag at byte {offset}")
    tag = data[offset]
    offset += 1
    if offset >= len(data):
        raise DecodeError("truncated BER: wanted a length byte")
    first = data[offset]
    offset += 1
    if first < 0x80:
        length = first
    elif first == 0x80:
        raise DecodeError("indefinite BER lengths are not valid in a GOOSE PDU")
    else:
        count = first & 0x7F
        if count > 4:
            raise DecodeError(f"unsupported BER length of {count} bytes")
        if offset + count > len(data):
            raise DecodeError("truncated BER: wanted a multi-byte length")
        length = int.from_bytes(data[offset:offset + count], "big")
        offset += count
    if offset + length > len(data):
        raise DecodeError(
            f"truncated BER: tag 0x{tag:02x} claims {length} byte(s), "
            f"{len(data) - offset} present"
        )
    return tag, data[offset:offset + length], offset + length


def encode_tlv(tag: int, value: bytes) -> bytes:
    """Encode one BER TLV in the definite short/long form."""
    length = len(value)
    if length < 0x80:
        header = bytes([tag, length])
    else:
        encoded = length.to_bytes((length.bit_length() + 7) // 8, "big")
        header = bytes([tag, 0x80 | len(encoded)]) + encoded
    return header + value


def _ber_uint(value: bytes) -> int:
    return int.from_bytes(value, "big", signed=False)


def _visible(value: bytes) -> str:
    return value.decode("utf-8", errors="replace")


def _utc_time(value: bytes) -> Dict[str, Any]:
    """Decode an IEC 61850 UtcTime: 4-byte seconds, 3-byte fraction, 1-byte quality."""
    if len(value) != 8:
        raise DecodeError(f"UtcTime must be 8 bytes, got {len(value)}")
    seconds = int.from_bytes(value[0:4], "big")
    fraction = int.from_bytes(value[4:7], "big")
    quality = value[7]
    moment = datetime.fromtimestamp(seconds, tz=timezone.utc)
    return {
        "seconds": seconds,
        "fraction": fraction,
        "quality": quality,
        "iso": moment.isoformat(timespec="milliseconds").replace("+00:00", "Z"),
        # A non-zero quality byte means time-quality bits are set; leaving them out
        # of the output would hide that a relay is reporting degraded time.
        "quality_ok": quality == 0,
    }


def _data_value(data: bytes, offset: int) -> Tuple[Dict[str, Any], int]:
    """Decode one entry of the allData sequence, one level deep."""
    tag, value, next_offset = read_tlv(data, offset)
    entry: Dict[str, Any] = {"tag": f"0x{tag:02x}"}
    if tag in (0x83, 0x84):                       # Boolean, BitString
        entry["kind"] = "boolean" if tag == 0x83 else "bitstring"
        entry["value"] = value != b"\x00" * len(value)
    elif tag in (0x85, 0x86):                     # Integer, Unsigned
        entry["kind"] = "integer"
        entry["value"] = _ber_uint(value)
    elif tag == 0x87:                             # Float
        if len(value) == 5:
            entry["kind"] = "float"
            entry["value"] = struct.unpack(">f", value[1:5])[0]
        elif len(value) == 9:
            entry["kind"] = "double"
            entry["value"] = struct.unpack(">d", value[1:9])[0]
        else:
            entry["kind"] = "float"
            entry["value"] = f"<unexpected length {len(value)}>"
    elif tag == 0x8C:                             # UtcTime inside the dataset
        entry["kind"] = "utc_time"
        entry["value"] = _utc_time(value)
    elif tag == 0x8A:                             # VisibleString
        entry["kind"] = "visible_string"
        entry["value"] = _visible(value)
    elif tag == 0xA2:                             # Structure (nested)
        entry["kind"] = "structure"
        nested: List[Dict[str, Any]] = []
        inner = 0
        while inner < len(value):
            child, inner = _data_value(value, inner)
            nested.append(child)
        entry["value"] = nested
    else:
        entry["kind"] = "unhandled"
        entry["value"] = f"<{len(value)} byte(s)> tag 0x{tag:02x} is not decoded here"
    return entry, next_offset


def decode_goose_pdu(pdu: bytes) -> Dict[str, Any]:
    """Decode a GOOSE PDU (the body of a 0x61 TLV) into named fields."""
    tag, body, _ = read_tlv(pdu, 0)
    if tag != GOOSE_PDU_TAG:
        raise DecodeError(f"expected GOOSE PDU tag 0x61, got 0x{tag:02x}")

    fields: Dict[str, Any] = {}
    offset = 0
    while offset < len(body):
        tag, value, offset = read_tlv(body, offset)
        name = FIELD_NAMES.get(tag, f"unknown_0x{tag:02x}")
        if name in ("gocb_ref", "dataset_ref", "goid"):
            fields[name] = _visible(value)
        elif name == "t_utc":
            fields[name] = _utc_time(value)
        elif name in ("test", "nds_com"):
            fields[name] = value != b"\x00" * len(value)
        elif name == "all_data":
            entries: List[Dict[str, Any]] = []
            inner = 0
            while inner < len(value):
                entry, inner = _data_value(value, inner)
                entries.append(entry)
            fields[name] = entries
        elif name.startswith("unknown_"):
            fields[name] = f"<{len(value)} byte(s)>"
        else:
            fields[name] = _ber_uint(value)
    return fields


def decode_goose_frame(frame: bytes) -> Dict[str, Any]:
    """Decode a whole Ethernet frame. Raises DecodeError if it is not GOOSE."""
    if len(frame) < 14:
        raise DecodeError(f"frame too short to have an Ethernet header ({len(frame)} bytes)")

    result: Dict[str, Any] = {
        "dst_mac": ":".join(f"{b:02x}" for b in frame[0:6]),
        "src_mac": ":".join(f"{b:02x}" for b in frame[6:12]),
        "length_bytes": len(frame),
    }

    offset = 12
    ethertype = int.from_bytes(frame[offset:offset + 2], "big")
    offset += 2
    result["vlan"] = None
    result["vlan_source"] = None
    if ethertype == VLAN_ETHERTYPE:
        if len(frame) < offset + 4:
            raise DecodeError("truncated VLAN tag")
        tci = int.from_bytes(frame[offset:offset + 2], "big")
        result["vlan"] = {"id": tci & 0x0FFF, "priority": (tci >> 13) & 0x07}
        result["vlan_source"] = "frame"
        ethertype = int.from_bytes(frame[offset + 2:offset + 4], "big")
        offset += 4

    if ethertype != GOOSE_ETHERTYPE:
        raise DecodeError(f"ethertype 0x{ethertype:04x} is not GOOSE (0x88b8)")

    if len(frame) < offset + 8:
        raise DecodeError("truncated GOOSE header")
    appid = int.from_bytes(frame[offset:offset + 2], "big")
    declared_length = int.from_bytes(frame[offset + 2:offset + 4], "big")
    reserved1 = int.from_bytes(frame[offset + 4:offset + 6], "big")
    reserved2 = int.from_bytes(frame[offset + 6:offset + 8], "big")
    offset += 8

    result.update(
        {
            "app_id": appid,
            "app_id_hex": f"0x{appid:04x}",
            "declared_length": declared_length,
            "reserved1": reserved1,
            "reserved2": reserved2,
            "pdu": decode_goose_pdu(frame[offset:]),
        }
    )
    # Reserved fields must be zero (IEC 61850-8-1); a non-zero value is a real
    # anomaly rather than a decode detail, so it is surfaced rather than ignored.
    result["reserved_ok"] = reserved1 == 0 and reserved2 == 0
    return result


# ---------------------------------------------------------------------------
# capture
# ---------------------------------------------------------------------------


def open_capture_socket(
    interface: str, promiscuous: bool = True, auxdata: bool = True
) -> socket.socket:
    sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(ETH_P_ALL))
    sock.bind((interface, 0))
    if auxdata:
        # The receive path strips a VLAN tag before AF_PACKET sees it (the same
        # behaviour that makes `tcpdump -e` print untagged frames on hardware with VLAN
        # offload). PACKET_AUXDATA is the standard way to recover it: the kernel hands
        # the removed TCI over in ancillary data instead.
        #
        # Without this the observer would confidently report "no VLAN" about frames
        # that carry one — a wrong answer, not a missing one, which is why it is on
        # by default here rather than being left to the caller.
        sock.setsockopt(SOL_PACKET, PACKET_AUXDATA, 1)
    if promiscuous:
        # A GOOSE frame is multicast to 01-0c-cd-... , which this interface is not a
        # member of, so the kernel would drop it before we ever saw it. Promiscuous
        # membership is what makes an independent observer on a flooded bridge work.
        # (This is a socket-level membership, so it needs NET_RAW but not NET_ADMIN —
        # unlike libiec61850's HAL, which sets IFF_PROMISC on the interface itself.)
        membership = struct.pack(
            "IHH8s", socket.if_nametoindex(interface), PACKET_MR_PROMISC, 0, b"\x00" * 8
        )
        sock.setsockopt(SOL_PACKET, PACKET_ADD_MEMBERSHIP, membership)
    return sock


def recv_frame(sock: socket.socket, auxdata: bool = True) -> Tuple[bytes, Optional[int]]:
    """Receive one frame, returning it plus any VLAN TCI the kernel stripped off it."""
    if not auxdata:
        return sock.recv(65535), None

    data, ancdata, _flags, _addr = sock.recvmsg(65535, socket.CMSG_SPACE(_AUXDATA_SIZE) + 32)
    tci: Optional[int] = None
    for level, ctype, cdata in ancdata:
        if level != SOL_PACKET or ctype != PACKET_AUXDATA or len(cdata) < _AUXDATA_SIZE:
            continue
        _status, _length, _snaplen, _mac, _net, vlan_tci, vlan_tpid = struct.unpack(
            _AUXDATA_FORMAT, cdata[:_AUXDATA_SIZE]
        )
        # tpid is 0x8100 (or 0x88a8 for a service tag) when a tag was actually
        # stripped; a zero TCI with a zero TPID means there never was one.
        if vlan_tpid != 0 or vlan_tci != 0:
            tci = vlan_tci
    return data, tci


def apply_stripped_vlan(decoded: Dict[str, Any], stripped_tci: Optional[int]) -> None:
    """Fold a kernel-stripped VLAN tag back into a decoded frame, in place.

    Kept as a helper so every consumer reports VLAN the same way: if the frame
    arrived untagged but a tag was removed, report the tag and say where it came from.
    """
    if decoded.get("vlan") is None and stripped_tci is not None:
        decoded["vlan"] = {
            "id": stripped_tci & 0x0FFF,
            "priority": (stripped_tci >> 13) & 0x07,
        }
        decoded["vlan_source"] = "auxdata"


def interface_mac(interface: str) -> Optional[str]:
    """Read an interface's MAC address from sysfs, or None if it cannot be read."""
    try:
        with open(f"/sys/class/net/{interface}/address", "r", encoding="ascii") as handle:
            return handle.read().strip().lower()
    except OSError:
        return None


# ---------------------------------------------------------------------------
# send
# ---------------------------------------------------------------------------


def build_goose_frame(
    dst_mac: str,
    src_mac: str,
    app_id: int,
    gocb_ref: str,
    dataset_ref: str,
    goid: str,
    st_num: int,
    sq_num: int,
    conf_rev: int,
    time_allowed_to_live_ms: int,
    trip: bool,
    operations: int,
    vlan_id: Optional[int] = None,
    vlan_priority: int = 4,
) -> bytes:
    """Encode a complete GOOSE frame from the wire format in IEC 61850-8-1."""
    changed_at = int(datetime.now(timezone.utc).timestamp())
    utc_time = changed_at.to_bytes(4, "big") + b"\x00\x00\x00" + b"\x00"

    data_entries = [
        encode_tlv(0x83, b"\x01" if trip else b"\x00"),          # Boolean
        encode_tlv(0x85, operations.to_bytes(1, "big")),         # Integer
        encode_tlv(0x8C, utc_time),                             # UtcTime
    ]
    all_data = encode_tlv(0xAB, b"".join(data_entries))

    pdu_body = b"".join(
        [
            encode_tlv(TAG_GOCB_REF, gocb_ref.encode()),
            encode_tlv(TAG_TIME_ALLOWED_TO_LIVE, time_allowed_to_live_ms.to_bytes(4, "big")),
            encode_tlv(TAG_DAT_SET, dataset_ref.encode()),
            encode_tlv(TAG_GO_ID, goid.encode()),
            encode_tlv(TAG_T, utc_time),
            encode_tlv(TAG_ST_NUM, st_num.to_bytes(4, "big")),
            encode_tlv(TAG_SQ_NUM, sq_num.to_bytes(4, "big")),
            encode_tlv(TAG_TEST, b"\x00"),
            encode_tlv(TAG_CONF_REV, conf_rev.to_bytes(4, "big")),
            encode_tlv(TAG_NDS_COM, b"\x00"),
            encode_tlv(TAG_NUM_DAT_SET_ENTRIES, len(data_entries).to_bytes(1, "big")),
            all_data,
        ]
    )
    pdu = encode_tlv(GOOSE_PDU_TAG, pdu_body)

    header = struct.pack(">HHHH", app_id, len(pdu), 0, 0)

    destination = bytes(int(part, 16) for part in dst_mac.split(":"))
    source = bytes(int(part, 16) for part in src_mac.split(":"))
    if vlan_id is None:
        ether = destination + source + struct.pack(">H", GOOSE_ETHERTYPE)
    else:
        tci = ((vlan_priority & 0x07) << 13) | (vlan_id & 0x0FFF)
        ether = destination + source + struct.pack(">HHH", VLAN_ETHERTYPE, tci, GOOSE_ETHERTYPE)
    return ether + header + pdu
