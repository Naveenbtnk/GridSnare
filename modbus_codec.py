#!/usr/bin/env python3
"""GridSnare — Modbus TCP request decoding, shared by both event sources.

Two different components record the *same* Modbus exchange:

  * ``monitor/traffic_monitor.py`` — captures the TCP request off the wire with
    Scapy (SPEC.md Section 7.2) and writes ``source='monitor'`` rows.
  * ``honeypot/log_ingest.py``    — tails Conpot's log and transcribes what the
    decoy itself saw (SPEC.md Section 9 step 2) as ``source='honeypot'`` rows.

They read the request from different places, but they must agree about what it
means. A honeypot row that named a different register than the monitor row for
the same exchange would make the ``raw_events`` table contradict itself, and DR-7
(Section 8) correlates those two rows precisely because they describe one event.

Why one decoder rather than two
-------------------------------
Conpot logs the request as the Modbus application data unit, rendered as hex text
(honeypot/log_ingest.py decodes that first). Hex-decoded, it is the exact same byte
layout the monitor sees on the wire, MBAP header included. So the same decoder
applies to both, and sharing it is not a convenience but the thing that keeps the
two rows consistent. This mirrors ``store.py``: where two components must agree on
the same thing, the definition lives in one module rather than a copy per component.
Both Dockerfiles copy this file in.

This module decodes requests only. It performs no detection: whether a function
code is allowed, or a register operational, is DR-2/DR-3's job in
engine/rules.py, against thresholds in config.yaml (SPEC.md Section 8).
"""

from __future__ import annotations

import json
import struct
from typing import Any, Dict, Optional

# MBAP header: transaction id(2) protocol id(2) length(2) unit id(1) = 7 bytes,
# followed by the PDU (MODBUS Application Protocol Specification v1.1b3).
MBAP_HEADER_LEN = 7

# Standard Modbus function codes, used only to make logs readable. Nothing here
# decides whether a code is allowed — that allow-list is config driven and belongs
# to DR-2 in engine/rules.py (SPEC.md Section 8).
FUNCTION_NAMES = {
    1: "read_coils",
    2: "read_discrete_inputs",
    3: "read_holding_registers",
    4: "read_input_registers",
    5: "write_single_coil",
    6: "write_single_register",
    7: "read_exception_status",
    8: "diagnostics",
    11: "get_comm_event_counter",
    12: "get_comm_event_log",
    15: "write_multiple_coils",
    16: "write_multiple_registers",
    17: "report_server_id",
    20: "read_file_record",
    21: "write_file_record",
    22: "mask_write_register",
    23: "read_write_multiple_registers",
    24: "read_fifo_queue",
    43: "encapsulated_interface_transport",
}

READ_FUNCTIONS = frozenset({1, 2, 3, 4})
MULTI_WRITE_FUNCTIONS = frozenset({15, 16})


def be16(buffer: bytes, offset: int) -> int:
    """Read one big-endian unsigned 16-bit word."""
    return struct.unpack_from(">H", buffer, offset)[0]


def decode_request_pdu(function_code: int, pdu: bytes) -> Dict[str, Any]:
    """Extract (register address, quantity, value) from a Modbus request PDU.

    Request layouts (MODBUS Application Protocol Specification v1.1b3):
        FC 1-4   : address(2) quantity(2)
        FC 5     : address(2) output_value(2)  0xFF00 = on, 0x0000 = off
        FC 6     : address(2) register_value(2)
        FC 15/16 : address(2) quantity(2) byte_count(1) values(n)

    Anything shorter or not covered by those layouts yields None fields rather
    than a guess — an unparseable request is still recorded with its function
    code, because the function code itself is what DR-2 classifies.
    """
    extracted: Dict[str, Any] = {
        "register_address": None,
        "quantity": None,
        "value": None,
        "values_json": None,
    }

    if function_code in READ_FUNCTIONS:
        if len(pdu) >= 5:
            extracted["register_address"] = be16(pdu, 1)
            extracted["quantity"] = be16(pdu, 3)

    elif function_code == 5:
        if len(pdu) >= 5:
            raw_value = be16(pdu, 3)
            extracted["register_address"] = be16(pdu, 1)
            extracted["quantity"] = 1
            # Normalise the two legal encodings; anything else is kept raw so a
            # malformed write stays visible instead of being rounded to on/off.
            extracted["value"] = {0xFF00: 1, 0x0000: 0}.get(raw_value, raw_value)

    elif function_code == 6:
        if len(pdu) >= 5:
            extracted["register_address"] = be16(pdu, 1)
            extracted["quantity"] = 1
            extracted["value"] = be16(pdu, 3)

    elif function_code in MULTI_WRITE_FUNCTIONS:
        if len(pdu) >= 6:
            register_address = be16(pdu, 1)
            quantity = be16(pdu, 3)
            byte_count = pdu[5]
            payload = pdu[6:6 + byte_count]
            if function_code == 16:
                values = [be16(payload, i) for i in range(0, len(payload) - 1, 2)]
            else:
                # Coils are packed LSB-first, one bit per coil.
                values = [
                    (payload[bit // 8] >> (bit % 8)) & 1
                    for bit in range(quantity)
                    if bit // 8 < len(payload)
                ]
            extracted["register_address"] = register_address
            extracted["quantity"] = quantity
            extracted["values_json"] = json.dumps(values[:quantity])

    return extracted


def parse_modbus_request(payload: bytes) -> Optional[Dict[str, Any]]:
    """Parse a Modbus TCP application data unit as a *request*, or return None.

    Returns None for anything that is not a well-formed request: non-Modbus
    protocol id, truncated MBAP/PDU, or an exception response (function code
    with the high bit set).
    """
    if len(payload) < MBAP_HEADER_LEN + 1:
        return None

    _transaction_id, protocol_id, length, unit_id = struct.unpack_from(">HHHB", payload, 0)
    if protocol_id != 0:
        return None
    # 'length' counts the unit id plus the PDU.
    if length < 2 or length > len(payload) - 6:
        return None

    pdu = payload[MBAP_HEADER_LEN:6 + length]
    if not pdu:
        return None

    function_code = pdu[0]
    if function_code & 0x80:
        return None  # exception response, not a command

    request: Dict[str, Any] = {"unit_id": unit_id, "function_code": function_code}
    request.update(decode_request_pdu(function_code, pdu))
    return request
