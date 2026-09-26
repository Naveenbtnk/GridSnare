#!/usr/bin/env python3
"""GridSnare — honeypot interaction ingester (SPEC.md Section 9, step 2).

SPEC.md Section 9 describes two feeds into the store, not one:

    1. "Traffic monitor captures a packet -> parses fields -> writes to raw_events"
    2. "In parallel, any honeypot interaction is logged to raw_events with
        source=honeypot"

Step 1 is monitor/traffic_monitor.py, which sees an exchange from the wire. Step 2
is this component, and it is deliberately not the same thing. The monitor knows what
a client *sent*; the decoy knows what it *received, interpreted and answered* — its
own log records the request bytes, the slave id, the function code Conpot decoded and
the response it sent. Those are two independent observers of one event, and SPEC.md
Section 9 step 2 asks for both. DR-7 (Section 8) is built on that: it correlates a
host seen in the honeypot log with a host seen in the monitor log.

What "interaction" means here, precisely
----------------------------------------
Conpot's log carries several line shapes. The ones naming a peer are:

    Modbus traffic from 172.20.0.5: {'request': ..., 'slave_id': 1, ...}
    New modbus session from 172.20.0.5 (uuid)
    New Modbus connection from 172.20.0.5:<port>. (uuid)

Only the ``Modbus traffic from`` line is a *protocol command* — it carries the request
bytes and the function code, which is what SPEC.md Section 7.1 means by "protocol
commands issued", and what a DR rule can reason about. Bare TCP connections and empty
sessions are therefore not written to the store; that scope is recorded as a known gap
in the README rather than silently implied as full coverage.

The source *port* is deliberately left NULL. The interaction line does not carry one,
and the connection lines that do share a session uuid with several different ports, so
picking one of them would be a guess. A NULL says "unknown"; a wrong number would say
something false to every reader of the table, including DR-7's own queries.

Real-time tailing, and restarts
-------------------------------
The decoy appends to a file, so this follows it the way ``tail -f`` does. The offset it
has consumed is kept in a small state file under the data volume, so a restart resumes
where it stopped instead of either replaying the whole log (which would fabricate a
burst of DR-1 Critical alerts from history) or silently skipping whatever happened
while it was down. On the very first run there is no offset, and it starts at the end
of the file: the log predating this component is not evidence this component gathered,
so it is not ingested. Both choices are logged at startup rather than left implicit.

Timestamp
---------
Conpot writes local time. In this lab the honeypot container runs with ``localtime``
set to UTC, the same basis the monitor stamps its rows with, so the two are directly
comparable — and DR-7 compares them. The ingested timestamp is therefore tagged UTC; a
deployment whose decoy logs in another zone would need this conversion revisited.
"""

from __future__ import annotations

import argparse
import ast
import logging
import os
import re
import signal
import sqlite3
import sys
import threading
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable, Dict, Optional, Sequence

import yaml

# Both the store schema and the Modbus decoder are shared with components that run in
# other images, so they live at the repository root; see store.py and modbus_codec.py.
# This search makes the import work in the container (both sit in /app) and from the
# repository tree.
for _candidate in (Path(__file__).resolve().parent, Path(__file__).resolve().parents[1]):
    if (_candidate / "store.py").is_file():
        if str(_candidate) not in sys.path:
            sys.path.insert(0, str(_candidate))
        break

from modbus_codec import FUNCTION_NAMES, parse_modbus_request  # noqa: E402
from store import open_database  # noqa: E402

LOG = logging.getLogger("gridsnare.honeypot_ingest")

DEFAULT_CONFIG_PATH = "/app/config.yaml"

# One Conpot Modbus interaction, e.g.
#
#   2026-09-23 16:36:36,253 Modbus traffic from 172.20.0.5: {'request':
#   b'0002000000060106003b4242', 'slave_id': 1, 'function_code': 6,
#   'response': b'8602'} (2006d9df-898b-408d-a466-d0b61bd5c3c2)
#
# The trailing paren group is Conpot's per-session uuid. It is captured so the pattern
# is anchored to the end of the line rather than ending mid-record on a stray brace,
# and then deliberately not persisted — the store has no session column and no rule
# needs one.
INTERACTION_PATTERN = re.compile(
    r"^(?P<timestamp>\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2},\d{3}) "
    r"Modbus traffic from (?P<src_ip>[0-9]{1,3}(?:\.[0-9]{1,3}){3}): "
    r"(?P<payload>\{.*\}) \((?P<session>[0-9a-fA-F-]{36})\)\s*$"
)

CONPOT_TIMESTAMP_FORMAT = "%Y-%m-%d %H:%M:%S,%f"

# Same column list the Modbus monitor inserts, so a honeypot row and a monitor row for
# one exchange differ in content, never in shape. The GOOSE columns sharing the table
# take their NULL default on a Modbus row.
INSERT_INTERACTION = """
INSERT INTO raw_events (
    timestamp, source, protocol, src_ip, src_port, dst_ip, dst_port,
    unit_id, function_code, register_address, quantity, value, values_json
) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
"""


class ConfigError(Exception):
    """Raised when config.yaml is missing or does not describe the ingester."""


@dataclass(frozen=True)
class IngestConfig:
    """Ingester settings read from config.yaml (SPEC.md Section 8: no hardcoding)."""

    log_path: str
    database: str
    state_path: str
    decoy_address: str
    decoy_port: int
    poll_interval_seconds: float
    log_level: str

    @classmethod
    def load(cls, path: str) -> "IngestConfig":
        """Load and validate the 'honeypot_ingest:' section. Fails loudly, never silently.

        A bad path or a missing section is a hard error on purpose: an ingester that
        started while tailing nothing would report "no honeypot events", which reads
        exactly like a quiet network instead of a broken component.
        """
        config_path = Path(path)
        if not config_path.is_file():
            raise ConfigError(f"config file not found: {config_path}")
        try:
            document = yaml.safe_load(config_path.read_text(encoding="utf-8")) or {}
        except yaml.YAMLError as exc:
            raise ConfigError(f"{config_path} is not valid YAML: {exc}") from exc

        section = document.get("honeypot_ingest")
        if not isinstance(section, dict):
            raise ConfigError(
                f"{config_path} must contain a 'honeypot_ingest:' mapping (SPEC.md Section 9 step 2)"
            )

        def required_text(key: str) -> str:
            value = section.get(key)
            if not isinstance(value, str) or not value.strip():
                raise ConfigError(f"honeypot_ingest.{key} must be a non-empty path")
            return value

        try:
            decoy_port = int(section["decoy_port"])
        except KeyError as exc:
            raise ConfigError("honeypot_ingest.decoy_port is required") from exc
        except (TypeError, ValueError) as exc:
            raise ConfigError("honeypot_ingest.decoy_port must be an integer") from exc
        if not 1 <= decoy_port <= 65535:
            raise ConfigError(f"honeypot_ingest.decoy_port out of range: {decoy_port}")

        decoy_address = section.get("decoy_address")
        if not isinstance(decoy_address, str) or not decoy_address.strip():
            raise ConfigError("honeypot_ingest.decoy_address must be a non-empty address")

        try:
            poll_interval = float(section.get("poll_interval_seconds", 0.5))
        except (TypeError, ValueError) as exc:
            raise ConfigError("honeypot_ingest.poll_interval_seconds must be a number") from exc
        if poll_interval <= 0:
            raise ConfigError("honeypot_ingest.poll_interval_seconds must be greater than zero")

        return cls(
            log_path=required_text("log_path"),
            database=required_text("database"),
            state_path=required_text("state_path"),
            decoy_address=decoy_address,
            decoy_port=decoy_port,
            poll_interval_seconds=poll_interval,
            log_level=str(section.get("log_level") or "INFO").upper(),
        )


def utc_iso(timestamp: datetime) -> str:
    """Store timestamp: ISO-8601 UTC, the same shape the monitor writes."""
    return timestamp.isoformat(timespec="milliseconds").replace("+00:00", "Z")


def decode_conpot_bytes(value: Any) -> Optional[bytes]:
    """Decode one of Conpot's `request`/`response` fields into the bytes it names.

    Conpot renders the Modbus application data unit as *hex text* held in a bytes
    object, so the log reads ``b'0002000000060106003b4242'`` — 24 ASCII characters, not
    the 12 bytes they denote.    Feeding that repr straight to the wire decoder yields nothing, because the first two
    'bytes' 0x30 0x30 are the characters '0' and '0' and the MBAP protocol id is then not
    zero, so every field taken from the ADU is lost (the function code survives, because
    Conpot states it separately).

    Returns None for anything that is not hex text, so an unexpected encoding degrades
    to "function code only" rather than to a wrong address.
    """
    if not isinstance(value, (bytes, bytearray)):
        return None
    try:
        return bytes.fromhex(bytes(value).decode("ascii"))
    except (UnicodeDecodeError, ValueError):
        return None


def parse_interaction(line: str, logger: logging.Logger = LOG) -> Optional[Dict[str, Any]]:
    """Turn one Conpot log line into a raw_events row, or return None.

    Returns None for every line that is not a Modbus interaction — startup banners,
    protocol registrations, session and connection lines — which is the common case and
    not an error.
    """
    match = INTERACTION_PATTERN.match(line)
    if match is None:
        return None

    try:
        fields = ast.literal_eval(match.group("payload"))
    except (ValueError, SyntaxError):
        # Conpot writes a Python literal; anything else is a line we cannot vouch for.
        logger.warning("unparseable interaction payload: %r", match.group("payload")[:120])
        return None
    if not isinstance(fields, dict):
        logger.warning("interaction payload is not a mapping: %r", type(fields).__name__)
        return None

    try:
        moment = datetime.strptime(match.group("timestamp"), CONPOT_TIMESTAMP_FORMAT)
    except ValueError:
        logger.warning("unparseable timestamp in log line: %r", match.group("timestamp"))
        return None

    # Conpot logs the application data unit as hex text (see decode_conpot_bytes); once
    # decoded it is byte-for-byte the same layout the monitor parses off the wire, which
    # is why the decoder itself is shared rather than reimplemented here.
    request_adu = decode_conpot_bytes(fields.get("request"))
    decoded: Dict[str, Any] = {}
    if request_adu is not None:
        decoded = parse_modbus_request(request_adu) or {}

    logged_function_code = fields.get("function_code")
    function_code = decoded.get("function_code", logged_function_code)
    if (
        decoded
        and isinstance(logged_function_code, int)
        and decoded["function_code"] != logged_function_code
    ):
        # The decoy's own record and its request bytes disagree. Keep both visible: the
        # decoded value is what the wire says, and the mismatch is worth an operator's
        # attention rather than being quietly resolved.
        logger.warning(
            "function code mismatch for %s: log says %s, request bytes decode to %s",
            match.group("src_ip"), logged_function_code, decoded["function_code"],
        )

    return {
        "timestamp": utc_iso(moment.replace(tzinfo=timezone.utc)),
        "source": "honeypot",
        "protocol": "modbus",
        "src_ip": match.group("src_ip"),
        # See the module docstring: the interaction line carries no source port and the
        # session uuid does not determine one, so NULL is the only truthful value.
        "src_port": None,
        "dst_ip": None,   # filled from the configured decoy identity by the caller
        "dst_port": None,
        "unit_id": decoded.get("unit_id", fields.get("slave_id")),
        "function_code": function_code,
        "register_address": decoded.get("register_address"),
        "quantity": decoded.get("quantity"),
        "value": decoded.get("value"),
        "values_json": decoded.get("values_json"),
    }


def summarise(event: Dict[str, Any]) -> str:
    """One readable line for the ingest log (the store holds the structured row)."""
    function_code = event["function_code"]
    written = event["values_json"] if event["values_json"] is not None else event["value"]
    return (
        f"src={event['src_ip']} dst={event['dst_ip']}:{event['dst_port']} "
        f"unit={event['unit_id']} fc={function_code}"
        f"({FUNCTION_NAMES.get(function_code, 'unlisted')})"
        f" reg={event['register_address']} qty={event['quantity']} value={written}"
        f" at={event['timestamp']}"
    )


class HoneypotIngest:
    """Turns Conpot log lines into ``source='honeypot'`` rows in the shared store."""

    def __init__(
        self,
        config: IngestConfig,
        connection: sqlite3.Connection,
        logger: logging.Logger = LOG,
    ) -> None:
        self._config = config
        self._db = connection
        self._db_lock = threading.Lock()
        self._log = logger
        self.stored = 0
        self.ignored = 0

    def handle_line(self, line: str) -> None:
        """Ingest one line. Never raises: one odd line must not end ingestion."""
        try:
            self._process(line)
        except Exception:  # noqa: BLE001 — deliberate catch-all, see docstring
            self._log.exception("failed to ingest a log line; tailing continues")

    def _process(self, line: str) -> None:
        event = parse_interaction(line, self._log)
        if event is None:
            self.ignored += 1
            return

        # The log names the peer but not the decoy; the decoy's identity is configuration,
        # not something to infer from a log line. Recorded so a honeypot row is as readable
        # as a monitor row rather than being half-empty.
        event["dst_ip"] = self._config.decoy_address
        event["dst_port"] = self._config.decoy_port

        with self._db_lock:
            self._db.execute(
                INSERT_INTERACTION,
                (
                    event["timestamp"], event["source"], event["protocol"],
                    event["src_ip"], event["src_port"], event["dst_ip"], event["dst_port"],
                    event["unit_id"], event["function_code"], event["register_address"],
                    event["quantity"], event["value"], event["values_json"],
                ),
            )
            self._db.commit()
        self.stored += 1
        self._log.info("ingested honeypot interaction: %s", summarise(event))


class LogTailer:
    """Follows an appended log file, resuming across restarts.

    Deliberately not a generic file watcher: this is the narrow set of behaviours the
    ingester needs, each chosen for a failure mode it prevents.

      * first run starts at end-of-file, so a pre-existing log is never replayed as if
        this component had just observed it;
      * the consumed offset is persisted per line, so a restart resumes rather than
        skipping history or duplicating it;
      * a file that shrinks (log rotation or truncation) restarts from the beginning of
        the new file instead of reading past its end forever.
    """

    def __init__(
        self,
        path: str,
        state_path: str,
        poll_interval_seconds: float,
        logger: logging.Logger = LOG,
    ) -> None:
        self._path = Path(path)
        self._state_path = Path(state_path)
        self._poll = poll_interval_seconds
        self._log = logger
        self._announced_wait = False

    # --- offset state ------------------------------------------------------

    def _read_offset(self) -> Optional[int]:
        try:
            raw = self._state_path.read_text(encoding="ascii").strip()
        except OSError:
            return None
        if not raw:
            return None
        try:
            offset = int(raw)
        except ValueError:
            self._log.warning("ignoring unreadable offset state in %s: %r", self._state_path, raw)
            return None
        return offset if offset >= 0 else None

    def _write_offset(self, offset: int) -> None:
        try:
            self._state_path.parent.mkdir(parents=True, exist_ok=True)
            self._state_path.write_text(str(offset), encoding="ascii")
        except OSError:
            # Losing the offset is survivable: the worst case is that a later restart
            # resumes from an older offset and re-ingests some lines. Failing ingestion
            # because a bookkeeping file is unwritable would be a worse trade.
            self._log.warning("could not persist tail offset to %s", self._state_path)

    # --- tailing -----------------------------------------------------------

    def _wait_for_file(self, stop: threading.Event) -> bool:
        while not self._path.is_file():
            if not self._announced_wait:
                self._log.info("waiting for %s to appear (the decoy creates it at startup)", self._path)
                self._announced_wait = True
            if stop.wait(self._poll):
                return False
        return True

    def run(self, handle_line: Callable[[str], None], stop: threading.Event) -> None:
        """Tail until `stop` is set, calling `handle_line` for every complete line."""
        while not stop.is_set():
            if not self._wait_for_file(stop):
                return

            with open(self._path, "rb") as handle:  # binary: byte offsets stay exact
                offset = self._read_offset()
                if offset is None:
                    handle.seek(0, os.SEEK_END)
                    self._log.info(
                        "first run: starting at the end of %s (offset %d) — the log's "
                        "earlier history is not backfilled",
                        self._path, handle.tell(),
                    )
                else:
                    handle.seek(offset)
                    self._log.info("resuming %s at byte offset %d", self._path, offset)
                self._write_offset(handle.tell())
                self._announced_wait = False

                buffer = b""
                while not stop.is_set():
                    chunk = handle.read(65536)
                    if not chunk:
                        if self._shrunk(handle):
                            break  # reopen and restart from the new file's beginning
                        stop.wait(self._poll)
                        continue

                    buffer += chunk
                    while b"\n" in buffer:
                        raw_line, buffer = buffer.split(b"\n", 1)
                        handle_line(raw_line.decode("utf-8", "replace"))
                        # Persisted per line, not per chunk: the alternative re-reads and
                        # re-ingests whole chunks after an unclean stop, and a duplicated
                        # honeypot row is a fabricated DR-1 alert.
                        self._write_offset(handle.tell() - len(buffer))

    def _shrunk(self, handle: Any) -> bool:
        """True if the file is now shorter than what has been consumed."""
        try:
            size = self._path.stat().st_size
        except OSError:
            return False
        if size >= handle.tell():
            return False
        self._log.warning(
            "%s is shorter than the consumed offset (%d < %d) — treating it as rotated or "
            "truncated and restarting from the beginning of the new file",
            self._path, size, handle.tell(),
        )
        self._write_offset(0)
        return True


def _parse_args(argv: Optional[Sequence[str]]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="GridSnare honeypot interaction ingester (SPEC.md Section 9 step 2)"
    )
    parser.add_argument(
        "--config",
        default=DEFAULT_CONFIG_PATH,
        help=f"path to config.yaml (default: {DEFAULT_CONFIG_PATH})",
    )
    return parser.parse_args(argv)


def main(argv: Optional[Sequence[str]] = None) -> int:
    args = _parse_args(argv)

    try:
        config = IngestConfig.load(args.config)
    except ConfigError as exc:
        print(f"configuration error: {exc}", file=sys.stderr)
        return 2

    logging.basicConfig(
        level=getattr(logging, config.log_level, logging.INFO),
        format="%(asctime)s %(levelname)s %(name)s | %(message)s",
        stream=sys.stdout,
    )

    LOG.info(
        "honeypot ingester starting (SPEC.md Section 9 step 2): config=%s log=%s db=%s state=%s",
        args.config, config.log_path, config.database, config.state_path,
    )
    LOG.info(
        "decoy identity for recorded destinations: %s:%d (configuration, not inferred "
        "from the log — the log names the peer only)",
        config.decoy_address, config.decoy_port,
    )

    connection = open_database(config.database)
    ingest = HoneypotIngest(config, connection)
    tailer = LogTailer(config.log_path, config.state_path, config.poll_interval_seconds)

    stop = threading.Event()

    def request_stop(signum: int, _frame: Any) -> None:
        LOG.info("received %s, shutting down", signal.Signals(signum).name)
        stop.set()

    signal.signal(signal.SIGTERM, request_stop)
    signal.signal(signal.SIGINT, request_stop)

    try:
        tailer.run(ingest.handle_line, stop)
    finally:
        connection.close()

    LOG.info(
        "ingest stopped: %d interaction(s) stored, %d non-interaction line(s) ignored",
        ingest.stored, ingest.ignored,
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
