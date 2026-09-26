#!/usr/bin/env python3
"""GridSnare — Modbus TCP protocol traffic monitor (SPEC.md Section 7.2).

Captures live Modbus TCP packets with Scapy, extracts source/destination IP,
function code, register address, value and timestamp from each request, and
writes one structured row per request into the shared SQLite data store
(SPEC.md Section 7.4: the ``raw_events`` table, indexed on source IP and
timestamp for the correlation queries DR-7 needs).

Scope boundary — this file implements no detection logic. DR-1..DR-7 live in
engine/rules.py and engine/correlator.py (SPEC.md Section 8) and are applied by
the engine against the rows written here. This is step 1 of the SPEC.md
Section 9 data flow:

    "Traffic monitor captures a packet -> parses fields -> writes to raw_events"

SPEC.md Section 18 (Content Integrity Policy) applies: this module reports only
what it actually observed.

Deployment note (see docker-compose.yml) — the monitor shares the honeypot's
network namespace. A Docker bridge does not deliver unicast traffic between two
other containers to a third container, so a monitor holding its own IP address
captures nothing on this segment; sharing the decoy's eth0 is the container
equivalent of a SPAN/mirror port on the decoy's link. Concretely:

  * captured     : both directions of every Modbus exchange the decoy takes part in
  * not captured : unicast between two other containers that never touches the decoy

A real deployment would mirror or route the monitored segment instead.
"""

from __future__ import annotations

import argparse
import logging
import signal
import sqlite3
import sys
import threading
import time
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Optional, Sequence

import yaml
from scapy.all import IP, TCP, AsyncSniffer, Raw

# The raw_events schema is shared with the Phase 2 GOOSE monitor, which runs in a
# different image, so it lives in store.py rather than here — see that module for why
# one copy beats two. The path search lets the import work both in the container (where
# this file and store.py both sit in /app) and from the repository tree.
for _candidate in (Path(__file__).resolve().parent, Path(__file__).resolve().parents[1]):
    if (_candidate / "store.py").is_file():
        if str(_candidate) not in sys.path:
            sys.path.insert(0, str(_candidate))
        break

from store import open_database  # noqa: E402  (import after the sys.path bootstrap)

# The Modbus request decoder is shared with honeypot/log_ingest.py, which transcribes
# the very same exchange out of Conpot's own log (SPEC.md Section 9 step 2). One copy,
# so the source='monitor' row and the source='honeypot' row for one exchange cannot
# describe it differently — see modbus_codec.py for why that matters (DR-7).
from modbus_codec import FUNCTION_NAMES, parse_modbus_request  # noqa: E402

LOG = logging.getLogger("gridsnare.monitor")

DEFAULT_CONFIG_PATH = "/app/config.yaml"

# The raw_events schema lives in store.py, because the GOOSE monitor writes the same
# table from another image. INSERT_EVENT still names every
# Modbus column explicitly, so it is unaffected by the GOOSE columns sharing the table —
# they take their NULL default on a Modbus row.
INSERT_EVENT = """
INSERT INTO raw_events (
    timestamp, source, protocol, src_ip, src_port, dst_ip, dst_port,
    unit_id, function_code, register_address, quantity, value, values_json
) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
"""


class ConfigError(Exception):
    """Raised when config.yaml is missing or does not describe the monitor."""


@dataclass(frozen=True)
class MonitorConfig:
    """Monitor settings read from config.yaml (SPEC.md Section 8: no hardcoding)."""

    modbus_ports: frozenset
    interface: str
    database: str
    log_level: str

    @classmethod
    def load(cls, path: str) -> "MonitorConfig":
        """Load and validate the 'monitor:' section. Fails loudly, never silently.

        Missing or malformed configuration is a hard error on purpose: a monitor
        that quietly starts up watching the wrong port would report "no events"
        for a busy network, which is worse than not starting at all.
        """
        config_path = Path(path)
        if not config_path.is_file():
            raise ConfigError(f"config file not found: {config_path}")
        try:
            document = yaml.safe_load(config_path.read_text(encoding="utf-8")) or {}
        except yaml.YAMLError as exc:
            raise ConfigError(f"{config_path} is not valid YAML: {exc}") from exc

        section = document.get("monitor")
        if not isinstance(section, dict):
            raise ConfigError(
                f"{config_path} must contain a 'monitor:' mapping (SPEC.md Section 7.2)"
            )

        ports = section.get("modbus_ports")
        if not isinstance(ports, list) or not ports:
            raise ConfigError("monitor.modbus_ports must be a non-empty list of TCP ports")
        try:
            parsed_ports = frozenset(int(port) for port in ports)
        except (TypeError, ValueError) as exc:
            raise ConfigError("monitor.modbus_ports must contain integers") from exc
        invalid = sorted(port for port in parsed_ports if not 1 <= port <= 65535)
        if invalid:
            raise ConfigError(f"monitor.modbus_ports has out-of-range port(s): {invalid}")

        database = section.get("database")
        if not isinstance(database, str) or not database.strip():
            raise ConfigError("monitor.database must be a non-empty path")

        return cls(
            modbus_ports=parsed_ports,
            interface=str(section.get("interface") or "eth0"),
            database=database,
            log_level=str(section.get("log_level") or "INFO").upper(),
        )


def utc_now_iso() -> str:
    """Capture timestamp, ISO-8601 UTC. Stored as UTC text, which sorts correctly.

    DR-4 (off-hours access) will need local time; the engine must convert using a
    configured timezone rather than this monitor writing local time, so that the
    store stays unambiguous.
    """
    return datetime.now(timezone.utc).isoformat(timespec="milliseconds").replace("+00:00", "Z")


def summarise(event: Dict[str, Any]) -> str:
    """One readable line for the capture log (the store holds the structured row)."""
    function_code = event["function_code"]
    written = event["values_json"] if event["values_json"] is not None else event["value"]
    return (
        f"src={event['src_ip']}:{event['src_port']} dst={event['dst_ip']}:{event['dst_port']} "
        f"unit={event['unit_id']} fc={function_code}"
        f"({FUNCTION_NAMES.get(function_code, 'unlisted')})"
        f" reg={event['register_address']} qty={event['quantity']} value={written}"
        f" at={event['timestamp']}"
    )


class TrafficMonitor:
    """Turns captured packets into rows in the shared data store."""

    def __init__(
        self,
        config: MonitorConfig,
        connection: sqlite3.Connection,
        logger: logging.Logger = LOG,
    ) -> None:
        self._config = config
        self._db = connection
        self._db_lock = threading.Lock()
        self._log = logger
        self.stored = 0
        self.ignored = 0

    def handle_packet(self, packet: Any) -> None:
        """Scapy callback. Never raises: one malformed frame must not end capture."""
        try:
            self._process(packet)
        except Exception:  # noqa: BLE001 — deliberate catch-all, see docstring
            self._log.exception("failed to process a captured packet; capture continues")

    def _process(self, packet: Any) -> None:
        if IP not in packet or TCP not in packet:
            return

        raw_layer = packet.getlayer(Raw)
        if raw_layer is None:
            return

        tcp_layer = packet[TCP]
        src_port, dst_port = int(tcp_layer.sport), int(tcp_layer.dport)

        if dst_port in self._config.modbus_ports:
            pass  # request: client -> Modbus server
        elif src_port in self._config.modbus_ports:
            # A response is not a command, and DR-2..DR-6 classify commands.
            self.ignored += 1
            self._log.debug(
                "ignoring Modbus response %s:%s -> %s:%s",
                packet[IP].src, src_port, packet[IP].dst, dst_port,
            )
            return
        else:
            return

        payload = bytes(raw_layer.load)
        request = parse_modbus_request(payload)
        if request is None:
            self.ignored += 1
            self._log.debug(
                "Modbus-port traffic that is not a request PDU (%d bytes) from %s:%s",
                len(payload), packet[IP].src, src_port,
            )
            return

        event = {
            "timestamp": utc_now_iso(),
            "source": "monitor",
            "protocol": "modbus",
            "src_ip": str(packet[IP].src),
            "src_port": src_port,
            "dst_ip": str(packet[IP].dst),
            "dst_port": dst_port,
        }
        event.update(request)
        self._store(event)

    def _store(self, event: Dict[str, Any]) -> None:
        with self._db_lock:
            self._db.execute(
                INSERT_EVENT,
                (
                    event["timestamp"], event["source"], event["protocol"],
                    event["src_ip"], event["src_port"], event["dst_ip"], event["dst_port"],
                    event["unit_id"], event["function_code"], event["register_address"],
                    event["quantity"], event["value"], event["values_json"],
                ),
            )
            self._db.commit()
        self.stored += 1
        self._log.info("captured %s", summarise(event))


def _parse_args(argv: Optional[Sequence[str]]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="GridSnare Modbus TCP traffic monitor (SPEC.md Section 7.2)"
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
        config = MonitorConfig.load(args.config)
    except ConfigError as exc:
        print(f"configuration error: {exc}", file=sys.stderr)
        return 2

    logging.basicConfig(
        level=getattr(logging, config.log_level, logging.INFO),
        format="%(asctime)s %(levelname)s %(name)s | %(message)s",
        stream=sys.stdout,
    )

    LOG.info(
        "monitor starting (SPEC.md 7.2): config=%s iface=%s modbus_ports=%s db=%s",
        args.config, config.interface, sorted(config.modbus_ports), config.database,
    )
    LOG.info(
        "capture mode: this container shares the network namespace of the device it "
        "watches (see docker-compose.yml), so it sees both directions of every Modbus "
        "exchange that device takes part in — the decoy's link for the `monitor` "
        "service and the legitimate PLC's for `monitor-plc`"
    )

    connection = open_database(config.database)
    monitor = TrafficMonitor(config, connection)

    stop = threading.Event()

    def request_stop(signum: int, _frame: Any) -> None:
        LOG.info("received %s, shutting down", signal.Signals(signum).name)
        stop.set()

    signal.signal(signal.SIGTERM, request_stop)
    signal.signal(signal.SIGINT, request_stop)

    # promisc=False is sufficient here: on the decoy's own interface the Modbus
    # frames are addressed to that interface, so nothing needs promiscuous mode.
    sniffer = AsyncSniffer(
        iface=config.interface,
        prn=monitor.handle_packet,
        store=False,
        promisc=False,
    )
    sniffer.start()
    time.sleep(1.0)

    startup_error = getattr(sniffer, "exception", None)
    if startup_error is not None or not getattr(sniffer, "running", False):
        LOG.error(
            "capture did not start on %s: %r — refusing to run while monitoring nothing",
            config.interface, startup_error,
        )
        connection.close()
        return 1

    LOG.info("capture running on %s; waiting for Modbus traffic", config.interface)

    try:
        while not stop.is_set():
            stop.wait(1.0)
    finally:
        if getattr(sniffer, "running", False):
            sniffer.stop()
        connection.close()

    LOG.info(
        "capture stopped: %d event(s) stored, %d packet(s) ignored",
        monitor.stored, monitor.ignored,
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
