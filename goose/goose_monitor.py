#!/usr/bin/env python3
"""GridSnare — IEC 61850 GOOSE protocol traffic monitor (SPEC.md Section 20.2).

Captures raw Ethernet multicast GOOSE frames (EtherType 0x88B8) on the lab segment
and writes one structured row per frame into the shared SQLite data store:

    SPEC.md 20.2: "Captures raw Ethernet multicast GOOSE frames (EtherType 0x88B8)
    and extracts StNum, SqNum, source MAC, GoCB reference, and timestamp — this is
    the component GR-1 through GR-4 key off, not the decoy's own receive path"

That last clause is the reason this file exists separately from the decoy. The decoy
IED hears GOOSE traffic addressed to *it*; this monitor watches the whole segment and
records what every publisher on it is saying. GR-1 (sequence violations), GR-2 (MAC
spoofing) and GR-3 (timing) all need the history of a publisher's frames, which only
a segment observer has.

Scope boundary — like the Phase 1 Modbus monitor, this module implements no detection
logic. GR-1..GR-4 live in engine/goose_rules.py (SPEC.md 20.3) and are applied by the
engine against the rows written here. This is step 1 of the SPEC.md Section 9 data
flow, applied to Phase 2's protocol:

    "Traffic monitor captures a packet -> parses fields -> writes to raw_events"

SPEC.md Section 18 (Content Integrity Policy) applies: this module reports only what
it actually observed.

Why not Scapy
-------------
The Phase 1 monitor uses Scapy, but GOOSE is not an IP protocol and there is no
Scapy layer for the GOOSE PDU. The wire format is decoded by goose/goose_frame.py,
which the decoy's subscriber and the test tooling already use. It reports the VLAN tag
the frame actually carried rather than the tag that survived the receive path.
"""

from __future__ import annotations

import argparse
import logging
import signal
import socket
import sqlite3
import sys
import threading
import time
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Optional, Sequence

import yaml

# The wire format and the store schema both live outside this file. Resolved from
# __file__ because the container runs `python -u goose/goose_monitor.py` from /app,
# which puts /app/goose — not /app — on sys.path.
for _candidate in (Path(__file__).resolve().parents[1], Path(__file__).resolve().parent):
    if (_candidate / "store.py").is_file():
        if str(_candidate) not in sys.path:
            sys.path.insert(0, str(_candidate))
        break

from goose.goose_frame import (  # noqa: E402  (import after the sys.path bootstrap)
    DecodeError,
    apply_stripped_vlan,
    decode_goose_frame,
    open_capture_socket,
    recv_frame,
)
from store import open_database  # noqa: E402

LOG = logging.getLogger("gridsnare.goose.monitor")

DEFAULT_CONFIG_PATH = "/app/config.yaml"

# How often to print a "still alive, still seeing frames" summary. This is a log
# cadence, not a detection threshold (SPEC.md Section 8 governs the latter), and it
# matches the decoy's own 30s self-report so the two containers' logs line up.
SUMMARY_INTERVAL_SECONDS = 30.0

# A GOOSE frame is multicast, so a socket that is not a member of the group never
# sees one. open_capture_socket joins with PACKET_MR_PROMISC for exactly this reason.
# The cap the service actually needs is therefore NET_RAW.

# Captured frames are committed in small batches rather than one commit per frame.
# SQLite takes an exclusive lock for the duration of every commit, and a GOOSE flood is
# hundreds of frames a second — so committing per frame held the store's write lock almost
# continuously and starved the other writer on it, the detection engine, which reported
# "database is locked" for both its alert insert and its watermark update (measured: an
# engine pass sat on one watermark update for over a minute while a flood was in flight,
# and its heartbeat went stale enough for the dashboard to call detection stopped).
# Batching cuts the lock churn by the batch size while keeping a captured frame visible to
# readers within FLUSH_INTERVAL_SECONDS: the main loop flushes once a second even when the
# segment has gone quiet, so a quiet spell cannot leave a frame uncommitted.
#
# Both bounds are needed. The count keeps a busy segment's commits from growing into a
# long-held transaction, and the interval bounds how long the newest frame stays unseen.
FLUSH_INTERVAL_SECONDS = 0.5
FLUSH_MAX_FRAMES = 25
INSERT_EVENT = """
INSERT INTO raw_events (
    timestamp, source, protocol,
    src_mac, dst_mac, app_id, gocb_ref, goid,
    st_num, sq_num, conf_rev, time_allowed_to_live_ms, vlan_id, vlan_priority
) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
"""


class ConfigError(Exception):
    """Raised when config.yaml is missing or does not describe the GOOSE monitor."""


@dataclass(frozen=True)
class GooseMonitorConfig:
    """GOOSE monitor settings (SPEC.md Section 8: tunable without touching code)."""

    interface: str
    database: str
    log_level: str

    @classmethod
    def load(cls, path: str) -> "GooseMonitorConfig":
        """Load and validate the 'goose_monitor:' section. Fails loudly, never silently.

        The GOOSE monitor reads its own section rather than reusing 'goose:' (the
        decoy's published identity) because the two are different roles: one is a
        device that publishes, the other is an observer that records. Keeping them
        separate means the decoy's bait can be re-pointed without moving the monitor,
        and vice versa. 'database' is the same path either way — the shared store.
        """
        config_path = Path(path)
        if not config_path.is_file():
            raise ConfigError(f"config file not found: {config_path}")
        try:
            document = yaml.safe_load(config_path.read_text(encoding="utf-8")) or {}
        except yaml.YAMLError as exc:
            raise ConfigError(f"{config_path} is not valid YAML: {exc}") from exc

        section = document.get("goose_monitor")
        if not isinstance(section, dict):
            raise ConfigError(
                f"{config_path} must contain a 'goose_monitor:' mapping (SPEC.md Section 20.2)"
            )

        interface = section.get("interface") or "eth0"
        if not isinstance(interface, str) or not interface.strip():
            raise ConfigError("goose_monitor.interface must be a non-empty string")

        database = section.get("database")
        if not isinstance(database, str) or not database.strip():
            raise ConfigError("goose_monitor.database must be a non-empty path")

        return cls(
            interface=interface.strip(),
            database=database.strip(),
            log_level=str(section.get("log_level") or "INFO").upper(),
        )


def utc_now_iso() -> str:
    """Capture timestamp, ISO-8601 UTC, matching the Modbus monitor's format.

    This is the time the frame was *observed*, which is what GR-3's retransmission
    timing is measured on. The PDU also carries the publisher's own `t` (its
    state-change time); that one describes the publisher's clock, not arrival here,
    so it is not what a timing rule should compare against and is not stored.
    """
    return datetime.now(timezone.utc).isoformat(timespec="milliseconds").replace("+00:00", "Z")


def frame_to_event(decoded: Dict[str, Any]) -> Dict[str, Any]:
    """Map a decoded GOOSE frame onto the raw_events columns (SPEC.md 20.2).

    Every field named in Section 20.2 comes from the frame itself. Fields the frame
    does not carry (IP addresses, ports, function code) are left NULL rather than
    filled with a stand-in: a GOOSE frame has no IP address, and putting its MAC in
    src_ip would make the store lie to every rule that queries that column.
    """
    pdu = decoded.get("pdu") or {}
    vlan = decoded.get("vlan") or {}
    return {
        "timestamp": utc_now_iso(),
        "source": "monitor",          # SPEC.md Section 9's traffic-monitor source
        "protocol": "goose",          # SPEC.md Section 20.3's protocol tag
        "src_mac": decoded.get("src_mac"),
        "dst_mac": decoded.get("dst_mac"),
        "app_id": decoded.get("app_id"),
        "gocb_ref": pdu.get("gocb_ref"),
        "goid": pdu.get("goid"),
        "st_num": pdu.get("st_num"),
        "sq_num": pdu.get("sq_num"),
        "conf_rev": pdu.get("conf_rev"),
        "time_allowed_to_live_ms": pdu.get("time_allowed_to_live_ms"),
        "vlan_id": vlan.get("id"),
        "vlan_priority": vlan.get("priority"),
    }


def summarise(event: Dict[str, Any]) -> str:
    """One readable line for the capture log (the store holds the structured row)."""
    vlan = (
        f"{event['vlan_priority']}/vid{event['vlan_id']}"
        if event["vlan_priority"] is not None
        else "none"
    )
    return (
        f"gocb={event['gocb_ref']} src={event['src_mac']} dst={event['dst_mac']} "
        f"appId=0x{event['app_id']:04x} "
        f"stNum={event['st_num']} sqNum={event['sq_num']} "
        f"confRev={event['conf_rev']} TAL={event['time_allowed_to_live_ms']}ms "
        f"vlan={vlan} at={event['timestamp']}"
    )


class GooseMonitor:
    """Turns received GOOSE frames into rows in the shared data store."""

    def __init__(
        self,
        config: GooseMonitorConfig,
        connection: sqlite3.Connection,
        logger: logging.Logger = LOG,
    ) -> None:
        self._config = config
        self._db = connection
        self._db_lock = threading.Lock()
        self._log = logger
        self.stored = 0
        self.ignored = 0          # frames on the wire that were not GOOSE
        self.undecodable = 0      # GOOSE frames this decoder could not read
        # Frames written but not yet committed (see FLUSH_INTERVAL_SECONDS above).
        self._pending = 0
        self._last_flush = time.monotonic()
        # Publishers seen, keyed by source MAC — the first thing an operator wants
        # when asking "who is talking on this segment?"
        self.publishers: Dict[str, int] = {}

    def handle_frame(self, frame: bytes, stripped_tci: Optional[int]) -> None:
        """Decode and store one captured frame. Never raises: one bad frame must not
        end capture, which is the same contract the Modbus monitor's callback keeps.
        """
        try:
            decoded = decode_goose_frame(frame)
        except DecodeError:
            # Not GOOSE (EtherType mismatch) or malformed. Both are counted and left
            # for the caller to classify as ignored vs undecodable — this method is
            # only reached for frames a caller already considers candidate GOOSE.
            raise
        apply_stripped_vlan(decoded, stripped_tci)
        self._store(frame_to_event(decoded), decoded)

    def _store(self, event: Dict[str, Any], decoded: Dict[str, Any]) -> None:
        with self._db_lock:
            self._db.execute(
                INSERT_EVENT,
                (
                    event["timestamp"], event["source"], event["protocol"],
                    event["src_mac"], event["dst_mac"], event["app_id"],
                    event["gocb_ref"], event["goid"],
                    event["st_num"], event["sq_num"], event["conf_rev"],
                    event["time_allowed_to_live_ms"], event["vlan_id"], event["vlan_priority"],
                ),
            )
            self._pending += 1
            if (self._pending >= FLUSH_MAX_FRAMES
                    or time.monotonic() - self._last_flush >= FLUSH_INTERVAL_SECONDS):
                self._flush_locked()
        self.stored += 1
        src_mac = event["src_mac"] or "unknown"
        self.publishers[src_mac] = self.publishers.get(src_mac, 0) + 1
        self._log.info("captured %s", summarise(event))

    def _flush_locked(self) -> None:
        """Commit whatever has been written. Caller holds the lock."""
        if self._pending:
            self._db.commit()
            self._pending = 0
        self._last_flush = time.monotonic()

    def flush(self) -> None:
        """Commit any frames still buffered.

        Called once per receive-loop iteration — including the iterations that time out —
        so the newest captured frame is on disk within about a second whether or not more
        traffic follows it.
        """
        with self._db_lock:
            self._flush_locked()


def _parse_args(argv: Optional[Sequence[str]]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="GridSnare IEC 61850 GOOSE traffic monitor (SPEC.md Section 20.2)"
    )
    parser.add_argument(
        "--config",
        default=DEFAULT_CONFIG_PATH,
        help=f"path to config.yaml (default: {DEFAULT_CONFIG_PATH})",
    )
    parser.add_argument(
        "--seconds",
        type=float,
        default=0.0,
        help="stop after this many seconds (0 = run until SIGTERM/SIGINT)",
    )
    return parser.parse_args(argv)


def main(argv: Optional[Sequence[str]] = None) -> int:
    args = _parse_args(argv)

    try:
        config = GooseMonitorConfig.load(args.config)
    except ConfigError as exc:
        print(f"configuration error: {exc}", file=sys.stderr)
        return 2

    logging.basicConfig(
        level=getattr(logging, config.log_level, logging.INFO),
        format="%(asctime)s %(levelname)s %(name)s | %(message)s",
        stream=sys.stdout,
    )

    LOG.info(
        "GOOSE monitor starting (SPEC.md 20.2): config=%s iface=%s db=%s",
        args.config, config.interface, config.database,
    )

    connection = open_database(config.database)

    # Fail loudly if the capture socket cannot be opened: a monitor that runs while
    # seeing nothing reports "no GOOSE traffic" for a busy segment, which is worse
    # than not starting. This is the same refusal the Modbus monitor makes.
    try:
        capture = open_capture_socket(config.interface)
    except OSError as exc:
        LOG.error(
            "cannot open a capture socket on %s: %s — refusing to run while monitoring "
            "nothing (the service needs CAP_NET_RAW)",
            config.interface, exc,
        )
        connection.close()
        return 1

    # A timeout turns recv_frame into a poll so the loop can notice a stop request and
    # emit its summary, while still blocking cheaply between frames.
    capture.settimeout(1.0)

    monitor = GooseMonitor(config, connection)

    stop = threading.Event()

    def request_stop(signum: int, _frame: Any) -> None:
        LOG.info("received %s, shutting down", signal.Signals(signum).name)
        stop.set()

    signal.signal(signal.SIGTERM, request_stop)
    signal.signal(signal.SIGINT, request_stop)

    LOG.info(
        "capture running on %s; waiting for GOOSE frames (EtherType 0x88B8)", config.interface
    )

    deadline = time.monotonic() + args.seconds if args.seconds > 0 else None
    next_summary = time.monotonic() + SUMMARY_INTERVAL_SECONDS

    try:
        while not stop.is_set():
            if deadline is not None and time.monotonic() >= deadline:
                LOG.info("reached --seconds %.1f, stopping", args.seconds)
                break
            try:
                frame, stripped_tci = recv_frame(capture)
            except socket.timeout:
                pass
            except OSError as exc:
                LOG.error("capture socket failed: %s", exc)
                break
            else:
                try:
                    monitor.handle_frame(frame, stripped_tci)
                except DecodeError as exc:
                    # A frame that reached the socket but is not a readable GOOSE PDU.
                    # Counted rather than logged per frame: a malformed stream must not
                    # bury the real captures, but silence about it would be a lie.
                    monitor.undecodable += 1
                    monitor.ignored += 1
                    LOG.debug("undecodable frame ignored: %s", exc)
                except Exception:  # noqa: BLE001 — deliberately broad, see below
                    # Same contract as the Modbus monitor's packet callback: one bad
                    # frame must never end capture on a monitored segment. A store
                    # hiccup on one frame is worth a traceback, not a blind segment.
                    LOG.exception("failed to store a GOOSE frame; capture continues")

            now = time.monotonic()
            monitor.flush()
            if now >= next_summary:
                _log_summary(monitor, LOG)
                next_summary = now + SUMMARY_INTERVAL_SECONDS
    finally:
        monitor.flush()
        capture.close()
        connection.close()

    _log_summary(monitor, LOG)
    LOG.info(
        "capture stopped: %d GOOSE frame(s) stored, %d undecodable frame(s) ignored",
        monitor.stored, monitor.undecodable,
    )
    return 0


def _log_summary(monitor: GooseMonitor, logger: logging.Logger) -> None:
    """Print the running totals, including who has been seen publishing."""
    seen = ", ".join(
        f"{mac} ({count})"
        for mac, count in sorted(monitor.publishers.items(), key=lambda item: -item[1])
    )
    logger.info(
        "stored %d GOOSE frame(s) so far from %d publisher(s)%s",
        monitor.stored,
        len(monitor.publishers),
        f": {seen}" if seen else " (none yet)",
    )


if __name__ == "__main__":
    sys.exit(main())
