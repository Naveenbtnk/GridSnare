#!/usr/bin/env python3
"""GridSnare anomaly & correlation engine (SPEC.md Sections 7.3, 8 and 9).

This module owns the two pieces the monitor does not:

  * the `alerts` table and the `engine_state` watermark (SPEC.md Section 7.4);
  * DR-7, which joins the honeypot log and the monitor log, plus the polling
    loop that drives DR-1..DR-7 (SPEC.md Section 9, step 3).

SPEC.md Section 9, steps 3-4:

    3. "Correlation engine polls raw_events on an interval, applies DR-1 .. DR-7"
    4. "Matches are written to alerts with severity and rule ID"

Run it one pass at a time (useful in tests) or as a polling loop:

    python -m engine.correlator --once
    python -m engine.correlator

Nothing here hardcodes a threshold: everything comes from `engine.detection` in
config.yaml (SPEC.md Section 8).
"""

from __future__ import annotations

import argparse
import logging
import signal
import sqlite3
import sys
import threading
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from datetime import timedelta
from pathlib import Path
from typing import Any, Optional, Tuple

import yaml

# Allow both `python -m engine.correlator` and `python engine/correlator.py`.
PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from engine.rules import (  # noqa: E402  (import after the sys.path bootstrap)
    SEVERITY_CRITICAL,
    SEVERITY_HIGH,
    Alert,
    DetectionThresholds,
    RuleConfigError,
    RuleContext,
    evaluate_event,
    parse_event_timestamp,
    utc_now_iso,
)

LOG = logging.getLogger("gridsnare.engine")

DEFAULT_CONFIG_PATH = "/app/config.yaml"

# SPEC.md Section 7.4: "SQLite database, two core tables: raw_events and alerts.
# Indexed on source IP and timestamp for correlation queries."
#
# engine_state is bookkeeping rather than a domain table: it holds the watermark
# that lets the polling loop resume without re-alerting events it already judged
# and without skipping events that arrived while it was stopped.
SCHEMA = """
CREATE TABLE IF NOT EXISTS alerts (
    id                  INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp           TEXT    NOT NULL,  -- raised at, ISO-8601 UTC
    rule_id             TEXT    NOT NULL,  -- 'DR-1' .. 'DR-7' (SPEC.md Section 8)
    severity            TEXT    NOT NULL,  -- Low | Medium | High | Critical (Section 7.3)
    protocol            TEXT    NOT NULL,  -- 'modbus'; Section 20.3 reuses this for 'goose'
    src_ip              TEXT,
    dst_ip              TEXT,
    description         TEXT    NOT NULL,
    event_id            INTEGER,           -- raw_events.id that triggered the alert
    correlated_event_id INTEGER            -- DR-7: raw_events.id on the other side of the join
);
-- Makes the engine idempotent: re-judging an event (replay, or a restart that
-- re-reads an interval) cannot duplicate an alert.
CREATE UNIQUE INDEX IF NOT EXISTS idx_alerts_rule_event
    ON alerts(rule_id, event_id);
CREATE INDEX IF NOT EXISTS idx_alerts_timestamp
    ON alerts(timestamp);
CREATE INDEX IF NOT EXISTS idx_alerts_src_ip_timestamp
    ON alerts(src_ip, timestamp);
-- Dashboard severity breakdown (SPEC.md Section 7.5).
CREATE INDEX IF NOT EXISTS idx_alerts_severity
    ON alerts(severity);

CREATE TABLE IF NOT EXISTS engine_state (
    key   TEXT PRIMARY KEY,
    value TEXT NOT NULL
);
"""

INSERT_ALERT = """
INSERT OR IGNORE INTO alerts (
    timestamp, rule_id, severity, protocol, src_ip, dst_ip,
    description, event_id, correlated_event_id
) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
"""

WATERMARK_KEY = "raw_events_watermark"

# Heartbeat, so the dashboard can distinguish "nothing to detect" from "detection
# stopped". Without it the only evidence the engine exists is the watermark, which
# goes stale in lockstep with the traffic: a quiet lab and a dead engine leave the
# same fingerprint. engine_state is bookkeeping (SPEC.md Section 7.4 defines the two
# core tables), so this adds no new domain table.
LAST_POLL_KEY = "last_poll_at"


class ConfigError(Exception):
    """Raised when the engine section of config.yaml is missing or malformed."""


@dataclass(frozen=True)
class EngineConfig:
    """Validated `engine` configuration."""

    database: str
    poll_interval_seconds: float
    log_level: str
    thresholds: DetectionThresholds

    @classmethod
    def load(cls, path: str) -> "EngineConfig":
        config_path = Path(path)
        if not config_path.is_file():
            raise ConfigError(f"config file not found: {config_path}")
        try:
            document = yaml.safe_load(config_path.read_text(encoding="utf-8")) or {}
        except yaml.YAMLError as exc:
            raise ConfigError(f"{config_path} is not valid YAML: {exc}") from exc

        section = document.get("engine")
        if not isinstance(section, Mapping):
            raise ConfigError(f"{config_path} must contain an 'engine:' mapping (SPEC.md Section 7.3)")

        database = section.get("database")
        if not isinstance(database, str) or not database.strip():
            raise ConfigError("engine.database must be a non-empty path")

        interval = section.get("poll_interval_seconds", 5)
        try:
            interval = float(interval)
        except (TypeError, ValueError) as exc:
            raise ConfigError("engine.poll_interval_seconds must be a number") from exc
        if interval <= 0:
            raise ConfigError("engine.poll_interval_seconds must be greater than zero")

        return cls(
            database=database,
            poll_interval_seconds=interval,
            log_level=str(section.get("log_level") or "INFO").upper(),
            thresholds=DetectionThresholds.from_mapping(section.get("detection")),
        )


def open_database(path: str) -> sqlite3.Connection:
    """Open the shared store, creating the engine-owned tables if needed."""
    database_path = Path(path)
    database_path.parent.mkdir(parents=True, exist_ok=True)
    connection = sqlite3.connect(database_path, timeout=10.0, check_same_thread=False)
    connection.row_factory = sqlite3.Row
    # Rollback journal, not WAL: see the note in store.py. WAL's `-shm` file cannot be
    # mmap'ed across containers on this bind mount, which makes the store unopenable by
    # a second container while the monitor holds it.
    connection.execute("PRAGMA journal_mode=DELETE")
    connection.execute("PRAGMA synchronous=NORMAL")
    connection.executescript(SCHEMA)
    connection.commit()
    return connection


def raw_events_exists(connection: sqlite3.Connection) -> bool:
    """raw_events belongs to the monitor; the engine can legitimately start first."""
    row = connection.execute(
        "SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = 'raw_events' LIMIT 1"
    ).fetchone()
    return row is not None


def get_watermark(connection: sqlite3.Connection) -> int:
    row = connection.execute(
        "SELECT value FROM engine_state WHERE key = ?", (WATERMARK_KEY,)
    ).fetchone()
    if row is None:
        return 0
    try:
        return int(row["value"])
    except (TypeError, ValueError):
        LOG.warning("engine_state watermark is not an integer (%r); restarting from 0", row["value"])
        return 0


def set_watermark(connection: sqlite3.Connection, value: int) -> None:
    connection.execute(
        "INSERT INTO engine_state (key, value) VALUES (?, ?) "
        "ON CONFLICT(key) DO UPDATE SET value = excluded.value",
        (WATERMARK_KEY, str(value)),
    )
    connection.commit()


def read_state(connection: sqlite3.Connection, key: str) -> Optional[str]:
    """Read one engine_state value, or None when the key has never been written."""
    try:
        row = connection.execute(
            "SELECT value FROM engine_state WHERE key = ?", (key,)
        ).fetchone()
    except sqlite3.Error:
        return None
    return None if row is None else str(row["value"])


def record_heartbeat(connection: sqlite3.Connection) -> str:
    """Stamp a completed poll cycle. Returns the timestamp written."""
    stamp = utc_now_iso()
    connection.execute(
        "INSERT INTO engine_state (key, value) VALUES (?, ?) "
        "ON CONFLICT(key) DO UPDATE SET value = excluded.value",
        (LAST_POLL_KEY, stamp),
    )
    connection.commit()
    return stamp


def insert_alert(connection: sqlite3.Connection, alert: Alert, logger: logging.Logger = LOG) -> bool:
    """Write an alert, ignoring duplicates. True when a new row was inserted."""
    cursor = connection.execute(
        INSERT_ALERT,
        (
            utc_now_iso(), alert.rule_id, alert.severity, alert.protocol,
            alert.src_ip, alert.dst_ip, alert.description,
            alert.event_id, alert.correlated_event_id,
        ),
    )
    connection.commit()
    if cursor.rowcount == 1:
        level = logging.WARNING if alert.severity in (SEVERITY_HIGH, SEVERITY_CRITICAL) else logging.INFO
        logger.log(level, "ALERT %s [%s] %s", alert.rule_id, alert.severity, alert.description)
        return True
    logger.debug("duplicate suppressed: %s already alerted for event %s", alert.rule_id, alert.event_id)
    return False


def correlate_honeypot_and_monitor(
    event: Mapping[str, Any],
    context: RuleContext,
) -> Optional[Alert]:
    """DR-7 | Correlated hit: same source IP in both honeypot and monitor logs within N minutes | Multi-stage attack indicator | Critical

    SPEC.md Section 8 classes this as a correlation rather than a single-event
    rule: the event being judged supplies the source IP, and the *other* source's
    table rows are searched inside a window of +/- correlation_window_minutes
    around it. The window is symmetric because poll ordering says nothing about
    attack ordering — a honeypot hit and a monitor anomaly from one host are the
    correlated pair regardless of which the engine happens to read first.

    One finding per *honeypot interaction*, not per event pair and not per source host:
    a burst of monitor anomalies against a single honeypot hit collapses into one
    finding, while a second, separate honeypot hit is a *new* finding even from a host
    already seen minutes earlier. The reasoning for anchoring on the interaction rather
    than the host is at the de-duplication check below.
    """
    connection = context.connection
    thresholds = context.thresholds
    logger = context.logger

    src_ip = event.get("src_ip")
    if src_ip is None:
        return None

    source = event.get("source")
    if source == "honeypot":
        other_source = "monitor"
    elif source == "monitor":
        other_source = "honeypot"
    else:
        return None

    try:
        moment = parse_event_timestamp(event["timestamp"])
    except (KeyError, ValueError):
        logger.warning("DR-7 skipped unparseable timestamp: %r", event.get("timestamp"))
        return None

    window = timedelta(minutes=thresholds.correlation_window_minutes)
    matched = connection.execute(
        "SELECT id, timestamp, protocol FROM raw_events "
        "WHERE source = ? AND src_ip = ? AND timestamp BETWEEN ? AND ? AND id <> ? "
        "ORDER BY timestamp LIMIT 1",
        (
            other_source,
            src_ip,
            (moment - window).isoformat(timespec="milliseconds").replace("+00:00", "Z"),
            (moment + window).isoformat(timespec="milliseconds").replace("+00:00", "Z"),
            event.get("id"),
        ),
    ).fetchone()
    if matched is None:
        return None

    # De-duplication, anchored on the honeypot interaction rather than the source host.
    #
    # The finding is "this host touched the decoy and also appeared on the monitored
    # link", so the honeypot hit is its anchor. One hit can match several monitor rows
    # and one monitor row can match several hits; both collapse into a single alert here,
    # including when the same finding is reached from the other direction, since the loop
    # may judge the monitor row before the honeypot row.
    #
    # Keying on the host instead would suppress a genuinely different honeypot
    # interaction from that host for the whole window. DR-1 is per-event by design
    # (SPEC.md Section 8) and already alerts on every honeypot interaction, so anchoring
    # on the interaction keeps the anti-storm property without hiding a new finding.
    honeypot_event_id = event.get("id") if source == "honeypot" else matched["id"]
    # Which id belongs to which log, named explicitly rather than assumed: either source
    # can be judged first, so hardcoding the monitor side would mislabel the alert text
    # half the time.
    monitor_event_id = matched["id"] if source == "honeypot" else event.get("id")
    already_alerted = connection.execute(
        "SELECT 1 FROM alerts WHERE rule_id = 'DR-7' AND "
        "(event_id = ? OR correlated_event_id = ?) LIMIT 1",
        (honeypot_event_id, honeypot_event_id),
    ).fetchone()
    if already_alerted is not None:
        logger.debug(
            "DR-7 already alerted for honeypot interaction raw_events id %s "
            "(%s appears in both logs); not repeating it",
            honeypot_event_id, src_ip,
        )
        return None

    return Alert(
        rule_id="DR-7",
        severity=SEVERITY_CRITICAL,
        protocol=str(event.get("protocol") or matched["protocol"] or "modbus"),
        description=(
            f"Correlated hit: {src_ip} appears in both the honeypot log (raw_events id "
            f"{honeypot_event_id}) and the monitor log (raw_events id {monitor_event_id}) "
            f"within {thresholds.correlation_window_minutes} minute(s) — multi-stage "
            f"attack indicator"
        ),
        src_ip=src_ip,
        dst_ip=event.get("dst_ip"),
        event_id=event.get("id"),
        correlated_event_id=matched["id"],
    )


def process_new_events(
    connection: sqlite3.Connection,
    thresholds: DetectionThresholds,
    logger: logging.Logger = LOG,
) -> Tuple[int, int]:
    """Judge every event newer than the watermark. Returns (events, alerts)."""
    if not raw_events_exists(connection):
        logger.debug("raw_events does not exist yet; waiting for the monitor to write one")
        return (0, 0)

    watermark = get_watermark(connection)
    rows = connection.execute(
        "SELECT * FROM raw_events WHERE id > ? ORDER BY id", (watermark,)
    ).fetchall()
    if not rows:
        return (0, 0)

    context = RuleContext(connection=connection, thresholds=thresholds, logger=logger)
    alerts_written = 0

    for row in rows:
        event = dict(row)
        for alert in evaluate_event(event, context):
            if insert_alert(connection, alert, logger):
                alerts_written += 1
        correlated = correlate_honeypot_and_monitor(event, context)
        if correlated is not None and insert_alert(connection, correlated, logger):
            alerts_written += 1
        # Advance only after the event has been judged, so a crash mid-loop cannot
        # silently skip the events that were not yet processed.
        set_watermark(connection, int(event["id"]))

    return (len(rows), alerts_written)


def describe_thresholds(thresholds: DetectionThresholds) -> str:
    """One line summarising the configuration in force, for the startup log."""
    hours = thresholds.operational_hours
    return (
        f"allowed_function_codes={sorted(thresholds.allowed_function_codes)} "
        f"register_range={list(thresholds.operational_register_range)} "
        f"coil_range={list(thresholds.operational_coil_range)} "
        f"hours={hours.start.strftime('%H:%M')}-{hours.end.strftime('%H:%M')} {hours.zone_name} "
        f"days={sorted(hours.days) or 'any'} "
        f"known_assets={sorted(thresholds.known_asset_allow_list)} "
        f"rate_limit={thresholds.polling_rate_limit}/{thresholds.polling_window_seconds}s "
        f"correlation_window={thresholds.correlation_window_minutes}min "
        f"alert_cooldown={thresholds.alert_cooldown_seconds}s"
    )


def _parse_args(argv: Optional[Sequence[str]]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="GridSnare anomaly & correlation engine (SPEC.md Sections 7.3 and 9)"
    )
    parser.add_argument(
        "--config", default=DEFAULT_CONFIG_PATH,
        help=f"path to config.yaml (default: {DEFAULT_CONFIG_PATH})",
    )
    parser.add_argument(
        "--once", action="store_true",
        help="judge the events queued since the watermark, then exit",
    )
    parser.add_argument(
        "--from-event-id", type=int, default=None,
        help="rewind the watermark so raw_events.id >= this value is judged again "
             "(replay aid for testing; duplicate alerts are suppressed)",
    )
    return parser.parse_args(argv)


def main(argv: Optional[Sequence[str]] = None) -> int:
    args = _parse_args(argv)

    try:
        config = EngineConfig.load(args.config)
    except (ConfigError, RuleConfigError) as exc:
        print(f"configuration error: {exc}", file=sys.stderr)
        return 2

    logging.basicConfig(
        level=getattr(logging, config.log_level, logging.INFO),
        format="%(asctime)s %(levelname)s %(name)s | %(message)s",
        stream=sys.stdout,
    )

    LOG.info(
        "engine starting (SPEC.md 7.3/9): config=%s db=%s poll_interval=%ss",
        args.config, config.database, config.poll_interval_seconds,
    )
    LOG.info("thresholds in effect: %s", describe_thresholds(config.thresholds))

    connection = open_database(config.database)

    if not raw_events_exists(connection):
        LOG.warning(
            "raw_events is absent from %s — the monitor has not written an event yet",
            config.database,
        )

    if args.from_event_id is not None:
        set_watermark(connection, max(0, args.from_event_id - 1))
        LOG.info("watermark rewound to %d: replaying from raw_events.id %d",
                 max(0, args.from_event_id - 1), args.from_event_id)

    if args.once:
        events, alerts = process_new_events(connection, config.thresholds, LOG)
        record_heartbeat(connection)
        LOG.info("single pass complete: %d event(s) judged, %d alert(s) written", events, alerts)
        connection.close()
        return 0

    stop = threading.Event()

    def request_stop(signum: int, _frame: Any) -> None:
        LOG.info("received %s, shutting down", signal.Signals(signum).name)
        stop.set()

    signal.signal(signal.SIGTERM, request_stop)
    signal.signal(signal.SIGINT, request_stop)

    LOG.info("polling raw_events every %ss", config.poll_interval_seconds)
    try:
        while not stop.is_set():
            events, alerts = process_new_events(connection, config.thresholds, LOG)
            # Stamped after every cycle, including quiet ones: the heartbeat is how
            # the dashboard tells "no traffic" from "engine not running".
            record_heartbeat(connection)
            if events:
                LOG.info("poll: %d event(s) judged, %d alert(s) written", events, alerts)
            stop.wait(config.poll_interval_seconds)
    finally:
        connection.close()

    LOG.info("engine stopped")
    return 0


if __name__ == "__main__":
    sys.exit(main())
