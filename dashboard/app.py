#!/usr/bin/env python3
"""GridSnare alert dashboard (SPEC.md Section 7.5).

Flask app reading the shared SQLite data store (SPEC.md Section 7.4) and rendering
the four views Section 7.5 requires:

    "Views: live alert feed, severity breakdown chart, timeline, honeypot vs.
     monitor event split"

Data flow position — SPEC.md Section 9, step 5: "Dashboard queries alerts and
raw_events for display, refreshing on a short interval." The browser polls
/api/dashboard every `refresh_seconds`.

Every number on the page comes from the store the monitor and the engine actually
wrote. There is no mock or sample data in this file: if the store is missing,
empty or not yet created, the page says exactly that instead of inventing rows.

Section 7.5 limitation, quoted verbatim: "No authentication needed for a local lab
demo; note this as a limitation if extended beyond localhost." This app binds
0.0.0.0 inside its own container while docker-compose.yml publishes it on
127.0.0.1 only, and the page states the limitation in its header.

Beyond SPEC.md Section 7.5's four views there is a fifth block, `pipeline`: per
source capture freshness plus the engine's watermark and heartbeat. It exists
because the four required views all answer "what was detected" and none answers
"is the sensor still reporting" — every count on the page looks calm while the
monitor, the decoy, or the engine is dead, since the store just stops growing.
See the comment above fetch_pipeline for how each state is derived and ranked.

Deployment note (docker-compose.yml): the dashboard is NOT on scada_net. It reads
the store through a volume, so it needs no adjacency to the monitored segment, and
Docker drops published ports on `internal: true` networks (the port mapping is
silently omitted), so viewing it from the host requires a network with a gateway.
"""

from __future__ import annotations

import argparse
import logging
import sqlite3
import sys
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Sequence, Tuple

import yaml
from flask import Flask, jsonify, render_template, request

LOG = logging.getLogger("gridsnare.dashboard")

DEFAULT_CONFIG_PATH = "/app/config.yaml"

# Severity vocabulary from SPEC.md Section 7.3.
SEVERITY_ORDER = ("Critical", "High", "Medium", "Low")


class ConfigError(Exception):
    """Raised when the dashboard section of config.yaml is missing or malformed."""


@dataclass(frozen=True)
class DashboardConfig:
    """Validated `dashboard` configuration (nothing hardcoded, per SPEC.md Section 8)."""

    database: str
    host: str
    port: int
    refresh_seconds: int
    feed_limit: int
    timeline_minutes: int
    timeline_windows: Tuple[int, ...]
    stale_after_seconds: int
    expected_sources: Tuple[str, ...]
    historical_sources: Tuple[str, ...]
    log_level: str

    @classmethod
    def load(cls, path: str) -> "DashboardConfig":
        config_path = Path(path)
        if not config_path.is_file():
            raise ConfigError(f"config file not found: {config_path}")
        try:
            document = yaml.safe_load(config_path.read_text(encoding="utf-8")) or {}
        except yaml.YAMLError as exc:
            raise ConfigError(f"{config_path} is not valid YAML: {exc}") from exc

        section = document.get("dashboard")
        if not isinstance(section, dict):
            raise ConfigError(
                f"{config_path} must contain a 'dashboard:' mapping (SPEC.md Section 7.5)"
            )

        database = section.get("database")
        if not isinstance(database, str) or not database.strip():
            raise ConfigError("dashboard.database must be a non-empty path")

        sources = section.get("expected_sources", ["monitor", "honeypot"])
        if not isinstance(sources, (list, tuple)) or not sources:
            raise ConfigError(
                "dashboard.expected_sources must be a non-empty list of source names"
            )
        cleaned_sources: List[str] = []
        for name in sources:
            if not isinstance(name, str) or not name.strip():
                raise ConfigError(
                    f"dashboard.expected_sources entries must be non-empty strings, got {name!r}"
                )
            cleaned_sources.append(name.strip())

        # Sources that are replayed from a historical dataset rather than captured
        # live. Optional, so the default (none) matches a stack that never replays.
        historical = section.get("historical_sources", [])
        if not isinstance(historical, (list, tuple)):
            raise ConfigError(
                "dashboard.historical_sources must be a list of source names"
            )
        cleaned_historical: List[str] = []
        for name in historical:
            if not isinstance(name, str) or not name.strip():
                raise ConfigError(
                    f"dashboard.historical_sources entries must be non-empty strings, got {name!r}"
                )
            cleaned_historical.append(name.strip())

        return cls(
            database=database,
            host=str(section.get("host") or "0.0.0.0"),
            port=_positive_int(section.get("port", 5000), "port"),
            refresh_seconds=_positive_int(section.get("refresh_seconds", 3), "refresh_seconds"),
            feed_limit=_positive_int(section.get("feed_limit", 50), "feed_limit"),
            timeline_minutes=_positive_int(section.get("timeline_minutes", 30), "timeline_minutes"),
            timeline_windows=_window_choices(section.get("timeline_windows")),
            stale_after_seconds=_positive_int(
                section.get("stale_after_seconds", 120), "stale_after_seconds"
            ),
            expected_sources=tuple(cleaned_sources),
            historical_sources=tuple(dict.fromkeys(cleaned_historical)),
            log_level=str(section.get("log_level") or "INFO").upper(),
        )


def _window_choices(value: Any) -> Tuple[int, ...]:
    """Validate dashboard.timeline_windows: a non-empty list of distinct minutes.

    A single-entry list is allowed (the viewer then has nothing to switch, and the
    UI hides the control rather than showing one dead button).
    """
    if value is None:
        return (30,)
    if not isinstance(value, (list, tuple)) or not value:
        raise ConfigError(
            "dashboard.timeline_windows must be a non-empty list of minute values"
        )
    choices: List[int] = []
    for entry in value:
        choices.append(_positive_int(entry, "timeline_windows entry"))
    return tuple(dict.fromkeys(choices))


def _positive_int(value: Any, name: str) -> int:
    try:
        parsed = int(value)
    except (TypeError, ValueError) as exc:
        raise ConfigError(f"dashboard.{name} must be an integer, got {value!r}") from exc
    if parsed <= 0:
        raise ConfigError(f"dashboard.{name} must be greater than zero")
    return parsed


# ---------------------------------------------------------------------------
# Data store access (SPEC.md Section 7.4: tables raw_events and alerts)
# ---------------------------------------------------------------------------


def connect(database: str) -> sqlite3.Connection:
    """Open the shared store read-only at the SQL level.

    A `mode=ro` URI is deliberately not used: SQLite still has to touch the store's
    sidecar files, and a read-only handle cannot create them, so it fails on a store
    the monitor is actively writing. PRAGMA query_only gives the same guarantee — any
    write from this process raises.
    """
    connection = sqlite3.connect(database, timeout=5.0)
    connection.row_factory = sqlite3.Row
    connection.execute("PRAGMA query_only = ON")
    return connection


def table_exists(connection: sqlite3.Connection, name: str) -> bool:
    row = connection.execute(
        "SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = ? LIMIT 1", (name,)
    ).fetchone()
    return row is not None


def utc_iso(moment: datetime) -> str:
    return moment.isoformat(timespec="milliseconds").replace("+00:00", "Z")


def fetch_totals(connection: sqlite3.Connection) -> Dict[str, int]:
    """Headline counts: events by source (the 7.5 honeypot/monitor split) and alerts."""
    totals = {
        "events_honeypot": 0,
        "events_monitor": 0,
        "events_total": 0,
        "alerts_total": 0,
        "alerts_correlated": 0,
    }
    if table_exists(connection, "raw_events"):
        for row in connection.execute(
            "SELECT source, COUNT(*) AS n FROM raw_events GROUP BY source"
        ):
            key = f"events_{row['source']}"
            totals[key] = int(row["n"])
            totals["events_total"] += int(row["n"])
    if table_exists(connection, "alerts"):
        totals["alerts_total"] = int(
            connection.execute("SELECT COUNT(*) FROM alerts").fetchone()[0]
        )
        # SPEC.md Section 13: the dashboard must distinguish correlated (DR-7)
        # alerts from single-source ones.
        totals["alerts_correlated"] = int(
            connection.execute("SELECT COUNT(*) FROM alerts WHERE rule_id = 'DR-7'").fetchone()[0]
        )
    return totals


def fetch_severity_breakdown(connection: sqlite3.Connection) -> Dict[str, int]:
    """Alert counts per severity, always all four buckets so the chart is stable."""
    breakdown = {severity: 0 for severity in SEVERITY_ORDER}
    if not table_exists(connection, "alerts"):
        return breakdown
    for row in connection.execute("SELECT severity, COUNT(*) AS n FROM alerts GROUP BY severity"):
        breakdown[str(row["severity"])] = int(row["n"])
    return breakdown


def fetch_feed(connection: sqlite3.Connection, limit: int) -> List[Dict[str, Any]]:
    """The live alert feed: newest alerts first."""
    if not table_exists(connection, "alerts"):
        return []
    return [
        {
            "id": int(row["id"]),
            "timestamp": str(row["timestamp"]),
            "rule_id": str(row["rule_id"]),
            "severity": str(row["severity"]),
            "protocol": str(row["protocol"]),
            "src_ip": row["src_ip"],
            "dst_ip": row["dst_ip"],
            "description": str(row["description"]),
            "event_id": row["event_id"],
            "correlated_event_id": row["correlated_event_id"],
        }
        for row in connection.execute(
            "SELECT * FROM alerts ORDER BY id DESC LIMIT ?", (limit,)
        )
    ]


def fetch_timeline(connection: sqlite3.Connection, minutes: int) -> Dict[str, Any]:
    """Alerts per minute over a trailing window, stacked by severity.

    Timestamps are stored as UTC text (SPEC.md Section 7.4), so bucketing is done
    in UTC and the browser converts the labels to the viewer's local time. Empty
    minutes are filled in, otherwise a quiet period silently collapses the chart.
    """
    now = datetime.now(timezone.utc)
    window_start = (now - timedelta(minutes=minutes - 1)).replace(second=0, microsecond=0)

    buckets: Dict[str, Dict[str, int]] = {}
    order: List[str] = []
    for offset in range(minutes):
        minute = window_start + timedelta(minutes=offset)
        key = utc_iso(minute)
        buckets[key] = {severity: 0 for severity in SEVERITY_ORDER}
        order.append(key)

    if table_exists(connection, "alerts"):
        for row in connection.execute(
            "SELECT substr(timestamp, 1, 16) AS minute, severity, COUNT(*) AS n "
            "FROM alerts WHERE timestamp >= ? "
            "GROUP BY minute, severity ORDER BY minute",
            (utc_iso(window_start),),
        ):
            # substr gives "YYYY-MM-DDTHH:MM"; normalise it to the bucket keys above.
            key = str(row["minute"]) + ":00.000Z"
            if key in buckets:
                buckets[key][str(row["severity"])] = int(row["n"])

    return {
        "window_minutes": minutes,
        "labels": order,
        "series": {
            severity: [buckets[key][severity] for key in order] for severity in SEVERITY_ORDER
        },
    }


# ---------------------------------------------------------------------------
# Pipeline health
#
# SPEC.md Section 7.5 asks for four views; this is a fifth, added because the
# other four answer "what was detected" and none answer "is the sensor still
# reporting". Every count on this page can look calm while the monitor, the
# decoy, or the engine is dead: the store simply stops growing. These states are
# derived only from what the components themselves wrote, so nothing here is
# inferred from wall-clock alone:
#
#   * a source is FRESH / STALE / SILENT from its newest raw_events row;
#   * the engine is CURRENT / BEHIND from its watermark against raw_events.id,
#     and STOPPED from the heartbeat it writes each poll cycle.
#
# Grade precedence matters. Unjudged events are a fault no matter how quiet the
# lab is, so they outrank everything; a source that is silent while a sibling is
# still reporting is provably broken, which is a stronger claim than "nothing has
# happened lately" and is graded accordingly.
# ---------------------------------------------------------------------------

FRESH = "fresh"
STALE = "stale"
SILENT = "silent"
UNKNOWN = "unknown"


def parse_stamp(text: Any) -> Optional[datetime]:
    """Parse a stored ISO-8601 UTC timestamp, tolerating an unparsable value."""
    if not isinstance(text, str) or not text.strip():
        return None
    try:
        moment = datetime.fromisoformat(text.strip().replace("Z", "+00:00"))
    except ValueError:
        return None
    if moment.tzinfo is None:
        moment = moment.replace(tzinfo=timezone.utc)
    return moment.astimezone(timezone.utc)


def age_seconds(text: Any, now: datetime) -> Optional[float]:
    """Seconds since a stored timestamp, or None when it cannot be parsed."""
    moment = parse_stamp(text)
    if moment is None:
        return None
    return round((now - moment).total_seconds(), 1)


def source_state(count: int, age: Optional[float], stale_after: int) -> str:
    if count == 0:
        return SILENT
    if age is None:
        return UNKNOWN
    return FRESH if age <= stale_after else STALE


def describe_source_state(entry: Dict[str, Any]) -> str:
    """One source as "<name> <state> (<fact behind the state>)".

    Uses the same words as the per-source chips (fresh / stale / silent /
    unknown), so the banner and the cards below it cannot drift apart. "Stale"
    always carries its age, because a source that has events but nothing recent
    must never read as a source that has nothing.
    """
    if entry["state"] == SILENT:
        return f"{entry['source']} silent (no event ever stored)"
    if entry["state"] == UNKNOWN:
        return f"{entry['source']} unknown (unreadable timestamp)"
    return f"{entry['source']} {entry['state']} (newest {entry['age_text']})"


def humanise_age(age: Optional[float]) -> str:
    """Coarse, honest age text. None means there is no timestamp to speak of."""
    if age is None:
        return "never"
    if age < 0:
        return "in the future (clock skew)"
    seconds = int(age)
    if seconds < 60:
        return f"{seconds}s ago"
    if seconds < 3600:
        return f"{seconds // 60}m {seconds % 60}s ago"
    if seconds < 86400:
        hours, remainder = divmod(seconds, 3600)
        return f"{hours}h {remainder // 60}m ago"
    days, remainder = divmod(seconds, 86400)
    return f"{days}d {remainder // 3600}h ago"


def fetch_pipeline(
    connection: sqlite3.Connection, config: DashboardConfig, now: datetime
) -> Dict[str, Any]:
    """Per-source freshness, engine position, and one graded overall state."""
    stale_after = config.stale_after_seconds
    observed: Dict[str, Dict[str, Any]] = {}
    latest_event_id = 0
    events_total = 0

    if table_exists(connection, "raw_events"):
        for row in connection.execute(
            "SELECT source, COUNT(*) AS n, MAX(timestamp) AS last "
            "FROM raw_events GROUP BY source"
        ):
            observed[str(row["source"])] = {"count": int(row["n"]), "last": row["last"]}
        top = connection.execute(
            "SELECT MAX(id) AS latest, COUNT(*) AS n FROM raw_events"
        ).fetchone()
        latest_event_id = int(top["latest"] or 0)
        events_total = int(top["n"] or 0)

    # Historical sources are bounded replays: their rows carry the timestamp of
    # the dataset they came from, not the moment they were stored, so age against
    # the wall clock is meaningless for them. Grading them on freshness would raise
    # a permanent, false fault (see dashboard.historical_sources), so they are held
    # out of the graded list below and reported separately, never as a fault.
    historical_names = set(config.historical_sources)

    # Expected sources keep their configured order; anything else the store has
    # seen is appended, because data in the store beats a list in a config file.
    names = [name for name in config.expected_sources if name not in historical_names]
    names += sorted(
        name for name in observed
        if name not in config.expected_sources and name not in historical_names
    )

    sources: List[Dict[str, Any]] = []
    for name in names:
        entry = observed.get(name, {"count": 0, "last": None})
        age = age_seconds(entry["last"], now)
        sources.append(
            {
                "source": name,
                "events": entry["count"],
                "last_event": entry["last"],
                "age_seconds": age,
                "age_text": humanise_age(age) if entry["count"] else "never",
                "state": source_state(entry["count"], age, stale_after),
                "expected": name in config.expected_sources,
            }
        )

    # Replayed sources are still shown, just not graded. Hiding them entirely would
    # leave the event totals — which do count them — unexplainable on the page.
    historical: List[Dict[str, Any]] = []
    for name in config.historical_sources:
        entry = observed.get(name, {"count": 0, "last": None})
        age = age_seconds(entry["last"], now)
        historical.append(
            {
                "source": name,
                "events": entry["count"],
                "last_event": entry["last"],
                "age_seconds": age,
                "age_text": humanise_age(age) if entry["count"] else "never",
            }
        )

    # Engine: watermark lag is definitive (events exist that nobody judged); the
    # heartbeat catches the case where the queue is empty and detection died
    # quietly, which is otherwise indistinguishable from an idle lab.
    watermark_text = read_engine_state(connection, "raw_events_watermark")
    watermark: Optional[int]
    try:
        watermark = int(watermark_text) if watermark_text is not None else None
    except (TypeError, ValueError):
        watermark = None

    # No watermark means nothing has ever been judged, so every captured event is
    # unjudged. Treating that as "lag 0" would be the exact false reassurance this
    # panel exists to remove: a store full of events and a never-run engine would
    # read as current.
    judged_through = watermark if watermark is not None else 0

    heartbeat_text = read_engine_state(connection, "last_poll_at")
    heartbeat_age = age_seconds(heartbeat_text, now)
    lag_events = max(0, latest_event_id - judged_through)

    # How long the oldest unjudged event has been waiting, which is what separates
    # "mid-cycle" from "stalled". A live engine drains its queue within one poll
    # interval, so a raw lag count alone would flash Critical between every poll;
    # an unjudged event older than the staleness window is a definitive stall.
    unjudged_since = None
    if lag_events > 0 and table_exists(connection, "raw_events"):
        row = connection.execute(
            "SELECT MIN(timestamp) AS oldest FROM raw_events WHERE id > ?", (judged_through,)
        ).fetchone()
        unjudged_since = row["oldest"]
    lag_age = age_seconds(unjudged_since, now)
    lag_is_stalled = lag_age is not None and lag_age > stale_after

    if lag_events > 0 and lag_is_stalled:
        engine_state_name = "behind"
    elif lag_events > 0:
        engine_state_name = "catching_up"
    elif heartbeat_age is not None and heartbeat_age > stale_after:
        engine_state_name = "stopped"
    elif heartbeat_age is not None:
        engine_state_name = "current"
    elif watermark:
        # Judged events before, but no heartbeat: either the engine ran as a
        # one-shot (--once), or it predates heartbeat recording.
        engine_state_name = "not_reporting"
    else:
        engine_state_name = "never_run"

    engine = {
        "state": engine_state_name,
        "watermark": watermark,
        "watermark_text": "none" if watermark is None else str(watermark),
        "latest_event_id": latest_event_id,
        "lag_events": lag_events,
        "lag_age_seconds": lag_age,
        "lag_age_text": humanise_age(lag_age),
        "unjudged_since": unjudged_since,
        "last_poll": heartbeat_text,
        "age_seconds": heartbeat_age,
        "age_text": humanise_age(heartbeat_age) if heartbeat_text else "never",
        # States that mean detection is provably not running. `catching_up` is not
        # one of them: by definition it has a live heartbeat and a fresh queue.
        "fault": engine_state_name in ("behind", "stopped", "not_reporting", "never_run"),
    }

    last_alert = None
    alerts_total = 0
    if table_exists(connection, "alerts"):
        row = connection.execute(
            "SELECT MAX(timestamp) AS last, COUNT(*) AS n FROM alerts"
        ).fetchone()
        last_alert = row["last"]
        alerts_total = int(row["n"] or 0)
    alert_age = age_seconds(last_alert, now)

    fresh = [s for s in sources if s["state"] == FRESH]
    stalled = [s for s in sources if s["state"] in (STALE, SILENT, UNKNOWN)]

    if events_total == 0:
        state = "starting"
        summary = (
            "No events in the store yet, so there is nothing to be stale about. "
            "Send Modbus traffic to the honeypot and start the engine "
            "(engine/correlator.py) — until then no detection is running."
        )
    elif engine_state_name == "behind":
        state = "down"
        summary = (
            f"Detection is stalled: {lag_events} captured event(s) have gone "
            f"unjudged for longer than {stale_after}s (oldest "
            f"{engine['lag_age_text']}, watermark "
            f"{engine['watermark_text']}). Start the engine (python -m "
            "engine.correlator) — nothing will be detected however much traffic "
            "arrives until it runs."
        )
    elif engine_state_name == "stopped":
        state = "down"
        summary = (
            f"Detection is stopped: the engine last polled {engine['age_text']}. "
            "It is not judging new events, so a quiet alert feed does not mean a "
            "quiet network."
        )
    elif engine_state_name == "not_reporting":
        state = "down"
        summary = (
            f"The engine is not reporting: it has judged events up to id "
            f"{engine['watermark_text']} but has written no heartbeat, so detection is "
            "not running now (a one-shot run, or an engine started before "
            "heartbeats were recorded)."
        )
    elif engine_state_name == "never_run":
        state = "down"
        summary = (
            "The engine has never judged anything in this store — no watermark "
            "and no heartbeat. Start it (python -m engine.correlator)."
        )
    elif not stalled:
        state = "healthy"
        summary = (
            f"All {len(sources)} expected source(s) fresh — newest event "
            f"{fresh[0]['age_text']} — and detection is current (last poll "
            f"{engine['age_text']}, {lag_events} unjudged)."
        )
    elif fresh:
        state = "blind"
        summary = (
            "Capture path looks broken: "
            + ", ".join(describe_source_state(s) for s in stalled)
            + ", while "
            + ", ".join(describe_source_state(s) for s in fresh)
            + ". Traffic is flowing, so a source going quiet is a fault rather "
            "than an idle lab — either its capture path has stopped, or it was "
            "never wired into this store."
        )
    else:
        state = "quiet"
        # Deliberately not dressed up as a fault: every source is silent, and this
        # reading cannot tell an idle lab from a broken capture path, so it says so.
        # Wording matters here — the sources do hold events (they are `stale`, not
        # `silent`), so "no events" would be false. What is true is that nothing
        # new arrived inside the staleness window.
        summary = (
            f"No new events from any source in the last {stale_after}s — "
            + ", ".join(describe_source_state(s) for s in sources)
            + ". Either the lab is idle or every capture path has stopped; this "
            "store cannot tell the two apart, so send known traffic to confirm."
        )

    return {
        "state": state,
        "summary": summary,
        "checked_at": utc_iso(now),
        "stale_after_seconds": stale_after,
        "expected_sources": list(config.expected_sources),
        "historical_sources": list(config.historical_sources),
        "sources": sources,
        "historical": historical,
        "engine": engine,
        "alerts": {
            "total": alerts_total,
            "last_alert": last_alert,
            "age_seconds": alert_age,
            "age_text": humanise_age(alert_age) if last_alert else "never",
        },
    }


def read_engine_state(connection: sqlite3.Connection, key: str) -> Optional[str]:
    """Read one engine_state value; absent or unreadable both mean None."""
    if not table_exists(connection, "engine_state"):
        return None
    try:
        row = connection.execute(
            "SELECT value FROM engine_state WHERE key = ?", (key,)
        ).fetchone()
    except sqlite3.Error:
        return None
    return None if row is None else str(row["value"])


def starting_pipeline(config: DashboardConfig) -> Dict[str, Any]:
    """The health block for a store that is missing, empty or unreadable."""
    return {
        "state": "starting",
        "summary": (
            "No pipeline status yet: no readable data store, so nothing is being "
            "captured and nothing is being judged."
        ),
        "checked_at": utc_iso(datetime.now(timezone.utc)),
        "stale_after_seconds": config.stale_after_seconds,
        "expected_sources": list(config.expected_sources),
        "historical_sources": list(config.historical_sources),
        "sources": [],
        "historical": [],
        "engine": {
            "state": "never_run", "watermark": None, "watermark_text": "none",
            "latest_event_id": 0,
            "lag_events": 0, "lag_age_seconds": None, "lag_age_text": "never",
            "unjudged_since": None, "last_poll": None, "age_seconds": None,
            "age_text": "never", "fault": True,
        },
        "alerts": {"total": 0, "last_alert": None, "age_seconds": None, "age_text": "never"},
    }


def build_payload(
    config: DashboardConfig, minutes: Optional[int] = None
) -> Dict[str, Any]:
    """Everything the page needs, in one response. Never raises for a cold store.

    `minutes` is the timeline window the viewer selected. It is clamped to
    `config.timeline_windows`, so a hand-edited querystring cannot ask the store for
    an unbounded window — the range is config (SPEC.md Section 8), not a parameter.
    """
    timeline_minutes = config.timeline_minutes
    if minutes is not None and minutes in config.timeline_windows:
        timeline_minutes = minutes

    payload: Dict[str, Any] = {
        "generated_at": utc_iso(datetime.now(timezone.utc)),
        "refresh_seconds": config.refresh_seconds,
        "database": config.database,
        "database_present": Path(config.database).is_file(),
        "store_ready": False,
        "totals": {},
        "severity": {},
        "feed": [],
        "timeline": {"window_minutes": timeline_minutes, "labels": [], "series": {}},
        "timeline_windows": list(config.timeline_windows),
        "pipeline": starting_pipeline(config),
    }

    if not payload["database_present"]:
        payload["notice"] = (
            f"No data store at {config.database} yet — start the monitor so it can "
            "create one. Nothing is being displayed from mock data."
        )
        return payload

    try:
        connection = connect(config.database)
    except sqlite3.Error as exc:
        payload["notice"] = f"Data store {config.database} could not be opened: {exc}"
        return payload

    try:
        payload["totals"] = fetch_totals(connection)
        payload["severity"] = fetch_severity_breakdown(connection)
        payload["feed"] = fetch_feed(connection, config.feed_limit)
        payload["timeline"] = fetch_timeline(connection, timeline_minutes)
        payload["pipeline"] = fetch_pipeline(
            connection, config, datetime.now(timezone.utc)
        )
    except sqlite3.Error as exc:
        payload["notice"] = f"Query against {config.database} failed: {exc}"
        return payload
    finally:
        connection.close()

    if not payload["totals"].get("alerts_total"):
        # The sensor-health panel below carries the "is anything running" advice;
        # this notice only explains the empty alert table.
        payload["notice"] = (
            "The store exists but holds no alerts yet — this page shows only what "
            "has actually been detected, never a placeholder."
        )
    payload["store_ready"] = True
    return payload


# ---------------------------------------------------------------------------
# Flask app
# ---------------------------------------------------------------------------


def create_app(config: DashboardConfig) -> Flask:
    app = Flask(__name__)

    @app.route("/")
    def index() -> str:
        # Rendered server-side as well as polled, so the very first paint already
        # shows real store contents rather than an empty skeleton.
        return render_template(
            "index.html",
            payload=build_payload(config),
            severities=list(SEVERITY_ORDER),
            auth_note=(
                "Lab demo — no authentication, bound to 127.0.0.1 on the host "
                "(SPEC.md Section 7.5 limitation)"
            ),
        )

    @app.route("/api/dashboard")
    def api_dashboard():
        requested = request.args.get("minutes", type=int)
        return jsonify(build_payload(config, requested))

    @app.route("/api/health")
    def api_health():
        payload = build_payload(config)
        pipeline = payload["pipeline"]
        return jsonify(
            {
                "status": "ok" if payload["store_ready"] else "waiting_for_store",
                "database": config.database,
                "database_present": payload["database_present"],
                "alerts": payload.get("totals", {}).get("alerts_total", 0),
                # Machine-readable pipeline state, so a script can watch for a
                # blind capture path or a stopped engine without scraping the UI.
                "pipeline": pipeline["state"],
                "pipeline_summary": pipeline["summary"],
                "sources": {
                    entry["source"]: {
                        "state": entry["state"],
                        "age_seconds": entry["age_seconds"],
                        "events": entry["events"],
                    }
                    for entry in pipeline["sources"]
                },
                # Replayed sources: reported for completeness, deliberately
                # without a state, because freshness does not apply to them.
                "historical_sources": {
                    entry["source"]: {
                        "age_seconds": entry["age_seconds"],
                        "events": entry["events"],
                    }
                    for entry in pipeline.get("historical", [])
                },
                "engine": pipeline["engine"]["state"],
                "unjudged_events": pipeline["engine"]["lag_events"],
            }
        )

    return app


def _parse_args(argv: Optional[Sequence[str]]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="GridSnare alert dashboard (SPEC.md Section 7.5)"
    )
    parser.add_argument(
        "--config", default=DEFAULT_CONFIG_PATH,
        help=f"path to config.yaml (default: {DEFAULT_CONFIG_PATH})",
    )
    return parser.parse_args(argv)


def main(argv: Optional[Sequence[str]] = None) -> int:
    args = _parse_args(argv)

    try:
        config = DashboardConfig.load(args.config)
    except ConfigError as exc:
        print(f"configuration error: {exc}", file=sys.stderr)
        return 2

    logging.basicConfig(
        level=getattr(logging, config.log_level, logging.INFO),
        format="%(asctime)s %(levelname)s %(name)s | %(message)s",
        stream=sys.stdout,
    )

    LOG.info(
        "dashboard starting (SPEC.md 7.5): config=%s db=%s bind=%s:%s refresh=%ss "
        "feed_limit=%s timeline=%smin",
        args.config, config.database, config.host, config.port,
        config.refresh_seconds, config.feed_limit, config.timeline_minutes,
    )

    startup = build_payload(config)
    if startup["store_ready"]:
        totals = startup["totals"]
        LOG.info(
            "data store open: %d event(s) (%d honeypot / %d monitor), %d alert(s), "
            "%d correlated",
            totals["events_total"], totals["events_honeypot"], totals["events_monitor"],
            totals["alerts_total"], totals["alerts_correlated"],
        )
        pipeline = startup["pipeline"]
        LOG.info(
            "pipeline: %s | %s", pipeline["state"].upper(), pipeline["summary"]
        )
        for entry in pipeline["sources"]:
            LOG.info(
                "  source %-9s %-6s last event %s (%d event(s))",
                entry["source"], entry["state"], entry["age_text"], entry["events"],
            )
        engine = pipeline["engine"]
        LOG.info(
            "  engine    %-9s %-6s last poll %s, %d unjudged (watermark %s / newest id %d)",
            "engine", engine["state"], engine["age_text"], engine["lag_events"],
            engine["watermark"], engine["latest_event_id"],
        )
        if pipeline["state"] != "healthy":
            LOG.warning("pipeline is not healthy: %s", pipeline["summary"])
    else:
        LOG.warning("data store not ready: %s", startup.get("notice"))

    app = create_app(config)
    # Flask's development server is fine for a loopback lab demo (SPEC.md Section
    # 7.5 explicitly scopes this as a local-only tool). A production deployment
    # would put waitress/gunicorn in front of the WSGI app.
    app.run(host=config.host, port=config.port, debug=False, threaded=True)
    return 0


if __name__ == "__main__":
    sys.exit(main())
