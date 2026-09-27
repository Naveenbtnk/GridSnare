#!/usr/bin/env python3
"""TC-1 .. TC-6 — the SPEC.md Section 12 validation & test plan, automated.

SPEC.md Section 20.6 requires each test case to be "implemented as an actual
automated test in `tests/test_scenarios.py`, not just documented here". This file is
that implementation for Phase 1. Every case quotes its Section 12 row verbatim in
its docstring (README instruction 4).

These are end-to-end tests against the running lab, not unit tests with mocks:

  1. traffic is generated over real Modbus/TCP sockets to the decoy, from this
     container's fixed address on scada_net (see tests/lab_traffic.py);
  2. the test waits for the live monitor to store what it captured;
  3. the test advances the engine by exactly one poll cycle (`--once`) instead of
     racing the background loop, so results do not depend on timing. The engine also
     runs continuously as its own compose service (SPEC.md Section 13 wants no manual
     steps), and a session fixture asserts that service is genuinely polling before any
     case runs — otherwise the one-off pass could mask a deployment with no detection;
  4. the assertions read the same SQLite store and the same dashboard HTTP API an
     operator sees.

Prerequisites, from the repository root:

    docker compose up -d
    docker compose --profile test run --rm tests

Anything the suite changes, it reports: the store is the lab's real store, so
running the plan appends real events and alerts to it (that is what end-to-end
means here). Counters are therefore always compared *relative to a snapshot taken
by the test*, never against absolute totals.

Nothing in this file fabricates a result: a case that does not meet its Section 12
expected result fails, loudly and with the reason (README instruction 5).
"""

from __future__ import annotations

import json
import os
import socket
import sqlite3
import subprocess
import sys
import time
import urllib.error
import urllib.request
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional

import pytest
import yaml

sys.path.insert(0, str(Path(__file__).resolve().parent))

import lab_traffic  # noqa: E402  (path bootstrap must run first)

from engine.rules import DetectionThresholds  # noqa: E402

REPO_ROOT = Path(__file__).resolve().parents[1]
CONFIG_PATH = REPO_ROOT / "config.yaml"

# Severity vocabulary from SPEC.md Section 7.3.
CRITICAL = "Critical"
HIGH = "High"


# ---------------------------------------------------------------------------
# Settings — config.yaml `tests:`, overridable by environment variable
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class Settings:
    honeypot_host: str
    honeypot_port: int
    plc_host: str
    plc_port: int
    client_source_ip: str
    database: str
    dashboard_url: str
    baseline_seconds: float
    baseline_interval_seconds: float
    event_timeout_seconds: float


def _setting(env_name: str, section: Dict[str, Any], key: str, default: Any) -> Any:
    if env_name in os.environ:
        return os.environ[env_name]
    return section.get(key, default)


@pytest.fixture(scope="session")
def config() -> Dict[str, Any]:
    if not CONFIG_PATH.is_file():
        pytest.fail(f"{CONFIG_PATH} is missing — the tests read thresholds from it, "
                    "they are never hardcoded (SPEC.md Section 8)")
    return yaml.safe_load(CONFIG_PATH.read_text(encoding="utf-8")) or {}


@pytest.fixture(scope="session")
def thresholds(config: Dict[str, Any]) -> DetectionThresholds:
    """The same validated thresholds the engine runs with, loaded by its own code.

    Importing `DetectionThresholds` instead of re-reading the YAML keeps the tests
    and the engine from disagreeing about what the configuration means.
    """
    from engine.rules import RuleConfigError

    try:
        return DetectionThresholds.from_mapping((config.get("engine") or {}).get("detection"))
    except RuleConfigError as exc:
        pytest.fail(f"engine.detection is not usable: {exc}")


@pytest.fixture(scope="session")
def settings(config: Dict[str, Any]) -> Settings:
    section = config.get("tests")
    if not isinstance(section, dict):
        pytest.fail("config.yaml must contain a `tests:` mapping (see the file's own comments)")

    def number(env_name: str, key: str, default: float) -> float:
        raw = _setting(env_name, section, key, default)
        try:
            return float(raw)
        except (TypeError, ValueError):
            pytest.fail(f"tests.{key} must be a number, got {raw!r}")

    honeypot_host = str(_setting("GRIDSNARE_HONEYPOT_HOST", section, "honeypot_host", "172.20.0.2"))
    honeypot_port = int(number("GRIDSNARE_HONEYPOT_PORT", "honeypot_port", 5020))

    # Preflight: a test run that cannot see its own targets should say so once,
    # clearly, rather than produce six confusing failures.
    try:
        socket.create_connection((honeypot_host, honeypot_port), timeout=5).close()
    except OSError as exc:
        pytest.fail(
            f"cannot reach the decoy at {honeypot_host}:{honeypot_port} ({exc}). "
            "Start the stack first: docker compose up -d"
        )

    return Settings(
        honeypot_host=honeypot_host,
        honeypot_port=honeypot_port,
        # The legitimate PLC (SPEC.md Section 11). TC-2 targets it; nothing else does.
        plc_host=str(_setting("GRIDSNARE_PLC_HOST", section, "plc_host", "172.20.0.6")),
        plc_port=int(number("GRIDSNARE_PLC_PORT", "plc_port", 502)),
        client_source_ip=str(_setting("GRIDSNARE_CLIENT_IP", section, "client_source_ip", "172.20.0.5")),
        database=str(_setting("GRIDSNARE_DB", section, "database", "/app/data/events.db")),
        dashboard_url=str(_setting("GRIDSNARE_DASHBOARD_URL", section, "dashboard_url",
                                   "http://dashboard:5000")).rstrip("/"),
        baseline_seconds=number("GRIDSNARE_BASELINE_SECONDS", "baseline_seconds", 600),
        baseline_interval_seconds=number("GRIDSNARE_BASELINE_INTERVAL", "baseline_interval_seconds", 15),
        event_timeout_seconds=number("GRIDSNARE_EVENT_TIMEOUT", "event_timeout_seconds", 20),
    )


# ---------------------------------------------------------------------------
# Store access (SPEC.md Section 7.4: raw_events, alerts, engine_state)
# ---------------------------------------------------------------------------

@pytest.fixture()
def store(settings: Settings):
    if not Path(settings.database).is_file():
        pytest.fail(
            f"no data store at {settings.database}. The monitor creates it; start the "
            "stack and send one Modbus request before running the plan."
        )
    connection = sqlite3.connect(settings.database, timeout=10.0)
    connection.row_factory = sqlite3.Row
    # Read-only at the SQL level: the tests drive the engine by running it, never by
    # writing rows themselves (SPEC.md Section 13 forbids manual database edits).
    connection.execute("PRAGMA query_only = ON")
    try:
        yield connection
    finally:
        connection.close()


@pytest.fixture(scope="session", autouse=True)
def engine_service_polling(settings: Settings) -> None:
    """Fail the plan unless the persistent `engine` service is actually polling.

    Detection runs as its own compose service (docker-compose.yml `engine`, SPEC.md
    Section 9 step 3 / Section 13's "no manual steps"). Every case below still advances
    the engine by one `--once` pass for determinism, but that pass would succeed even if
    the *deployed* engine were dead — leaving the lab with no detection while the suite
    reported success. This watches the `engine_state` heartbeat advance, which only the
    background loop does at session start: no case has run yet, so nothing else in this
    suite is stamping it.

    Generous timeout on purpose: the loop stamps `last_poll_at` once per *cycle*, and a
    cycle that drains a large backlog takes as long as that backlog does, so a short wait
    could fail a healthy engine that simply started after a long downtime.
    """
    path = Path(settings.database)
    if not path.is_file():
        return  # the `store` fixture fails first, with a clearer message

    def heartbeat() -> Optional[str]:
        try:
            connection = sqlite3.connect(path, timeout=10.0)
        except sqlite3.Error:
            return None
        try:
            row = connection.execute(
                "SELECT value FROM engine_state WHERE key = 'last_poll_at'"
            ).fetchone()
        except sqlite3.Error:
            return None
        finally:
            connection.close()
        return None if row is None else str(row[0])

    first = heartbeat()
    deadline = time.monotonic() + 90
    while time.monotonic() < deadline:
        current = heartbeat()
        if current is not None and current != first:
            return
        time.sleep(0.5)

    pytest.fail(
        "the persistent engine service is not polling: engine_state.last_poll_at has not "
        f"advanced in 90s (last value {first!r}). Detection is its own service now — start "
        "the stack with `docker compose up -d` and check `docker compose logs engine`. "
        "Each case also runs a one-off engine pass for determinism, so without this check "
        "the plan would report success against a stack that had no detection running."
    )


@dataclass(frozen=True)
class Snapshot:
    """Everything needed to scope an assertion to "what happened during this test"."""

    raw_events_id: int
    alerts_id: int


def snapshot(store: sqlite3.Connection) -> Snapshot:
    raw = store.execute("SELECT COALESCE(MAX(id), 0) AS n FROM raw_events").fetchone()["n"]
    alerts = store.execute("SELECT COALESCE(MAX(id), 0) AS n FROM alerts").fetchone()["n"]
    return Snapshot(raw_events_id=int(raw), alerts_id=int(alerts))


def raw_events_after(store: sqlite3.Connection, after_id: int, source: Optional[str] = None,
                     src_ip: Optional[str] = None) -> List[sqlite3.Row]:
    query = "SELECT * FROM raw_events WHERE id > ?"
    params: List[Any] = [after_id]
    if source is not None:
        query += " AND source = ?"
        params.append(source)
    if src_ip is not None:
        query += " AND src_ip = ?"
        params.append(src_ip)
    query += " ORDER BY id"
    return list(store.execute(query, params))


def alerts_after(store: sqlite3.Connection, after_id: int,
                 src_ip: Optional[str] = None) -> List[sqlite3.Row]:
    query = "SELECT * FROM alerts WHERE id > ?"
    params: List[Any] = [after_id]
    if src_ip is not None:
        query += " AND src_ip = ?"
        params.append(src_ip)
    query += " ORDER BY id"
    return list(store.execute(query, params))


def store_diagnosis(store: sqlite3.Connection) -> str:
    """A one-block explanation of the current store state, attached to timeouts.

    An end-to-end test that fails with only "timed out" wastes the operator's time;
    this says what the store actually contains and whether anything is polling.
    """
    lines = []
    for table in ("raw_events", "alerts"):
        try:
            row = store.execute(
                f"SELECT COUNT(*) AS n, MAX(id) AS top, MAX(timestamp) AS newest FROM {table}"
            ).fetchone()
            lines.append(f"    {table}: {row['n']} row(s), newest id {row['top']}, "
                         f"newest timestamp {row['newest']}")
        except sqlite3.Error as exc:
            lines.append(f"    {table}: unreadable ({exc})")
    try:
        state = {row["key"]: row["value"] for row in store.execute("SELECT * FROM engine_state")}
        lines.append(f"    engine_state: {state or 'empty (engine has never polled)'}")
    except sqlite3.Error as exc:
        lines.append(f"    engine_state: unreadable ({exc})")
    return "\n".join(lines)


def wait_for(store: sqlite3.Connection, description: str, probe: Callable[[], Any],
             timeout: float, interval: float = 0.25) -> Any:
    """Poll `probe` until it returns something truthy. Fails with store diagnostics."""
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        found = probe()
        if found:
            return found
        time.sleep(interval)
    pytest.fail(
        f"timed out after {timeout:.0f}s waiting for {description}.\n"
        f"  store at the time of failure:\n{store_diagnosis(store)}"
    )


def wait_or_empty(store: sqlite3.Connection, probe: Callable[[], Any],
                  timeout: float, interval: float = 0.25) -> List[sqlite3.Row]:
    """Like wait_for, but returns [] instead of failing.

    Used where an absence has a specific, known cause that deserves its own
    explanation rather than a generic timeout message.
    """
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        found = probe()
        if found:
            return found
        time.sleep(interval)
    return []


# ---------------------------------------------------------------------------
# Driving the engine (SPEC.md Section 9, step 3)
# ---------------------------------------------------------------------------

def run_engine_once() -> str:
    """Run exactly one engine poll cycle, the way the stack runs it.

    Called as a subprocess so the test exercises the engine's real entry point
    rather than importing a function the running container might not use. One pass
    instead of a wait on the background loop keeps the plan deterministic; because
    alerts are de-duplicated on (rule_id, event_id), running this while the loop is
    also running cannot produce duplicates.
    """
    completed = subprocess.run(
        [sys.executable, "-m", "engine.correlator", "--once"],
        cwd=str(REPO_ROOT), capture_output=True, text=True, timeout=60,
    )
    output = (completed.stdout or "").strip()
    if completed.returncode != 0:
        pytest.fail(
            f"engine pass failed (exit {completed.returncode})\n"
            f"  stdout: {output}\n  stderr: {(completed.stderr or '').strip()}"
        )
    return output


# ---------------------------------------------------------------------------
# Dashboard access (SPEC.md Section 7.5 / 9, step 5)
# ---------------------------------------------------------------------------

def dashboard_payload(settings: Settings) -> Dict[str, Any]:
    url = f"{settings.dashboard_url}/api/dashboard"
    try:
        with urllib.request.urlopen(url, timeout=10) as response:
            return json.loads(response.read().decode("utf-8"))
    except (urllib.error.URLError, OSError, json.JSONDecodeError) as exc:
        pytest.fail(f"dashboard API {url} is not usable: {exc}")


def wait_for_quiescence(store: sqlite3.Connection, seconds: float = 1.5) -> None:
    """Confirm the *alerts* table has stopped moving before comparing counts.

    TC-6 compares two separate reads of live state (SQLite and HTTP). Without this,
    an alert arriving between the two reads would look like a dashboard bug.

    Only ``alerts`` is watched, not ``raw_events``. TC-6's assertions are entirely
    about alert counts, and in Phase 2 the event stream is never idle: the GOOSE
    monitor records the decoy's retransmissions and 2s heartbeat continuously, so a
    raw_events-based guard would fail for a lab that is working exactly as intended.
    That churn cannot affect these assertions either way — GOOSE rows are judged only
    by the GR rules (SPEC.md 20.3), so they raise no alert for TC-6 to race with.
    """
    first = snapshot(store).alerts_id
    time.sleep(seconds)
    second = snapshot(store).alerts_id
    if first != second:
        pytest.fail(
            "the alerts table changed while the test was reading it "
            f"(alerts {first} -> {second}). "
            "Something outside this test is writing alerts to the lab store; stop it and re-run."
        )


# ---------------------------------------------------------------------------
# TC-1
# ---------------------------------------------------------------------------

def test_tc1_honeypot_detection(settings: Settings, store: sqlite3.Connection):
    """TC-1: Honeypot detection.

    SPEC.md Section 12 (verbatim):
      | TC-1: Honeypot detection | Send a benign Modbus read request to the honeypot's
        IP from a lab test script | Event logged, DR-1 fires, Critical alert appears
        on dashboard |

    DR-1 (Section 8): "Any interaction with the honeypot" — Critical. Section 9 step 2
    is what feeds it: "any honeypot interaction is logged to raw_events with
    source=honeypot".
    """
    mark = snapshot(store)

    reply = lab_traffic.classic_read(
        settings.honeypot_host, settings.honeypot_port, address=0, quantity=10
    )
    print(f"[TC-1] sent FC3 read (address 0, qty 10) to "
          f"{settings.honeypot_host}:{settings.honeypot_port} -> {lab_traffic.describe_reply(reply)}")

    # The decoy answering at all — including with an exception frame — is proof the
    # interaction happened at the honeypot end.
    assert reply is not None, (
        "the decoy did not answer the benign read, so no interaction can be claimed. "
        "Check `docker compose logs honeypot`."
    )

    monitor_rows = wait_for(
        store, "the monitor to store the captured request",
        lambda: raw_events_after(store, mark.raw_events_id, source="monitor",
                                 src_ip=settings.client_source_ip),
        settings.event_timeout_seconds,
    )
    captured = monitor_rows[0]
    print(f"[TC-1] monitor side: raw_events id {captured['id']} source={captured['source']} "
          f"fc={captured['function_code']} from {captured['src_ip']}")

    honeypot_rows = wait_or_empty(
        store,
        lambda: raw_events_after(store, mark.raw_events_id, source="honeypot",
                                 src_ip=settings.client_source_ip),
        settings.event_timeout_seconds,
    )
    assert honeypot_rows, _HONEYPOT_INGESTION_FAILURE.format(where="TC-1")

    run_engine_once()
    new_alerts = alerts_after(store, mark.alerts_id)
    dr1 = [row for row in new_alerts if row["rule_id"] == "DR-1"]
    print(f"[TC-1] engine pass produced {len(new_alerts)} alert(s): "
          f"{sorted({row['rule_id'] for row in new_alerts})}")

    assert dr1, (
        f"DR-1 did not fire. Expected a Critical alert for the honeypot interaction "
        f"from {settings.client_source_ip}; the engine wrote: "
        f"{[(row['rule_id'], row['severity']) for row in new_alerts]}"
    )
    assert all(row["severity"] == CRITICAL for row in dr1), (
        f"DR-1 must be Critical (SPEC.md Section 8), got "
        f"{[(row['rule_id'], row['severity']) for row in dr1]}"
    )

    feed = dashboard_payload(settings)["feed"]
    assert any(row["rule_id"] == "DR-1" and row["severity"] == CRITICAL for row in feed), (
        "the DR-1 Critical alert is in the alerts table but not in the dashboard feed"
    )
    print(f"[TC-1] dashboard feed carries the DR-1 Critical alert (feed size {len(feed)})")


_HONEYPOT_INGESTION_FAILURE = (
    "{where} needs a honeypot-sourced event in raw_events and the store has none.\n"
    "  SPEC.md Section 9 step 2 (\"any honeypot interaction is logged to raw_events with\n"
    "  source=honeypot\") is implemented by the `honeypot-ingest` service, which tails the\n"
    "  decoy's log over the shared `conpot_logs` volume. Check, in this order:\n"
    "    1. is it running:                 docker compose ps honeypot-ingest\n"
    "    2. is it tailing or stalled:      docker compose logs --tail 20 honeypot-ingest\n"
    "       (one 'ingested honeypot interaction: ...' line per interaction; on first start\n"
    "       it seeks to the end of the log on purpose, so it never backfills history)\n"
    "    3. did the decoy log it at all:   docker compose exec honeypot tail -5 /var/log/conpot/conpot.log\n"
    "  If the decoy logged the interaction and the ingester is healthy but no row reached\n"
    "  the store, the defect is in honeypot/log_ingest.py rather than in this test."
)


# ---------------------------------------------------------------------------
# TC-2
# ---------------------------------------------------------------------------

def test_tc2_baseline_no_false_positive(settings: Settings, store: sqlite3.Connection,
                                        thresholds: DetectionThresholds):
    """TC-2: Baseline traffic (no false positive).

    SPEC.md Section 12 (verbatim):
      | TC-2: Baseline traffic (no false positive) | Run expected/whitelisted Modbus
        traffic pattern for 10 minutes, targeting the legitimate PLC simulator
        (Section 11) — never the honeypot | No alerts generated |

    The pattern is allow-listed reads only, spaced so it stays under DR-6's request
    limit, from a source on DR-5's allow-list — otherwise the rules would fire by
    design and the case would prove nothing about false positives.

    It targets the legitimate PLC (SPEC.md Section 11), not the decoy: a decoy has no
    legitimate traffic (Section 7.1), so baseline traffic aimed at it is traffic the rule
    set is supposed to flag. There is no configuration of the rules that makes baseline
    traffic to a decoy alert-free.

    The case asserts both halves: that the pattern raised no alert, **and** that the
    monitor actually observed it. The second half is what stops this passing while
    measuring nothing — see the positive control below.
    """
    hours = thresholds.operational_hours
    now = datetime.now(timezone.utc)
    window_end = now + timedelta(seconds=settings.baseline_seconds)
    if not hours.covers(now) or not hours.covers(window_end):
        pytest.skip(
            f"outside the configured operational hours ({hours.start:%H:%M}-{hours.end:%H:%M} "
            f"{hours.zone_name}); DR-4 would fire by design and this case tests false "
            "positives, so it is skipped rather than reported as a pass"
        )

    per_minute = 60.0 / settings.baseline_interval_seconds
    assert per_minute + 1 <= thresholds.polling_rate_limit, (
        f"the baseline pattern ({per_minute:.1f} requests/minute) would exceed DR-6's "
        f"limit of {thresholds.polling_rate_limit} per {thresholds.polling_window_seconds}s, "
        "so it is not a legitimate baseline. Raise tests.baseline_interval_seconds."
    )
    assert settings.client_source_ip in thresholds.known_asset_allow_list, (
        f"the baseline source {settings.client_source_ip} is not on "
        f"engine.detection.known_asset_allow_list {sorted(thresholds.known_asset_allow_list)}, "
        "so DR-5 would fire by design (SPEC.md Section 11 expects a baseline traffic "
        "source; it has to be allow-listed to be a baseline)."
    )
    assert (settings.plc_host, settings.plc_port) != (settings.honeypot_host, settings.honeypot_port), (
        f"TC-2 is configured to send its baseline pattern to the honeypot "
        f"({settings.honeypot_host}:{settings.honeypot_port}). Section 12 requires it to "
        "target the legitimate PLC simulator instead: a decoy has no legitimate traffic "
        "(Section 7.1), so traffic aimed at it is supposed to alert, and this case would "
        "be asserting the opposite of the rule set's intent. Point tests.plc_host/plc_port "
        "at the Section 11 PLC simulator."
    )

    # Preflight the baseline target with its own message: a baseline that cannot reach the
    # PLC would otherwise fail later as "no alerts", which reads like a pass.
    try:
        socket.create_connection((settings.plc_host, settings.plc_port), timeout=5).close()
    except OSError as exc:
        pytest.fail(
            f"the legitimate PLC simulator at {settings.plc_host}:{settings.plc_port} is "
            f"unreachable ({exc}). It is a required component (SPEC.md Section 11); start "
            "the stack with `docker compose up -d` and check `docker compose logs plc`."
        )

    # Drain anything queued from earlier cases so every alert counted below is
    # attributable to this baseline.
    run_engine_once()
    mark = snapshot(store)
    print(f"[TC-2] running the whitelisted pattern for {settings.baseline_seconds:.0f}s at "
          f"{settings.baseline_interval_seconds:.0f}s intervals "
          f"({per_minute:.1f} requests/minute, DR-6 limit {thresholds.polling_rate_limit}) "
          f"from {settings.client_source_ip} to the legitimate PLC "
          f"{settings.plc_host}:{settings.plc_port} (never the honeypot "
          f"{settings.honeypot_host}:{settings.honeypot_port})")

    def progress(record: Dict[str, Any]) -> None:
        print(f"[TC-2]   #{record['index'] + 1:>3} {record['function']} "
              f"addr={record['address']} -> {record['reply']}")

    started = time.monotonic()
    sent = lab_traffic.baseline_reads(
        settings.plc_host,
        settings.plc_port,
        addresses=[("holding", 0), ("coils", 0), ("holding", 4)],
        interval_seconds=settings.baseline_interval_seconds,
        duration_seconds=settings.baseline_seconds,
        on_send=progress,
    )
    elapsed = time.monotonic() - started

    # Positive control, and the reason this case cannot pass vacuously. "No alerts" only
    # says something about the rule set if the traffic was observed at all; a blind
    # observer and a well-behaved network produce identical silence. These rows are the
    # monitor's view of the very requests just sent.
    #
    # It also guards the lab's shape: a Linux bridge does not deliver one container's
    # unicast to a passive observer, so watching the PLC requires the `monitor-plc` tap on
    # the PLC's link. If someone removes it, this assertion fails and says so, instead of
    # this case quietly becoming a test of nothing.
    observed = wait_or_empty(
        store,
        lambda: [row for row in raw_events_after(store, mark.raw_events_id, source="monitor")
                 if row["dst_ip"] == settings.plc_host],
        settings.event_timeout_seconds,
    )
    print(f"[TC-2] the monitor observed {len(observed)} of {len(sent)} baseline "
          f"request(s) to {settings.plc_host}")
    assert observed, (
        f"the baseline pattern sent {len(sent)} request(s) to the legitimate PLC "
        f"{settings.plc_host}:{settings.plc_port} and the monitor stored none of them, so "
        "this case would pass while measuring nothing — with no observed traffic there is "
        "nothing for a rule to false-positive on.\n"
        "  Check the `monitor-plc` tap: `docker compose logs monitor-plc`. It must share the "
        "PLC's network namespace to see the PLC's traffic, because a Linux bridge does not "
        "deliver another container's unicast to a passive observer."
    )

    run_engine_once()
    new_alerts = alerts_after(store, mark.alerts_id)
    from_client = [row for row in new_alerts if row["src_ip"] == settings.client_source_ip]

    print(f"[TC-2] {len(sent)} request(s) sent over {elapsed:.0f}s; "
          f"{len(new_alerts)} alert(s) raised in that window "
          f"({len(from_client)} attributed to the baseline source)")

    assert not from_client, (
        f"the baseline pattern produced {len(from_client)} false positive(s): "
        f"{[(row['rule_id'], row['severity'], row['description'][:80]) for row in from_client]}"
    )
    assert not new_alerts, (
        f"{len(new_alerts)} alert(s) appeared during the baseline window with no "
        f"deliberate attack traffic: "
        f"{[(row['rule_id'], row['severity'], row['src_ip']) for row in new_alerts]}"
    )

    # Nothing else in the suite depends on the movement the baseline caused, so the
    # store is left exactly as the engine wrote it; no cleanup edits.
    print("[TC-2] PASS: zero alerts from the whitelisted pattern")


# ---------------------------------------------------------------------------
# TC-3
# ---------------------------------------------------------------------------

def test_tc3_function_code_anomaly(settings: Settings, store: sqlite3.Connection,
                                   thresholds: DetectionThresholds):
    """TC-3: Function code anomaly.

    SPEC.md Section 12 (verbatim):
      | TC-3: Function code anomaly | Send a Modbus request using a function code
        outside the allow-list | DR-2 fires, High alert generated |

    DR-2 (Section 8): "Modbus function code outside an allow-list of expected codes"
    — High. The function code used is FC 43 (Read Device Identification), a
    recognised ICS reconnaissance function, chosen from the configuration rather
    than hardcoded: the test first proves it is not on the allow-list.
    """
    anomaly = lab_traffic.READ_DEVICE_IDENTIFICATION
    assert anomaly not in thresholds.allowed_function_codes, (
        f"FC {anomaly} is on the configured allow-list "
        f"{sorted(thresholds.allowed_function_codes)}, so it cannot demonstrate DR-2. "
        "Pick a different function code or fix the configuration."
    )

    mark = snapshot(store)
    reply = lab_traffic.read_device_identification(
        settings.honeypot_host, settings.honeypot_port
    )
    print(f"[TC-3] sent FC {anomaly} (read device identification) -> "
          f"{lab_traffic.describe_reply(reply)}")

    rows = wait_for(
        store, f"the monitor to store FC {anomaly}",
        lambda: [row for row in raw_events_after(store, mark.raw_events_id, source="monitor")
                 if row["function_code"] == anomaly],
        settings.event_timeout_seconds,
    )
    print(f"[TC-3] monitor stored raw_events id {rows[0]['id']} "
          f"fc={rows[0]['function_code']} from {rows[0]['src_ip']}")

    run_engine_once()
    new_alerts = alerts_after(store, mark.alerts_id)
    dr2 = [row for row in new_alerts if row["rule_id"] == "DR-2"]
    print(f"[TC-3] engine wrote {[(row['rule_id'], row['severity']) for row in new_alerts]}")

    assert dr2, (
        f"DR-2 did not fire for function code {anomaly}. Alerts written: "
        f"{[(row['rule_id'], row['severity'], row['description'][:60]) for row in new_alerts]}"
    )
    assert all(row["severity"] == HIGH for row in dr2), (
        f"DR-2 must be High (SPEC.md Section 8), got "
        f"{[(row['rule_id'], row['severity']) for row in dr2]}"
    )


# ---------------------------------------------------------------------------
# TC-4
# ---------------------------------------------------------------------------

def test_tc4_out_of_range_write(settings: Settings, store: sqlite3.Connection,
                                thresholds: DetectionThresholds):
    """TC-4: Out-of-range write.

    SPEC.md Section 12 (verbatim):
      | TC-4: Out-of-range write | Send a write request to a register outside the
        defined operational range | DR-3 fires, High alert generated |

    DR-3 (Section 8): "Write request to a register outside the defined operational
    range" — High. The address is derived from the configured range, so retuning
    `operational_register_range` keeps the case honest.

    Note: this write also trips DR-2, because Modbus write function codes are not on
    the read-oriented allow-list. That overlap is by design in the current
    configuration; the case asserts DR-3, which is what Section 12 specifies.
    """
    low, high = thresholds.operational_register_range
    target = high + 50
    assert target > high, "test address must be outside the operational range"

    mark = snapshot(store)
    value = 0x4242
    reply = lab_traffic.write_single_register(
        settings.honeypot_host, settings.honeypot_port, address=target, value=value
    )
    print(f"[TC-4] sent FC 6 write value={value} to register {target} "
          f"(operational range {low}-{high}) -> {lab_traffic.describe_reply(reply)}")

    rows = wait_for(
        store, f"the monitor to store the write to register {target}",
        lambda: [row for row in raw_events_after(store, mark.raw_events_id, source="monitor")
                 if row["function_code"] == 6 and row["register_address"] == target],
        settings.event_timeout_seconds,
    )
    print(f"[TC-4] monitor stored raw_events id {rows[0]['id']} "
          f"fc=6 register={rows[0]['register_address']} value={rows[0]['value']}")

    run_engine_once()
    new_alerts = alerts_after(store, mark.alerts_id)
    dr3 = [row for row in new_alerts if row["rule_id"] == "DR-3"]
    print(f"[TC-4] engine wrote {[(row['rule_id'], row['severity']) for row in new_alerts]}")

    assert dr3, (
        f"DR-3 did not fire for a write to register {target}, outside the operational "
        f"range {low}-{high}. Alerts written: "
        f"{[(row['rule_id'], row['severity'], row['description'][:60]) for row in new_alerts]}"
    )
    assert all(row["severity"] == HIGH for row in dr3), (
        f"DR-3 must be High (SPEC.md Section 8), got "
        f"{[(row['rule_id'], row['severity']) for row in dr3]}"
    )


# ---------------------------------------------------------------------------
# TC-5
# ---------------------------------------------------------------------------

def test_tc5_correlation(settings: Settings, store: sqlite3.Connection,
                         thresholds: DetectionThresholds):
    """TC-5: Correlation.

    SPEC.md Section 12 (verbatim):
      | TC-5: Correlation | Trigger both a honeypot hit and a monitor anomaly from the
        same source IP within the correlation window | DR-7 fires, Critical alert,
        both source events linked in dashboard view |

    DR-7 (Section 8): "Correlated hit: same source IP in both honeypot and monitor
    logs within N minutes" — Critical, with N from `correlation_window_minutes`.

    The monitor half is generated first and asserted, so a failure here says which
    half of the correlation is missing rather than just "DR-7 did not fire".
    """
    mark = snapshot(store)

    # 1. Monitor-side anomaly: an out-of-range write from this test's address.
    low, high = thresholds.operational_register_range
    lab_traffic.write_single_register(settings.honeypot_host, settings.honeypot_port,
                                      address=high + 25, value=0x1337)
    monitor_rows = wait_for(
        store, "the monitor to store the anomaly half of the correlation",
        lambda: raw_events_after(store, mark.raw_events_id, source="monitor",
                                 src_ip=settings.client_source_ip),
        settings.event_timeout_seconds,
    )
    print(f"[TC-5] monitor side ok: raw_events id {monitor_rows[0]['id']} "
          f"fc={monitor_rows[0]['function_code']} from {monitor_rows[0]['src_ip']}")

    run_engine_once()
    monitor_alerts = [row for row in alerts_after(store, mark.alerts_id) if row["rule_id"] != "DR-7"]
    assert monitor_alerts, (
        "the monitor-side anomaly produced no alert at all, so there is nothing to "
        "correlate; investigate DR-2/DR-3 before DR-7"
    )
    print(f"[TC-5] monitor-side alert(s): "
          f"{[(row['rule_id'], row['severity']) for row in monitor_alerts]}")

    # 2. Honeypot-side hit from the same source IP, inside the correlation window.
    reply = lab_traffic.classic_read(settings.honeypot_host, settings.honeypot_port,
                                     address=0, quantity=10)
    print(f"[TC-5] honeypot hit sent from the same address -> {lab_traffic.describe_reply(reply)}")

    honeypot_rows = wait_or_empty(
        store,
        lambda: raw_events_after(store, mark.raw_events_id, source="honeypot",
                                 src_ip=settings.client_source_ip),
        settings.event_timeout_seconds,
    )
    assert honeypot_rows, _HONEYPOT_INGESTION_FAILURE.format(where="TC-5")

    # 3. With both halves present the correlation itself is asserted.
    run_engine_once()
    dr7 = [row for row in alerts_after(store, mark.alerts_id) if row["rule_id"] == "DR-7"]
    assert dr7, (
        f"DR-7 did not fire even though source {settings.client_source_ip} appears in "
        f"both logs within {thresholds.correlation_window_minutes} minute(s)"
    )
    assert all(row["severity"] == CRITICAL for row in dr7), (
        f"DR-7 must be Critical (SPEC.md Section 8), got "
        f"{[(row['rule_id'], row['severity']) for row in dr7]}"
    )
    assert all(row["correlated_event_id"] for row in dr7), (
        "DR-7 is meant to link both source events; correlated_event_id is null"
    )

    feed = dashboard_payload(settings)["feed"]
    assert any(row["rule_id"] == "DR-7" and row["correlated_event_id"] for row in feed), (
        "the dashboard feed shows no correlated DR-7 alert"
    )
    print(f"[TC-5] DR-7 linked raw_events "
          f"{[(row['event_id'], row['correlated_event_id']) for row in dr7]}")


# ---------------------------------------------------------------------------
# TC-6
# ---------------------------------------------------------------------------

def test_tc6_dashboard_accuracy(settings: Settings, store: sqlite3.Connection,
                                config: Dict[str, Any]):
    """TC-6: Dashboard accuracy.

    SPEC.md Section 12 (verbatim):
      | TC-6: Dashboard accuracy |    Compare dashboard alert count/severity against raw
        `alerts` table | Counts match exactly |

    Compares the live dashboard API against the same store it reads, exactly: total,
    all four severity buckets, the correlated count, and the identity of every row in
    the feed — so a dashboard that reported a plausible-looking wrong number would
    fail here.

    Scoped to alerts on purpose: the Phase 2 GOOSE monitor writes raw_events
    continuously, so the event stream is never quiet in this lab. Every assertion here
    is about the `alerts` table, which only the engine writes.
    """
    run_engine_once()          # drain the queue
    wait_for_quiescence(store)

    feed_limit = int(((config.get("dashboard") or {}).get("feed_limit")) or 50)

    def database_truth() -> Dict[str, Any]:
        total = store.execute("SELECT COUNT(*) AS n FROM alerts").fetchone()["n"]
        severity = {name: 0 for name in ("Critical", "High", "Medium", "Low")}
        for row in store.execute("SELECT severity, COUNT(*) AS n FROM alerts GROUP BY severity"):
            severity[str(row["severity"])] = int(row["n"])
        correlated = store.execute(
            "SELECT COUNT(*) AS n FROM alerts WHERE rule_id = 'DR-7'"
        ).fetchone()["n"]
        newest = [int(row["id"]) for row in store.execute(
            "SELECT id FROM alerts ORDER BY id DESC LIMIT ?", (feed_limit,)
        )]
        return {"total": int(total), "severity": severity, "correlated": int(correlated),
                "newest_ids": newest}

    # Two reads of live state: retry only to get a *consistent pair*, never to hide a
    # mismatch. If the store is quiescent these agree on the first attempt, and if
    # they never agree the assertion below fails with both sides printed.
    attempts = []
    for attempt in range(1, 4):
        payload = dashboard_payload(settings)
        truth = database_truth()
        attempts.append((attempt, payload, truth))
        totals = payload.get("totals") or {}
        if (totals.get("alerts_total") == truth["total"]
                and payload.get("severity") == truth["severity"]):
            break
        time.sleep(1.0)

    _, payload, truth = attempts[-1]
    totals = payload.get("totals") or {}
    feed_ids = [row["id"] for row in payload.get("feed") or []]

    print(f"[TC-6] database: total={truth['total']} severity={truth['severity']} "
          f"correlated={truth['correlated']}")
    print(f"[TC-6] dashboard: total={totals.get('alerts_total')} "
          f"severity={payload.get('severity')} "
          f"correlated={totals.get('alerts_correlated')} feed={len(feed_ids)} row(s)")

    assert totals.get("alerts_total") == truth["total"], (
        f"dashboard reports {totals.get('alerts_total')} alert(s), the alerts table "
        f"holds {truth['total']}"
    )
    assert payload.get("severity") == truth["severity"], (
        f"severity breakdown differs — dashboard {payload.get('severity')} vs "
        f"table {truth['severity']}"
    )
    assert totals.get("alerts_correlated") == truth["correlated"], (
        f"dashboard reports {totals.get('alerts_correlated')} correlated alert(s), the "
        f"table holds {truth['correlated']} DR-7 row(s)"
    )

    expected_feed = truth["newest_ids"]
    assert feed_ids == expected_feed, (
        f"feed rows differ: dashboard {feed_ids[:10]}... vs newest "
        f"{expected_feed[:10]}... (feed_limit={feed_limit})"
    )


# ---------------------------------------------------------------------------
# TC-14 (Phase 2 regression)
# ---------------------------------------------------------------------------

def test_tc14_historical_sources_not_graded(settings: Settings, store: sqlite3.Connection,
                                            config: Dict[str, Any]):
    """TC-14: Historical replay sources never affect sensor health.

    Regression guard for the dashboard fix that excludes `dashboard.historical_sources`
    (currently `swat_replay`, a one-time replay of a 2015 dataset) from the freshness
    grading. Those rows carry the *dataset's* timestamp rather than their capture time, so
    the source reads as maximally stale by design; before the fix that alone flipped the
    pipeline to `blind` — "Capture degraded" — even while every live source was reporting.

    The case drives the exact failing condition: it makes both live sources fresh (a
    benign honeypot read makes `honeypot` fresh; the GOOSE monitor keeps `monitor` fresh)
    while the replayed source is still maximally stale, then asserts the pipeline is
    `healthy`. A historical source that leaked back into the graded list would show up in
    `pipeline.sources` and re-trigger the false degradation this guards against.
    """
    dashboard_section = config.get("dashboard") or {}
    historical = [str(name).strip() for name in (dashboard_section.get("historical_sources") or [])]
    assert historical, (
        "dashboard.historical_sources is empty, so this regression cannot be exercised. "
        "It must list the bounded replay source(s) — e.g. [swat_replay] — whose rows "
        "carry historical timestamps and are therefore never freshness-graded."
    )

    # Make every live source fresh, deterministically.
    mark = snapshot(store)
    reply = lab_traffic.classic_read(
        settings.honeypot_host, settings.honeypot_port, address=0, quantity=10
    )
    print(f"[TC-14] benign honeypot read -> {lab_traffic.describe_reply(reply)}")
    assert reply is not None, (
        "the decoy did not answer the benign read, so `honeypot` cannot be made fresh "
        "and this regression cannot be exercised. Check `docker compose logs honeypot`."
    )
    honeypot_rows = wait_for(
        store, "the honeypot side to store the interaction",
        lambda: raw_events_after(store, mark.raw_events_id, source="honeypot"),
        settings.event_timeout_seconds,
    )
    print(f"[TC-14] honeypot raw_events id {honeypot_rows[0]['id']} stored")
    # Stamp a fresh heartbeat so a stale engine is never the reason the pipeline is not
    # healthy — this case is about the source grading, not about detection liveness.
    run_engine_once()

    def both_live_sources_fresh() -> Optional[Dict[str, Any]]:
        payload = dashboard_payload(settings)
        pipeline = payload.get("pipeline") or {}
        states = {entry["source"]: entry["state"] for entry in pipeline.get("sources") or []}
        expected = list(pipeline.get("expected_sources") or [])
        if expected and all(states.get(name) == "fresh" for name in expected):
            return payload
        return None

    payload = wait_for(
        store, "every expected source to read fresh on the dashboard",
        both_live_sources_fresh, settings.event_timeout_seconds,
    )
    pipeline = payload["pipeline"]
    graded = [entry["source"] for entry in pipeline["sources"]]
    print(f"[TC-14] graded sources {graded}; "
          f"pipeline state {pipeline['state']!r}")

    for name in historical:
        assert name not in graded, (
            f"historical source {name!r} is being freshness-graded: it appears in "
            f"pipeline.sources {graded}. A replayed source carries its dataset's timestamp "
            "and must be excluded, or it will read as permanently stale and wrongly "
            "degrade the pipeline."
        )

    reported = {entry["source"]: entry for entry in pipeline.get("historical") or []}
    for name in historical:
        assert name in reported, (
            f"historical source {name!r} is neither graded nor reported — it should appear "
            "in pipeline.historical so the event totals still add up"
        )
        entry = reported[name]
        assert "state" not in entry, (
            f"historical source {name!r} carries a freshness state {entry.get('state')!r}; "
            "freshness does not apply to a replayed source and must not be reported for it"
        )

    assert pipeline["state"] == "healthy", (
        f"pipeline reads {pipeline['state']!r} while every live source is fresh — the only "
        f"stale source present is the replayed {historical}, which must never degrade "
        f"health. Summary: {pipeline['summary']}"
    )
    for name in historical:
        assert name not in pipeline["summary"], (
            f"the pipeline summary names the replayed source {name!r}, so it is still being "
            f"counted as a fault: {pipeline['summary']}"
        )
    print(f"[TC-14] PASS: replayed {historical} is stale but never graded; "
          f"pipeline healthy")
