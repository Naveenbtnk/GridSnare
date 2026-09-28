#!/usr/bin/env python3
"""TC-1 .. TC-14 — the SPEC.md Section 12 and 20.6 validation & test plans, automated.

SPEC.md Section 20.6 requires each test case to be "implemented as an actual
automated test in `tests/test_scenarios.py`, not just documented here", and says the
same for Section 12. This file is that implementation for both phases. Every case
quotes its Section 12 or 20.6 row verbatim in its docstring (README instruction 4).

The Phase 2 cases (TC-7 .. TC-13) are in the "Phase 2 — GOOSE" section below. They
read the same store and the same dashboard API as Phase 1's, and they differ in one
way that shapes every one of them: a GOOSE frame is not a request with a reply to wait
for. Nothing acknowledges it, so each case proves its own traffic landed — from an
independent capture on this container and from the GOOSE traffic monitor's record —
before it credits or blames a rule. Section 20.6's TC-8 is the case most exposed to
that failure mode: "no alerts" and "no traffic" look identical without that check.

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
from typing import Any, Callable, Dict, List, Optional, Tuple

import pytest
import yaml

sys.path.insert(0, str(Path(__file__).resolve().parent))

import goose_traffic  # noqa: E402  (path bootstrap must run first)
import lab_traffic  # noqa: E402

from engine.goose_rules import GooseRuleContext, GooseThresholds  # noqa: E402
from engine.rules import DetectionThresholds, parse_event_timestamp  # noqa: E402

REPO_ROOT = Path(__file__).resolve().parents[1]
CONFIG_PATH = REPO_ROOT / "config.yaml"

# Severity vocabulary from SPEC.md Section 7.3.
CRITICAL = "Critical"
HIGH = "High"
MEDIUM = "Medium"

# Link addresses this runner uses to forge GOOSE frames. They are not on GR-2's
# allow-list and are shaped like locally administered unicast addresses (the 02: prefix
# is the locally-administered bit), so they cannot collide with a real device's MAC or
# with the lab's two pinned publisher addresses (02:00:5e:00:53:01 / :02).
FORGED_TRIP_MAC = "02:00:5e:00:53:99"       # TC-7 / TC-13: a forged trip on the decoy
FORGED_PUBLISHER_MAC = "02:00:5e:00:53:9a"  # TC-10: a spoofed publisher on a real block


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
# Phase 2 settings and fixtures (SPEC.md Section 20.6)
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class GooseSettings:
    """What the GOOSE cases need from config.yaml's `tests:` section.

    Separate from `Settings` rather than added to it: the Phase 1 cases run without
    CAP_NET_RAW and without a GOOSE-aware interface, and folding these in would make
    every one of them depend on Phase 2's deployment.
    """

    interface: str
    address: str
    baseline_seconds: float
    flood_frames: int
    drain_timeout_seconds: float


@pytest.fixture(scope="session")
def goose_settings(config: Dict[str, Any], settings: Settings) -> GooseSettings:
    section = config.get("tests") or {}

    def number(env_name: str, key: str, default: float) -> float:
        raw = _setting(env_name, section, key, default)
        try:
            return float(raw)
        except (TypeError, ValueError):
            pytest.fail(f"tests.{key} must be a number, got {raw!r}")

    # The interface this runner injects on and captures from. config.yaml says 'auto',
    # which resolves it from the address this container holds on the monitored segment:
    # a two-network container's interface names are not the ones docker-compose.yml lists
    # (measured here: eth0 is the dashboard network, eth1 the segment, and the order has
    # varied between runs), and injecting on the wrong one still succeeds at the socket
    # level — the frame just never reaches the segment. Choosing by name would therefore
    # make every case in this section pass or fail by luck.
    configured = str(_setting("GRIDSNARE_GOOSE_INTERFACE", section, "goose_interface", "auto")).strip()
    addresses = goose_traffic.interface_addresses()
    if configured.lower() == "auto":
        interface = goose_traffic.interface_for_address(settings.client_source_ip)
        if interface is None:
            pytest.fail(
                f"no interface in this container holds {settings.client_source_ip}, the address "
                f"tests.client_source_ip says this runner has on the monitored segment "
                f"(interfaces: {addresses}). The GOOSE cases inject and capture on that "
                "segment, and without it they would be sending frames into a network nothing "
                "is watching."
            )
    else:
        interface = configured
        if interface not in addresses:
            pytest.fail(
                f"tests.goose_interface names {interface!r}, which this container does not "
                f"have: {sorted(addresses)}"
            )
    print(f"[GOOSE] injecting and capturing on {interface} "
          f"({addresses[interface]}, tests.client_source_ip={settings.client_source_ip})")

    return GooseSettings(
        interface=interface,
        address=settings.client_source_ip,
        baseline_seconds=number("GRIDSNARE_GOOSE_BASELINE_SECONDS", "goose_baseline_seconds", 25),
        flood_frames=int(number("GRIDSNARE_GOOSE_FLOOD_FRAMES", "goose_flood_frames", 320)),
        drain_timeout_seconds=number(
            "GRIDSNARE_GOOSE_DRAIN_TIMEOUT", "goose_drain_timeout_seconds", 180
        ),
    )


@pytest.fixture(scope="session")
def goose_thresholds(config: Dict[str, Any]) -> GooseThresholds:
    """The same validated `engine.goose` thresholds the engine runs with.

    Loaded by the engine's own code, like `thresholds` above, so a case cannot disagree
    with the engine about what the allow-list or the timing limit says.
    """
    from engine.rules import RuleConfigError

    try:
        return GooseThresholds.from_mapping((config.get("engine") or {}).get("goose"))
    except RuleConfigError as exc:
        pytest.fail(f"engine.goose is not usable: {exc}")


@pytest.fixture(scope="session")
def injector(goose_settings: GooseSettings):
    """A raw socket for putting GOOSE frames on the lab segment.

    Opened once for the session: it holds no state between cases, and the capability it
    needs (CAP_NET_RAW) is either present for the whole run or absent for it. A missing
    capability fails here, once, with that reason — rather than inside six cases as six
    socket errors.
    """
    try:
        sock = goose_traffic.open_injector(goose_settings.interface)
    except goose_traffic.InjectionUnavailable as exc:
        pytest.fail(str(exc))
    yield sock
    sock.close()


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

def run_engine_once(attempts: int = 4) -> str:
    """Run exactly one engine poll cycle, the way the stack runs it.

    Called as a subprocess so the test exercises the engine's real entry point
    rather than importing a function the running container might not use. One pass
    instead of a wait on the background loop keeps the plan deterministic; because
    alerts are de-duplicated on (rule_id, event_id), running this while the loop is
    also running cannot produce duplicates.

    A pass that fails on a *locked* store is retried, and only that. The store is one
    SQLite file with four writers on a bind mount — both traffic monitors (the GOOSE one
    committing once per captured frame), the background engine, and this pass — and SQLite
    answers a write it cannot lock with "database is locked" instead of waiting forever.
    A timing-anomaly flood is exactly when that happens, because the monitor is writing
    flat out underneath it. That is a property of the shared store rather than a detection
    result, and the pass is safe to repeat (alerts are de-duplicated on (rule_id, event_id)
    and the watermark only ever moves forward), so the retry finishes the work instead of
    reporting a rule failure that never happened. Any other non-zero exit is reported as
    it stands.
    """
    failure: Optional[str] = None
    for attempt in range(1, attempts + 1):
        completed = subprocess.run(
            [sys.executable, "-m", "engine.correlator", "--once"],
            cwd=str(REPO_ROOT), capture_output=True, text=True, timeout=120,
        )
        output = (completed.stdout or "").strip()
        if completed.returncode == 0:
            return output
        stderr = (completed.stderr or "").strip()
        failure = (
            f"engine pass failed (exit {completed.returncode}, attempt {attempt}/{attempts})\n"
            f"  stdout: {output}\n  stderr: {stderr}"
        )
        if "database is locked" not in stderr:
            break
        if attempt < attempts:
            print(f"[engine] attempt {attempt} hit a locked store; retrying")
            time.sleep(2.0 * attempt)
    pytest.fail(failure or "engine pass failed for an unknown reason")


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
# Phase 2 — GOOSE (SPEC.md Section 20.6, TC-7 .. TC-13)
# ---------------------------------------------------------------------------
#
# These cases differ from Phase 1's in one way that shapes all of them. A Modbus case
# sends a request and gets a reply, so "the decoy answered" is evidence the traffic
# landed. A GOOSE frame is a raw Ethernet frame put on the segment that nothing
# acknowledges, so each case below proves its own traffic landed twice — once from an
# independent capture on this container, once from the GOOSE traffic monitor's record —
# before it credits or blames a rule. Without that check a case whose frames never left
# the container would report a passing "no alert" result, which is exactly how SPEC.md
# 20.6's TC-8 could pass while measuring nothing.

def goose_rows_after(store: sqlite3.Connection, after_id: int, src_mac: Optional[str] = None,
                     gocb_ref: Optional[str] = None) -> List[sqlite3.Row]:
    query = "SELECT * FROM raw_events WHERE protocol = 'goose' AND id > ?"
    params: List[Any] = [after_id]
    if src_mac is not None:
        query += " AND src_mac = ?"
        params.append(src_mac)
    if gocb_ref is not None:
        query += " AND gocb_ref = ?"
        params.append(gocb_ref)
    query += " ORDER BY id"
    return list(store.execute(query, params))


def next_st_num(store: sqlite3.Connection, src_mac: str, gocb_ref: str) -> int:
    """A StNum this (MAC, control block) pair has never used.

    The forged frames in TC-7, TC-10 and TC-13 come from a link address that is reused on
    every run, so a fixed StNum would make the second run a duplicate of the first — a
    genuine GR-1 finding layered on top of the rule each case is actually asserting. An
    attacker injecting a trip advances StNum anyway (that is what a state change *is*), so
    continuing the sequence is both the honest choice and the one that isolates the rule.
    """
    row = store.execute(
        "SELECT COALESCE(MAX(st_num), 0) AS top FROM raw_events "
        "WHERE protocol = 'goose' AND src_mac = ? AND gocb_ref = ?",
        (src_mac, gocb_ref),
    ).fetchone()
    return int(row["top"]) + 1


def alerts_for_event(alerts: List[sqlite3.Row], event_id: Any) -> List[sqlite3.Row]:
    """The alerts the engine raised *for one captured frame*.

    Scoping to the event id rather than to (rule, severity) is what makes each Phase 2
    case a statement about its own frame: an alert with the right rule id that came from
    some other device's traffic is not evidence for this case.
    """
    return [row for row in alerts if row["event_id"] == event_id]


def busiest_window(store: sqlite3.Connection, after_id: int, src_mac: str, gocb_ref: str,
                   window_seconds: float) -> Tuple[int, int]:
    """(most frames in any trailing window, total frames) for one publisher.

    GR-3's own measurement (engine/goose_rules.py counts frames in a trailing window per
    publisher), recomputed here so a case can report what it actually produced rather
    than only that an alert appeared.
    """
    rows = store.execute(
        "SELECT timestamp FROM raw_events WHERE protocol = 'goose' AND src_mac = ? "
        "AND gocb_ref = ? AND id > ? ORDER BY timestamp",
        (src_mac, gocb_ref, after_id),
    ).fetchall()
    moments = [parse_event_timestamp(str(row["timestamp"])) for row in rows]
    best = 0
    start = 0
    for end, moment in enumerate(moments):
        while moment - moments[start] > timedelta(seconds=window_seconds):
            start += 1
        best = max(best, end - start + 1)
    return best, len(moments)


def describe_alert(store: sqlite3.Connection, alert: sqlite3.Row) -> str:
    """One alert, with the event it points at — the form a failure message needs.

    The `alerts` table has no src_mac column: a GOOSE alert names its publisher through
    the event it references, not through a column of its own (see store.py). Reading one
    from the alert row raises sqlite3.IndexError, which is a confusing way to learn that —
    so the publisher is looked up where every other reader looks for it, in raw_events.
    """
    event = store.execute(
        "SELECT protocol, src_mac, src_ip FROM raw_events WHERE id = ?", (alert["event_id"],)
    ).fetchone()
    where = "no matching event" if event is None else (
        f"event {alert['event_id']} is {event['protocol']}: "
        f"src_ip={event['src_ip']} src_mac={event['src_mac']}"
    )
    return f"{alert['rule_id']} {alert['severity']} ({alert['protocol']}; {where})"


def engine_watermark(store: sqlite3.Connection) -> Optional[int]:
    row = store.execute(
        "SELECT value FROM engine_state WHERE key = 'raw_events_watermark'"
    ).fetchone()
    if row is None:
        return None
    try:
        return int(row["value"])
    except (TypeError, ValueError):
        return None


def drain_engine(store: sqlite3.Connection, timeout: float, description: str,
                 target_id: Optional[int] = None) -> int:
    """Run engine passes until the watermark covers `target_id` (default: every row).

    Every Phase 2 case drives the engine this way rather than with a single `--once`
    pass, because a timing-anomaly flood puts hundreds of rows in the store at once and
    one pass over a backlog that size is not instantaneous (measured: ~22ms per GOOSE
    row on this bind-mounted store). Waiting for the watermark means the alert a case
    asserts on has definitely been judged instead of merely queued — and the engine stays
    the only writer, so no test edits the database (SPEC.md Section 13).
    """
    if target_id is None:
        target_id = int(
            store.execute("SELECT COALESCE(MAX(id), 0) AS n FROM raw_events").fetchone()["n"]
        )
    deadline = time.monotonic() + timeout
    passes = 0
    while time.monotonic() < deadline:
        watermark = engine_watermark(store)
        if watermark is not None and watermark >= target_id:
            return passes
        run_engine_once()
        passes += 1
    pytest.fail(
        f"engine_state.raw_events_watermark did not reach raw_events id {target_id} within "
        f"{timeout:.0f}s while draining {description} ({passes} engine pass(es) run).\n"
        f"  store at the time of failure:\n{store_diagnosis(store)}"
    )


def goose_action(description: str, action: Callable[[], Any]) -> Any:
    """Run a raw-socket action, turning a missing capability into a clear failure."""
    try:
        return action()
    except goose_traffic.InjectionUnavailable as exc:
        pytest.fail(f"{description}: {exc}")


def assert_conforming_sequence(pairs: List[Any], description: str) -> None:
    """Assert a sequence is one GR-1 must accept: SqNum advances within a StNum, and
    StNum never goes backwards (IEC 61850-8-1)."""
    for (prev_st, prev_sq), (cur_st, cur_sq) in zip(pairs, pairs[1:]):
        assert cur_st >= prev_st, (
            f"{description}: StNum went backwards, {prev_st} then {cur_st}. A legitimate "
            "publisher only ever advances it (SPEC.md 20.3 GR-1)."
        )
        assert not (cur_st == prev_st and cur_sq <= prev_sq), (
            f"{description}: SqNum did not advance within StNum {cur_st} ({prev_sq} then "
            f"{cur_sq}). A legitimate publisher increments SqNum on every frame and resets "
            "it only on a StNum change (SPEC.md 20.3 GR-1)."
        )


def test_tc7_decoy_detection(settings: Settings, goose_settings: GooseSettings,
                             goose_thresholds: GooseThresholds, store: sqlite3.Connection,
                             config: Dict[str, Any], injector):
    """TC-7: Decoy detection.

    SPEC.md Section 20.6 (verbatim):
      | TC-7: Decoy detection | Send a GOOSE frame referencing the decoy IED's GoCB |
        GR-4 fires, Critical alert |

    GR-4 (Section 20.3): "Any GOOSE traffic referencing the decoy IED's GoCB" — Critical,
    because "decoy has no legitimate subscribers/publishers". The frame is built from the
    decoy's *own* published identity (its GoCB reference, dataset, APPID and multicast
    destination, all read from config.yaml) and sent from a link address that is not the
    decoy's — which is what an attacker who captured the decoy's traffic and forged a trip
    from it would put on the wire.
    """
    decoy = goose_traffic.decoy_endpoint(config)
    assert decoy.src_mac == goose_thresholds.decoy_src_mac, (
        f"the decoy's configured MAC ({decoy.src_mac}) is not the one GR-4 treats as the "
        f"decoy's own ({goose_thresholds.decoy_src_mac}); this case would forge a frame "
        "the rule does not read the way it expects"
    )
    attacker = FORGED_TRIP_MAC
    assert attacker != decoy.src_mac, "the forged trip has to come from a link address that is not the decoy's"

    drain_engine(store, goose_settings.drain_timeout_seconds, "traffic from earlier cases")
    st_num = next_st_num(store, attacker, decoy.gocb_ref)
    mark = snapshot(store)
    frame = goose_traffic.build(decoy.with_src_mac(attacker), st_num=st_num, sq_num=1, trip=True)
    print(f"[TC-7] injecting a forged trip: {goose_traffic.describe_bytes(frame)}")
    goose_action("TC-7 needs raw socket access to inject the forged trip",
                 lambda: goose_traffic.send_frames(injector, [frame]))

    rows = wait_for(
        store, "the GOOSE monitor to store the forged trip",
        lambda: goose_rows_after(store, mark.raw_events_id, src_mac=attacker,
                                 gocb_ref=decoy.gocb_ref),
        settings.event_timeout_seconds,
    )
    injected = rows[0]
    print(f"[TC-7] monitor stored raw_events id {injected['id']}: gocb={injected['gocb_ref']} "
          f"src_mac={injected['src_mac']} stNum={injected['st_num']} sqNum={injected['sq_num']}")

    drain_engine(store, goose_settings.drain_timeout_seconds, "the forged trip",
                 target_id=int(injected["id"]))
    findings = alerts_for_event(alerts_after(store, mark.alerts_id), injected["id"])
    print(f"[TC-7] engine wrote {[(row['rule_id'], row['severity'], row['protocol']) for row in findings]}")

    gr4 = [row for row in findings if row["rule_id"] == "GR-4"]
    assert gr4, (
        f"GR-4 did not fire for a frame claiming the decoy's control block {decoy.gocb_ref} "
        f"from {attacker} (raw_events id {injected['id']}). The engine wrote:"
        f"{[(row['rule_id'], row['severity']) for row in findings]}"
    )
    assert all(row["severity"] == CRITICAL for row in gr4), (
        f"GR-4 must be Critical (SPEC.md 20.3), got "
        f"{[(row['rule_id'], row['severity']) for row in gr4]}"
    )
    assert all(row["protocol"] == "goose" for row in gr4), (
        "the alert must carry the GOOSE protocol tag (SPEC.md 20.3), got "
        f"{[(row['rule_id'], row['protocol']) for row in gr4]}"
    )
    # One finding, not two: GR-2 deliberately leaves the decoy's own control block to
    # GR-4, so an impostor on it does not also raise a spoofing alert.
    assert not [row for row in findings if row["rule_id"] == "GR-2"], (
        "GR-2 also fired on the decoy's own control block. It must not: the decoy's block "
        "is GR-4's subject, and two Critical findings for one frame is noise an operator "
        "has to reconcile (see engine/goose_rules.py)."
    )
    assert not [row for row in findings if row["rule_id"] in ("GR-1", "GR-3")], (
        f"this link address has never published this control block before and sent one "
        f"frame, so there is nothing for GR-1 or GR-3 to judge; got "
        f"{[(row['rule_id'], row['severity']) for row in findings]}"
    )
    print("[TC-7] PASS: one Critical GR-4 for the forged trip, no duplicate GR-2")


def test_tc8_baseline_no_false_positive(settings: Settings, goose_settings: GooseSettings,
                                        goose_thresholds: GooseThresholds,
                                        store: sqlite3.Connection, config: Dict[str, Any]):
    """TC-8: Baseline traffic (no false positive) — the GOOSE side.

    SPEC.md Section 20.6 (verbatim):
      | TC-8: Baseline traffic (no false positive) | Run whitelisted GOOSE publisher
        traffic for a defined period | No false-positive alerts |

    SPEC.md Section 11 names the publisher this has to watch: "a legitimate GOOSE
    publisher distinct from the decoy IED is required for TC-8". Nothing here is aimed at
    the decoy, so a Critical GR-4 during this window would be a genuine false positive
    rather than the rule set working.

    The window is longer than the publisher's state-change cycle on purpose, and the case
    asserts that a burst really happened inside it: the retransmission profile is the
    shape GR-3 is tuned against, so a baseline that never exercised it would leave the
    rule that most risks false-positiving on legitimate traffic untested.
    """
    publisher = goose_traffic.publisher_endpoint(config)
    known = goose_traffic.known_publishers(config)
    allowed = known.get(publisher.gocb_ref)

    assert allowed, (
        f"the legitimate publisher's control block {publisher.gocb_ref} has no entry in "
        f"engine.goose.known_publishers, so GR-2 would flag the baseline by configuration "
        f"error rather than by false positive. Allow-list: {sorted(known)}"
    )
    assert publisher.src_mac in allowed, (
        f"the publisher's MAC {publisher.src_mac} is not allow-listed for "
        f"{publisher.gocb_ref} (allowed: {allowed}), so GR-2 fires on its own baseline"
    )
    assert publisher.gocb_ref != goose_thresholds.decoy_gocb_ref, (
        "this case's baseline publisher is the decoy's own control block. Section 11 and "
        "TC-8 both require a publisher distinct from the decoy: every frame here would be "
        "a Critical GR-4 finding, and the case would be asserting the opposite of the "
        "rule set's intent."
    )
    assert publisher.src_mac != goose_thresholds.decoy_src_mac, (
        "the baseline publisher must not be the decoy's link address for the same reason"
    )

    drain_engine(store, goose_settings.drain_timeout_seconds, "traffic from earlier cases")
    mark = snapshot(store)
    print(f"[TC-8] watching the legitimate publisher ({publisher.src_mac} on "
          f"{publisher.gocb_ref}) for {goose_settings.baseline_seconds:.0f}s")

    captured = goose_action(
        "TC-8 needs raw socket access to capture the baseline",
        lambda: goose_traffic.capture(goose_settings.interface, goose_settings.baseline_seconds),
    )
    ours = goose_traffic.frames_for(captured, publisher)
    assert ours, (
        f"no frame from the legitimate publisher ({publisher.src_mac} on "
        f"{publisher.gocb_ref}) reached this container's capture in "
        f"{goose_settings.baseline_seconds:.0f}s, so this case would pass while measuring "
        "nothing. The publisher is a required component (SPEC.md Section 11); check "
        "`docker compose logs goose-publisher` and `docker compose ps goose-publisher`."
    )
    pairs = goose_traffic.sequence_of(ours)
    st_nums = sorted({st for st, _ in pairs})
    print(f"[TC-8] captured {len(ours)} frame(s) from {publisher.src_mac}: "
          f"{len(st_nums)} distinct StNum(s) {st_nums} "
          f"(bursts are what the configured retransmission profile produces)")
    assert_conforming_sequence(pairs, "the legitimate publisher's frames on the wire")
    assert len(st_nums) >= 2, (
        f"the baseline window captured {len(ours)} frame(s) but only StNum {st_nums} — no "
        "state change happened inside it, so the retransmission burst was never exercised "
        "and GR-3's subject went untested. Raise tests.goose_baseline_seconds above "
        "goose_publisher.state_change_cycle_seconds (20s)."
    )

    stored = wait_for(
        store, "the GOOSE monitor to store the baseline frames",
        lambda: goose_rows_after(store, mark.raw_events_id, src_mac=publisher.src_mac,
                                 gocb_ref=publisher.gocb_ref),
        settings.event_timeout_seconds,
    )
    print(f"[TC-8] the GOOSE monitor stored {len(stored)} of those frame(s)")
    assert_conforming_sequence(
        [(int(row["st_num"]), int(row["sq_num"])) for row in stored],
        "the monitor's record of the baseline",
    )

    drain_engine(store, goose_settings.drain_timeout_seconds, "the baseline window",
                 target_id=int(stored[-1]["id"]))
    new_alerts = alerts_after(store, mark.alerts_id)
    print(f"[TC-8] {len(new_alerts)} alert(s) raised during the baseline window")
    assert not new_alerts, (
        f"the legitimate publisher's baseline produced {len(new_alerts)} alert(s): "
        f"{[describe_alert(store, row) for row in new_alerts]}. "
        "Baseline traffic is supposed to be invisible to GR-1..GR-4 (SPEC.md 20.6 TC-8)."
    )
    print("[TC-8] PASS: a conforming publisher (burst and heartbeat) raised nothing")


def test_tc9_replay_detection(settings: Settings, goose_settings: GooseSettings,
                               goose_thresholds: GooseThresholds, store: sqlite3.Connection,
                               config: Dict[str, Any], injector):
    """TC-9: Replay detection.

    SPEC.md Section 20.6 (verbatim):
      | TC-9: Replay detection | Capture a legitimate GOOSE frame sequence, retransmit it
        out of expected StNum/SqNum order | GR-1 fires, High alert |

    The sequence is captured off the wire from the legitimate publisher (Section 11), not
    synthesised, and the frame that is replayed is one of those captured frames re-sent
    out of its place — with the publisher's own source MAC, which is what a replay of
    captured bytes looks like on the segment. That matters for which rule fires: with the
    publisher's allow-listed MAC the frame is not a spoof (GR-2 stays silent), so the only
    thing wrong with it is its sequence position (GR-1).

    GR-1 compares a frame against the immediately preceding frame from the same publisher,
    so the case asserts that precondition explicitly rather than assuming it: it waits for
    the monitor to hold a frame strictly newer than the one being replayed, then proves the
    predecessor really is that newer frame before asserting the alert.
    """
    publisher = goose_traffic.publisher_endpoint(config)
    known = goose_traffic.known_publishers(config)
    assert publisher.src_mac in (known.get(publisher.gocb_ref) or []), (
        f"the replayed frame carries {publisher.src_mac}, which must be the allow-listed "
        f"publisher for {publisher.gocb_ref} or GR-2 would report a spoof instead of a "
        f"replay"
    )

    drain_engine(store, goose_settings.drain_timeout_seconds, "traffic from earlier cases")
    mark = snapshot(store)
    captured = goose_action(
        "TC-9 needs raw socket access to capture a legitimate sequence",
        lambda: goose_traffic.capture(goose_settings.interface, 8.0),
    )
    ours = goose_traffic.frames_for(captured, publisher)
    assert len(ours) >= 2, (
        f"only {len(ours)} frame(s) from the legitimate publisher "
        f"({publisher.src_mac} on {publisher.gocb_ref}) were captured in 8s, so there is no "
        "sequence to replay. The publisher heartbeats every "
        f"{config['goose_publisher'].get('heartbeat_seconds')}s — check "
        "`docker compose logs goose-publisher`."
    )
    pairs = goose_traffic.sequence_of(ours)
    print(f"[TC-9] captured a legitimate sequence: {pairs}")
    assert_conforming_sequence(pairs, "the captured sequence")

    # The oldest captured frame is the one re-sent: a captured frame put back on the wire
    # out of its place in the sequence.
    replayed_st, replayed_sq = min(pairs)
    newest_st, newest_sq = pairs[-1]
    assert (newest_st, newest_sq) > (replayed_st, replayed_sq), (
        f"the captured sequence did not advance ({pairs}), so replaying "
        f"({replayed_st}, {replayed_sq}) would not be out of order"
    )
    print(f"[TC-9] replaying the captured frame stNum={replayed_st} sqNum={replayed_sq} "
          f"(the publisher has since reached stNum={newest_st} sqNum={newest_sq})")

    # GR-1's precondition: the predecessor of the replayed frame must be strictly newer.
    wait_for(
        store, "the monitor to store a frame newer than the one being replayed",
        lambda: [row for row in goose_rows_after(store, mark.raw_events_id,
                                                src_mac=publisher.src_mac,
                                                gocb_ref=publisher.gocb_ref)
                 if (int(row["st_num"]), int(row["sq_num"])) > (replayed_st, replayed_sq)],
        settings.event_timeout_seconds,
    )

    mark = snapshot(store)
    frame = goose_traffic.build(publisher, st_num=replayed_st, sq_num=replayed_sq, trip=False)
    print(f"[TC-9] injecting the replay: {goose_traffic.describe_bytes(frame)}")
    goose_action("TC-9 needs raw socket access to inject the replay",
                 lambda: goose_traffic.send_frames(injector, [frame]))

    rows = wait_for(
        store, "the GOOSE monitor to store the replayed frame",
        lambda: [row for row in goose_rows_after(store, mark.raw_events_id,
                                                src_mac=publisher.src_mac,
                                                gocb_ref=publisher.gocb_ref)
                 if int(row["st_num"]) == replayed_st and int(row["sq_num"]) == replayed_sq],
        settings.event_timeout_seconds,
    )
    injected = rows[0]
    print(f"[TC-9] monitor stored raw_events id {injected['id']} at stNum={injected['st_num']} "
          f"sqNum={injected['sq_num']}")

    predecessor = GooseRuleContext(connection=store, thresholds=goose_thresholds).previous_frame(
        publisher.src_mac, publisher.gocb_ref, injected["id"]
    )
    assert predecessor is not None and (
        int(predecessor["st_num"]), int(predecessor["sq_num"])
    ) > (replayed_st, replayed_sq), (
        f"the frame GR-1 compares against (raw_events id {None if predecessor is None else predecessor['id']}, "
        f"stNum/sqNum {None if predecessor is None else (predecessor['st_num'], predecessor['sq_num'])}) "
        f"is not newer than the replay ({replayed_st}, {replayed_sq}), so nothing about the "
        "replay is out of order and this case is not exercising GR-1"
    )

    drain_engine(store, goose_settings.drain_timeout_seconds, "the replayed frame",
                 target_id=int(injected["id"]))
    findings = alerts_for_event(alerts_after(store, mark.alerts_id), injected["id"])
    print(f"[TC-9] engine wrote {[(row['rule_id'], row['severity'], row['protocol']) for row in findings]}")

    gr1 = [row for row in findings if row["rule_id"] == "GR-1"]
    assert gr1, (
        f"GR-1 did not fire for a replayed frame: stNum/sqNum ({replayed_st}, {replayed_sq}) "
        f"was re-sent from {publisher.src_mac} after the publisher had reached "
        f"({predecessor['st_num']}, {predecessor['sq_num']}). The engine wrote: "
        f"{[(row['rule_id'], row['severity']) for row in findings]}"
    )
    assert all(row["severity"] == HIGH for row in gr1), (
        f"GR-1 must be High (SPEC.md 20.3), got "
        f"{[(row['rule_id'], row['severity']) for row in gr1]}"
    )
    assert all(row["protocol"] == "goose" for row in gr1), (
        f"the alert must carry the GOOSE protocol tag, got "
        f"{[(row['rule_id'], row['protocol']) for row in gr1]}"
    )
    assert not [row for row in findings if row["rule_id"] == "GR-2"], (
        "GR-2 also fired. The replayed frame carries the publisher's own allow-listed "
        "MAC, so the finding is a sequence violation only — a spoof would be a different "
        "case (TC-10)."
    )
    print("[TC-9] PASS: High GR-1 for the out-of-order replay, no GR-2 on the same frame")


def test_tc10_spoofing_detection(settings: Settings, goose_settings: GooseSettings,
                                 goose_thresholds: GooseThresholds, store: sqlite3.Connection,
                                 config: Dict[str, Any], injector):
    """TC-10: Spoofing.

    SPEC.md Section 20.6 (verbatim):
      | TC-10: Spoofing | Transmit a GOOSE frame with a source MAC that is not on the
        allow-list for that GoCB | GR-2 fires, Critical alert |

    GR-2 (Section 20.3): "Source MAC address does not match the known-publisher allow-list
    for a given GoCB reference", because "a legitimate relay's MAC is fixed and known". The
    frame claims a *real* control block — the legitimate publisher's — from a link address
    that control block's allow-list does not name, which is precisely a spoof and not a
    malformed frame.
    """
    publisher = goose_traffic.publisher_endpoint(config)
    known = goose_traffic.known_publishers(config)
    allowed = known.get(publisher.gocb_ref) or []
    assert allowed, (
        f"{publisher.gocb_ref} has no allow-listed publisher in engine.goose.known_publishers, "
        "so there would be nothing for a spoof to deviate from"
    )
    impostor = FORGED_PUBLISHER_MAC
    assert impostor not in allowed, (
        f"{impostor} is on the allow-list for {publisher.gocb_ref} ({allowed}), so the frame "
        "would be legitimate and this case would prove nothing"
    )

    drain_engine(store, goose_settings.drain_timeout_seconds, "traffic from earlier cases")
    st_num = next_st_num(store, impostor, publisher.gocb_ref)
    mark = snapshot(store)
    frame = goose_traffic.build(publisher.with_src_mac(impostor), st_num=st_num, sq_num=1)
    print(f"[TC-10] injecting a spoofed publisher: {goose_traffic.describe_bytes(frame)}")
    print(f"[TC-10] {publisher.gocb_ref} is allow-listed for {allowed}; "
          f"the frame claims it from {impostor}")
    goose_action("TC-10 needs raw socket access to inject the spoofed frame",
                 lambda: goose_traffic.send_frames(injector, [frame]))

    rows = wait_for(
        store, "the GOOSE monitor to store the spoofed frame",
        lambda: goose_rows_after(store, mark.raw_events_id, src_mac=impostor,
                                 gocb_ref=publisher.gocb_ref),
        settings.event_timeout_seconds,
    )
    injected = rows[0]
    print(f"[TC-10] monitor stored raw_events id {injected['id']} from "
          f"{injected['src_mac']} claiming {injected['gocb_ref']}")

    drain_engine(store, goose_settings.drain_timeout_seconds, "the spoofed frame",
                 target_id=int(injected["id"]))
    findings = alerts_for_event(alerts_after(store, mark.alerts_id), injected["id"])
    print(f"[TC-10] engine wrote {[(row['rule_id'], row['severity'], row['protocol']) for row in findings]}")

    gr2 = [row for row in findings if row["rule_id"] == "GR-2"]
    assert gr2, (
        f"GR-2 did not fire for a frame claiming {publisher.gocb_ref} from {impostor}, which "
        f"is not on that control block's allow-list {allowed}. The engine wrote: "
        f"{[(row['rule_id'], row['severity']) for row in findings]}"
    )
    assert all(row["severity"] == CRITICAL for row in gr2), (
        f"GR-2 must be Critical (SPEC.md 20.3), got "
        f"{[(row['rule_id'], row['severity']) for row in gr2]}"
    )
    assert all(row["protocol"] == "goose" for row in gr2), (
        f"the alert must carry the GOOSE protocol tag, got "
        f"{[(row['rule_id'], row['protocol']) for row in gr2]}"
    )
    # This control block belongs to a real device, so the finding is spoofing (GR-2) and
    # not an impersonation of the decoy (GR-4); and it is one frame from a link address
    # with no earlier history, so there is no sequence for GR-1 to judge.
    assert not [row for row in findings if row["rule_id"] in ("GR-1", "GR-4")], (
        f"only GR-2 should fire for this frame — {publisher.gocb_ref} is not the decoy's "
        f"control block and this address has no earlier frames. Got "
        f"{[(row['rule_id'], row['severity']) for row in findings]}"
    )
    print("[TC-10] PASS: one Critical GR-2 for the spoofed source MAC")


def test_tc11_timing_anomaly(settings: Settings, goose_settings: GooseSettings,
                             goose_thresholds: GooseThresholds, store: sqlite3.Connection,
                             config: Dict[str, Any], injector):
    """TC-11: Timing anomaly.

    SPEC.md Section 20.6 (verbatim):
      | TC-11: Timing anomaly | Transmit GOOSE frames at an interval inconsistent with the
        configured retransmission profile | GR-3 fires, Medium alert |

    GR-3 (Section 20.3) flags retransmission timing that "deviates from the configured
    GOOSE timing profile", because "anomalous timing suggests an unauthorized or
    malfunctioning publisher". The frame rate here is what no profile can produce: the
    configured burst is 8 frames over ~2.3s followed by a 2s heartbeat, and this sends
    hundreds of frames as fast as the socket takes them.

    The frames continue the decoy's own sequence rather than restarting it, and carry the
    decoy's own MAC, so the only thing wrong with them is *when* they were sent: a
    restarted sequence would also be a legitimate GR-1 finding (High) and the case could
    no longer attribute the Medium alert to timing. The flood still leaves one sequence
    consequence, and the case reports it rather than pretending otherwise: the decoy's next
    real frame is compared against the flooded sequence and may itself be flagged by GR-1,
    because nothing on the wire distinguishes an attacker forging a publisher's identity
    from that publisher misbehaving.
    """
    decoy = goose_traffic.decoy_endpoint(config)
    latest = store.execute(
        "SELECT * FROM raw_events WHERE protocol = 'goose' AND src_mac = ? AND gocb_ref = ? "
        "ORDER BY id DESC LIMIT 1",
        (decoy.src_mac, decoy.gocb_ref),
    ).fetchone()
    assert latest is not None, (
        f"the decoy IED ({decoy.src_mac}) has published nothing on {decoy.gocb_ref}, so there "
        "is no sequence for this flood to continue. Check `docker compose logs goose`."
    )
    # Start well above the decoy's newest SqNum: the flood has to be *ahead* of the real
    # publisher, or its own first frames would be out of sequence and fire GR-1.
    first_st = int(latest["st_num"])
    first_sq = int(latest["sq_num"]) + 1000
    threshold = goose_thresholds.timing_max_frames_per_window
    window = goose_thresholds.timing_window_seconds
    print(f"[TC-11] the decoy's newest frame is stNum={first_st} sqNum={latest['sq_num']}; "
          f"flooding {goose_settings.flood_frames} frame(s) from stNum={first_st} "
          f"sqNum={first_sq} with no interval, against a limit of {threshold} frame(s) "
          f"per {window:g}s")

    drain_engine(store, goose_settings.drain_timeout_seconds, "traffic from earlier cases")
    mark = snapshot(store)
    frames = goose_traffic.sequence(
        decoy, first_st=first_st, first_sq=first_sq, count=goose_settings.flood_frames
    )
    sent = goose_action("TC-11 needs raw socket access to flood the segment",
                        lambda: goose_traffic.send_frames(injector, frames))
    print(f"[TC-11] sent {sent} frame(s)")

    # The monitor stores roughly one frame per commit and the socket drops whatever it
    # cannot keep up with, so the flood reaches the store over a few seconds. Wait for it
    # to be *measurably* over the limit — the same quantity GR-3 reads — rather than for a
    # fixed delay, then let it finish before reporting what the window actually held.
    def over_limit() -> Optional[int]:
        count, total = busiest_window(store, mark.raw_events_id, decoy.src_mac,
                                      decoy.gocb_ref, window)
        return count if count > threshold else None

    time.sleep(1.0)
    peak = wait_for(
        store, f"the monitor to store more than {threshold} flooded frame(s) in one {window:g}s window",
        over_limit, settings.event_timeout_seconds,
    )
    assert peak > threshold, f"the flood did not exceed the limit: {peak} <= {threshold}"
    time.sleep(2.0)      # let the monitor empty the socket buffer before measuring it
    stored_count, stored_total = busiest_window(store, mark.raw_events_id, decoy.src_mac,
                                               decoy.gocb_ref, window)
    print(f"[TC-11] the monitor stored {stored_total} of {sent} frame(s) (the rest are what "
          f"the socket dropped); the busiest {window:g}s window holds {stored_count} "
          f"(limit {threshold})")

    flooded = goose_rows_after(store, mark.raw_events_id, src_mac=decoy.src_mac,
                               gocb_ref=decoy.gocb_ref)
    drain_engine(store, goose_settings.drain_timeout_seconds, "the flood",
                 target_id=int(flooded[-1]["id"]))
    findings = alerts_after(store, mark.alerts_id)
    gr3 = [row for row in findings if row["rule_id"] == "GR-3"]
    print(f"[TC-11] engine wrote {[(row['rule_id'], row['severity'], row['protocol']) for row in findings]}")

    assert gr3, (
        f"GR-3 did not fire although {stored_count} frame(s) arrived from {decoy.src_mac} "
        f"within {window:g}s against a limit of {threshold}. The engine wrote: "
        f"{[(row['rule_id'], row['severity']) for row in findings]}. Note that GR-3 "
        "suppresses itself for engine.goose.cooldown_seconds after firing, so a recent "
        "alert for the same rule would also explain silence."
    )
    assert all(row["severity"] == MEDIUM for row in gr3), (
        f"GR-3 must be Medium (SPEC.md 20.3), got "
        f"{[(row['rule_id'], row['severity']) for row in gr3]}"
    )
    assert all(row["protocol"] == "goose" for row in gr3), (
        f"the alert must carry the GOOSE protocol tag, got "
        f"{[(row['rule_id'], row['protocol']) for row in gr3]}"
    )
    print(f"[TC-11] {gr3[0]['description']}")
    # The flood used the decoy's own MAC on the decoy's own control block, so it is not a
    # spoof (GR-2) and not an impersonation (GR-4): only the timing is wrong.
    assert not [row for row in findings if row["rule_id"] in ("GR-2", "GR-4")], (
        f"the flood claimed the decoy's own identity, so GR-2 and GR-4 must stay silent; got "
        f"{[(row['rule_id'], row['severity']) for row in findings]}"
    )

    # Report, and drain, the sequence aftermath described in the docstring, so the next
    # case (and the next *run*) starts from a store the engine has finished with. One
    # heartbeat is enough for the decoy's next real frame to arrive and be judged.
    time.sleep(3.0)
    drain_engine(store, goose_settings.drain_timeout_seconds, "the flood's aftermath")
    aftermath = [row for row in alerts_after(store, mark.alerts_id) if row["rule_id"] != "GR-3"]
    print(f"[TC-11] after draining, follow-on finding(s): "
          f"{[describe_alert(store, row) for row in aftermath]}")
    assert not [row for row in aftermath if row["rule_id"] in ("GR-2", "GR-4")], (
        f"only a sequence finding can follow this flood, because it carried the decoy's own "
        f"MAC and control block; got "
        f"{[(row['rule_id'], row['severity']) for row in aftermath]}"
    )
    print("[TC-11] PASS: Medium GR-3 for a rate no retransmission profile can produce")


def test_tc13_unified_dashboard(settings: Settings, goose_settings: GooseSettings,
                                goose_thresholds: GooseThresholds, store: sqlite3.Connection,
                                config: Dict[str, Any], thresholds: DetectionThresholds,
                                injector):
    """TC-13: Unified dashboard check.

    SPEC.md Section 20.6 (verbatim):
      | TC-13: Unified dashboard check | Trigger one Modbus alert and one GOOSE alert
        together | Dashboard correctly shows both, tagged with the right protocol, no
        cross-contamination |

    Section 20.3 puts the two rule families in one engine and one `alerts` table
    "distinguished by a `protocol` field", so this case produces one finding of each kind
    in the same window and checks the tagging end to end: the alert row, the event it
    points at, and the dashboard feed.

    "No cross-contamination" is asserted in both directions. Every alert's protocol must
    match its own rule family (DR-* is Modbus, GR-* is GOOSE), and every alert must point
    at an event whose protocol agrees with it — an alert that joined a GOOSE event to a
    Modbus rule is exactly the defect this case exists to catch.
    """
    def expected_protocol(rule_id: str) -> str:
        return "goose" if rule_id.startswith("GR-") else "modbus"

    drain_engine(store, goose_settings.drain_timeout_seconds, "traffic from earlier cases")
    mark = snapshot(store)

    # --- one Modbus alert: an out-of-allow-list function code at the decoy (TC-3's input)
    anomaly = lab_traffic.READ_DEVICE_IDENTIFICATION
    assert anomaly not in thresholds.allowed_function_codes, (
        f"FC {anomaly} is on the allow-list, so it would raise no Modbus alert for this case"
    )
    reply = lab_traffic.read_device_identification(settings.honeypot_host, settings.honeypot_port)
    print(f"[TC-13] Modbus side: FC {anomaly} to the decoy -> {lab_traffic.describe_reply(reply)}")

    # --- one GOOSE alert: a forged trip on the decoy's control block (TC-7's input)
    decoy = goose_traffic.decoy_endpoint(config)
    attacker = FORGED_TRIP_MAC
    st_num = next_st_num(store, attacker, decoy.gocb_ref)
    frame = goose_traffic.build(decoy.with_src_mac(attacker), st_num=st_num, sq_num=1, trip=True)
    print(f"[TC-13] GOOSE side: injecting {goose_traffic.describe_bytes(frame)}")
    goose_action("TC-13 needs raw socket access to inject the GOOSE half",
                 lambda: goose_traffic.send_frames(injector, [frame]))

    modbus_rows = wait_for(
        store, f"the monitor to store FC {anomaly}",
        lambda: [row for row in raw_events_after(store, mark.raw_events_id, source="monitor")
                 if row["protocol"] == "modbus" and row["function_code"] == anomaly],
        settings.event_timeout_seconds,
    )
    print(f"[TC-13] monitor stored Modbus raw_events id {modbus_rows[0]['id']} "
          f"(fc={modbus_rows[0]['function_code']})")

    goose_rows = wait_for(
        store, "the GOOSE monitor to store the forged trip",
        lambda: goose_rows_after(store, mark.raw_events_id, src_mac=attacker,
                                 gocb_ref=decoy.gocb_ref),
        settings.event_timeout_seconds,
    )
    print(f"[TC-13] monitor stored GOOSE raw_events id {goose_rows[0]['id']} "
          f"(gocb={goose_rows[0]['gocb_ref']}, src_mac={goose_rows[0]['src_mac']})")

    drain_engine(store, goose_settings.drain_timeout_seconds, "the paired findings")
    new_alerts = alerts_after(store, mark.alerts_id)
    print(f"[TC-13] engine wrote {[(row['rule_id'], row['severity'], row['protocol']) for row in new_alerts]}")

    by_protocol = {
        protocol: [row for row in new_alerts if row["protocol"] == protocol]
        for protocol in ("modbus", "goose")
    }
    assert by_protocol["modbus"], (
        f"the Modbus half produced no alert: {[(row['rule_id'], row['protocol']) for row in new_alerts]}"
    )
    assert by_protocol["goose"], (
        f"the GOOSE half produced no alert: {[(row['rule_id'], row['protocol']) for row in new_alerts]}"
    )
    assert any(row["rule_id"] == "GR-4" for row in by_protocol["goose"]), (
        f"the GOOSE half should be the Critical GR-4 for the forged trip, got "
        f"{[(row['rule_id'], row['severity']) for row in by_protocol['goose']]}"
    )

    # Cross-contamination, direction 1: a rule may only write its own protocol.
    for row in new_alerts:
        assert row["protocol"] == expected_protocol(row["rule_id"]), (
            f"{row['rule_id']} wrote a {row['protocol']!r} alert; DR-* is the Modbus family "
            "and GR-* is the GOOSE family (SPEC.md 20.3)"
        )

    # Cross-contamination, direction 2: an alert must point at an event of the same
    # protocol. This is the check that catches a rule family reading the other's rows.
    for row in new_alerts:
        event = store.execute(
            "SELECT protocol, src_mac, src_ip, gocb_ref FROM raw_events WHERE id = ?",
            (row["event_id"],),
        ).fetchone()
        assert event is not None, f"{row['rule_id']} points at raw_events id {row['event_id']}, which does not exist"
        assert event["protocol"] == row["protocol"], (
            f"{row['rule_id']} is a {row['protocol']} alert but its event (raw_events id "
            f"{row['event_id']}) is {event['protocol']}"
        )
        print(f"[TC-13] {row['rule_id']} ({row['severity']}, {row['protocol']}) -> "
              f"raw_events {row['event_id']} ({event['protocol']}, "
              f"src_ip={event['src_ip']}, src_mac={event['src_mac']}, gocb={event['gocb_ref']})")

    # And the dashboard shows both, with the same tags the store holds.
    feed = dashboard_payload(settings)["feed"]
    stored_tags = {int(row["id"]): row["protocol"] for row in new_alerts}
    in_feed = {int(row["id"]): row["protocol"] for row in feed if int(row["id"]) in stored_tags}
    print(f"[TC-13] dashboard feed carries {len(in_feed)} of {len(stored_tags)} new alert(s), "
          f"tagged {sorted(in_feed.items())}")
    assert in_feed == stored_tags, (
        f"the dashboard feed does not carry both findings with the store's protocol tags: "
        f"feed {in_feed} vs store {stored_tags}"
    )
    assert set(in_feed.values()) == {"modbus", "goose"}, (
        f"the feed should show one finding of each protocol, got {sorted(in_feed.values())}"
    )
    print("[TC-13] PASS: both findings on one feed, each tagged with its own protocol")


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
