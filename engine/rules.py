#!/usr/bin/env python3
"""GridSnare detection rules DR-1..DR-6 (SPEC.md Section 8).

Each rule below is a small function that classifies a single row of `raw_events`
and returns an `Alert` (or None). The polling loop that drives them, and the
alerts table they feed, live in engine/correlator.py (SPEC.md Section 9,
steps 3-4):

    3. "Correlation engine polls raw_events on an interval, applies DR-1 .. DR-7"
    4. "Matches are written to alerts with severity and rule ID"

DR-7 is deliberately NOT here: it joins the honeypot log and the monitor log
rather than classifying one event, so it lives in engine/correlator.py alongside
the loop that has both sources in view.

Every threshold used by these rules is read from the `engine.detection` section
of config.yaml — SPEC.md Section 8 requires thresholds to be configurable rather
than hardcoded. Nothing in this module writes to the database; it returns
classification results and lets the caller persist them.
"""

from __future__ import annotations

import logging
import os
import sqlite3
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from datetime import datetime, time, timedelta, timezone, tzinfo
from typing import Any, Optional, Tuple

from zoneinfo import ZoneInfo

LOG = logging.getLogger("gridsnare.engine.rules")

# Severity vocabulary from SPEC.md Section 7.3 ("Low / Medium / High / Critical").
SEVERITY_LOW = "Low"
SEVERITY_MEDIUM = "Medium"
SEVERITY_HIGH = "High"
SEVERITY_CRITICAL = "Critical"

# Modbus write function codes, split by address space because coils and registers
# are separate spaces in Modbus (see rule DR-3).
COIL_WRITE_FUNCTION_CODES = frozenset({5, 15})
REGISTER_WRITE_FUNCTION_CODES = frozenset({6, 16, 22, 23})


class RuleConfigError(Exception):
    """Raised when the engine.detection configuration is missing or malformed."""


@dataclass(frozen=True)
class Alert:
    """A detection result, ready to be written to the `alerts` table."""

    rule_id: str
    severity: str
    protocol: str
    description: str
    src_ip: Optional[str]
    dst_ip: Optional[str]
    event_id: Optional[int]
    correlated_event_id: Optional[int] = None


@dataclass(frozen=True)
class OperationalHours:
    """The expected-usage window used by DR-4."""

    start: time
    end: time
    days: frozenset
    zone: tzinfo
    zone_name: str

    def covers(self, moment: datetime) -> bool:
        """True when `moment` (any tz-aware datetime) falls inside the window."""
        local = moment.astimezone(self.zone)
        if self.days and local.weekday() not in self.days:
            return False
        current = local.time()
        if self.start <= self.end:
            return self.start <= current <= self.end
        # Window wraps past midnight, e.g. 22:00 -> 06:00.
        return current >= self.start or current <= self.end

    # Off-hours override. The validation plan (SPEC.md Section 12) has to be runnable
    # at any wall-clock time, but TC-2 only means anything inside operational hours:
    # baseline traffic that is captured as source='monitor' outside the window trips
    # DR-4 *by design*, so the case correctly skips rather than reporting a pass it did
    # not earn. Rather than weaken the committed window (which would make DR-4 unable
    # to fire in normal operation), the window can be declared for a single run through
    # the environment. The committed config.yaml is untouched, and every override is
    # logged as a warning so an off-hours run is never silent about what it changed.
    ENV_START = "GRIDSNARE_OPERATIONAL_START"
    ENV_END = "GRIDSNARE_OPERATIONAL_END"
    ENV_TZ = "GRIDSNARE_OPERATIONAL_TZ"

    @classmethod
    def _override(cls, key: str, env_name: str, section: Mapping[str, Any]) -> Any:
        """Return the environment's value for `key`, falling back to the YAML section."""
        raw = os.environ.get(env_name)
        if raw is None or not raw.strip():
            return section.get(key)
        LOG.warning(
            "operational_hours.%s overridden by %s=%r for this process — the committed "
            "config.yaml still declares %r. This exists so the validation suite can run "
            "off-hours; it must not be set for normal lab operation.",
            key, env_name, raw, section.get(key),
        )
        return raw

    @classmethod
    def from_mapping(cls, section: Mapping[str, Any]) -> "OperationalHours":
        if not isinstance(section, Mapping):
            raise RuleConfigError("engine.detection.operational_hours must be a mapping")

        zone_name = str(cls._override("timezone", cls.ENV_TZ, section) or "UTC")
        try:
            zone = ZoneInfo(zone_name)
        except Exception as exc:  # ZoneInfoNotFoundError, or missing tzdata
            raise RuleConfigError(
                f"operational_hours.timezone {zone_name!r} could not be loaded ({exc}). "
                "Install the tzdata package (or the OS tz database) for the container."
            ) from exc

        raw_days = section.get("days") or []
        if not isinstance(raw_days, (list, tuple)):
            raise RuleConfigError("operational_hours.days must be a list of weekday numbers")
        days = set()
        for day in raw_days:
            if not isinstance(day, int) or not 0 <= day <= 6:
                raise RuleConfigError(
                    f"operational_hours.days entries must be integers 0..6 (Monday=0), got {day!r}"
                )
            days.add(day)

        return cls(
            start=_parse_hhmm(
                cls._override("start", cls.ENV_START, section), "operational_hours.start"
            ),
            end=_parse_hhmm(
                cls._override("end", cls.ENV_END, section), "operational_hours.end"
            ),
            days=frozenset(days),
            zone=zone,
            zone_name=zone_name,
        )


@dataclass(frozen=True)
class DetectionThresholds:
    """Validated `engine.detection` configuration (SPEC.md Section 8)."""

    allowed_function_codes: frozenset
    operational_register_range: Tuple[int, int]
    operational_coil_range: Tuple[int, int]
    operational_hours: OperationalHours
    known_asset_allow_list: frozenset
    polling_rate_limit: int
    polling_window_seconds: int
    correlation_window_minutes: int
    alert_cooldown_seconds: int

    @classmethod
    def from_mapping(cls, section: Mapping[str, Any]) -> "DetectionThresholds":
        if not isinstance(section, Mapping):
            raise RuleConfigError("config.yaml must contain an engine.detection mapping")

        allowed = section.get("allowed_function_codes")
        if not isinstance(allowed, (list, tuple)) or not allowed:
            raise RuleConfigError("engine.detection.allowed_function_codes must be a non-empty list")

        allow_list = section.get("known_asset_allow_list")
        if not isinstance(allow_list, (list, tuple)):
            raise RuleConfigError("engine.detection.known_asset_allow_list must be a list")

        return cls(
            allowed_function_codes=frozenset(int(code) for code in allowed),
            operational_register_range=_parse_range(
                section.get("operational_register_range"), "operational_register_range"),
            operational_coil_range=_parse_range(
                section.get("operational_coil_range"), "operational_coil_range"),
            operational_hours=OperationalHours.from_mapping(section.get("operational_hours")),
            known_asset_allow_list=frozenset(str(asset) for asset in allow_list),
            polling_rate_limit=_parse_positive_int(
                section.get("polling_rate_limit"), "polling_rate_limit"),
            polling_window_seconds=_parse_positive_int(
                section.get("polling_window_seconds"), "polling_window_seconds"),
            correlation_window_minutes=_parse_positive_int(
                section.get("correlation_window_minutes"), "correlation_window_minutes"),
            alert_cooldown_seconds=_parse_non_negative_int(
                section.get("alert_cooldown_seconds"), "alert_cooldown_seconds"),
        )


def _parse_hhmm(value: Any, name: str) -> time:
    if not isinstance(value, str):
        raise RuleConfigError(f"{name} must be a \"HH:MM\" string, got {value!r}")
    try:
        hour, minute = (int(part) for part in value.strip().split(":"))
        return time(hour=hour, minute=minute)
    except (TypeError, ValueError) as exc:
        raise RuleConfigError(f"{name} must be a \"HH:MM\" string, got {value!r}") from exc


def _parse_range(value: Any, name: str) -> Tuple[int, int]:
    if not isinstance(value, (list, tuple)) or len(value) != 2:
        raise RuleConfigError(f"engine.detection.{name} must be a [first, last] pair")
    try:
        first, last = int(value[0]), int(value[1])
    except (TypeError, ValueError) as exc:
        raise RuleConfigError(f"engine.detection.{name} must contain integers") from exc
    if first > last:
        raise RuleConfigError(f"engine.detection.{name} first ({first}) exceeds last ({last})")
    return (first, last)


def _parse_positive_int(value: Any, name: str) -> int:
    parsed = _parse_non_negative_int(value, name)
    if parsed <= 0:
        raise RuleConfigError(f"engine.detection.{name} must be greater than zero")
    return parsed


def _parse_non_negative_int(value: Any, name: str) -> int:
    try:
        parsed = int(value)
    except (TypeError, ValueError) as exc:
        raise RuleConfigError(f"engine.detection.{name} must be an integer, got {value!r}") from exc
    if parsed < 0:
        raise RuleConfigError(f"engine.detection.{name} must not be negative")
    return parsed


def utc_now_iso() -> str:
    """Engine-side timestamp, ISO-8601 UTC, matching the monitor's format."""
    return datetime.now(timezone.utc).isoformat(timespec="milliseconds").replace("+00:00", "Z")


def parse_event_timestamp(value: str) -> datetime:
    """Parse an ISO-8601 timestamp written by the monitor or an ingester."""
    try:
        parsed = datetime.fromisoformat(str(value).replace("Z", "+00:00"))
    except ValueError as exc:
        raise ValueError(f"raw_events.timestamp is not ISO-8601: {value!r}") from exc
    if parsed.tzinfo is None:
        # Stored timestamps are UTC; treat a naive value as UTC rather than local.
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed


@dataclass
class RuleContext:
    """Everything a rule needs beyond the event row itself."""

    connection: sqlite3.Connection
    thresholds: DetectionThresholds
    logger: logging.Logger = LOG

    def monitor_events_in_window(self, src_ip: str, start_iso: str, end_iso: str) -> int:
        """Count monitor-sourced events from one source, inclusive of both bounds."""
        row = self.connection.execute(
            "SELECT COUNT(*) FROM raw_events "
            "WHERE source = 'monitor' AND src_ip = ? AND timestamp BETWEEN ? AND ?",
            (src_ip, start_iso, end_iso),
        ).fetchone()
        return int(row[0]) if row else 0

    def recent_alert_exists(self, rule_id: str, src_ip: Optional[str]) -> bool:
        """Has this rule already alerted for this source inside the cooldown window?

        Measured against wall-clock time at evaluation rather than the event's own
        timestamp, because the cooldown governs how often the engine speaks, not
        anything about the traffic.
        """
        cooldown = self.thresholds.alert_cooldown_seconds
        if cooldown <= 0:
            return False
        cutoff = (
            datetime.now(timezone.utc) - timedelta(seconds=cooldown)
        ).isoformat(timespec="milliseconds").replace("+00:00", "Z")
        row = self.connection.execute(
            "SELECT 1 FROM alerts WHERE rule_id = ? AND src_ip IS ? AND timestamp >= ? LIMIT 1",
            (rule_id, src_ip, cutoff),
        ).fetchone()
        return row is not None


# ---------------------------------------------------------------------------
# DR-1 .. DR-6
#
# Each docstring quotes the row from the SPEC.md Section 8 detection table:
#   ID | Rule | Rationale | Severity
# ---------------------------------------------------------------------------


def rule_dr1_any_honeypot_interaction(event: Mapping[str, Any], context: RuleContext) -> Optional[Alert]:
    """DR-1 | Any interaction with the honeypot | Decoy has no legitimate traffic | Critical

    The decoy has no legitimate traffic, so a single event is enough: there is no
    threshold to tune and no allow-list to satisfy.
    """
    if event.get("source") != "honeypot":
        return None
    return Alert(
        rule_id="DR-1",
        severity=SEVERITY_CRITICAL,
        protocol=str(event.get("protocol") or "modbus"),
        description=(
            f"Honeypot interaction from {event.get('src_ip')} "
            f"(unit {event.get('unit_id')}, function code {event.get('function_code')}) — "
            "the decoy has no legitimate traffic"
        ),
        src_ip=event.get("src_ip"),
        dst_ip=event.get("dst_ip"),
        event_id=event.get("id"),
    )


def rule_dr2_function_code_outside_allow_list(
    event: Mapping[str, Any], context: RuleContext
) -> Optional[Alert]:
    """DR-2 | Modbus function code outside an allow-list of expected codes | Indicates protocol misuse or reconnaissance | High"""
    if event.get("source") != "monitor":
        return None
    function_code = event.get("function_code")
    if function_code is None:
        return None
    if function_code in context.thresholds.allowed_function_codes:
        return None
    return Alert(
        rule_id="DR-2",
        severity=SEVERITY_HIGH,
        protocol=str(event.get("protocol") or "modbus"),
        description=(
            f"Modbus function code {function_code} from {event.get('src_ip')} is outside the "
            f"configured allow-list {sorted(context.thresholds.allowed_function_codes)} — "
            "indicates protocol misuse or reconnaissance"
        ),
        src_ip=event.get("src_ip"),
        dst_ip=event.get("dst_ip"),
        event_id=event.get("id"),
    )


def rule_dr3_write_outside_operational_range(
    event: Mapping[str, Any], context: RuleContext
) -> Optional[Alert]:
    """DR-3 | Write request to a register outside the defined operational range | Potential unauthorized control action | High

    The whole addressed span (address .. address + quantity - 1) must sit inside
    the configured range; a write that only partly overlaps it is outside.
    Coil writes are checked against the coil range, which is a separate address
    space from registers.
    """
    if event.get("source") != "monitor":
        return None

    function_code = event.get("function_code")
    if function_code in REGISTER_WRITE_FUNCTION_CODES:
        bounds, space = context.thresholds.operational_register_range, "register"
    elif function_code in COIL_WRITE_FUNCTION_CODES:
        bounds, space = context.thresholds.operational_coil_range, "coil"
    else:
        return None  # not a write request

    address = event.get("register_address")
    if address is None:
        # A write whose PDU this monitor does not decode (e.g. FC22/FC23) carries
        # no address, so DR-3 cannot judge it. DR-2 still classifies the code.
        return None

    quantity = event.get("quantity") or 1
    last = int(address) + int(quantity) - 1
    first_allowed, last_allowed = bounds
    if first_allowed <= int(address) and last <= last_allowed:
        return None

    return Alert(
        rule_id="DR-3",
        severity=SEVERITY_HIGH,
        protocol=str(event.get("protocol") or "modbus"),
        description=(
            f"Modbus write (function code {function_code}) from {event.get('src_ip')} targets "
            f"{space} {address}-{last}, outside the operational {space} range "
            f"{first_allowed}-{last_allowed} — potential unauthorized control action"
        ),
        src_ip=event.get("src_ip"),
        dst_ip=event.get("dst_ip"),
        event_id=event.get("id"),
    )


def rule_dr4_outside_operational_hours(
    event: Mapping[str, Any], context: RuleContext
) -> Optional[Alert]:
    """DR-4 | Access outside defined operational hours | Deviates from expected baseline usage | Medium

    Scoped to monitor-sourced traffic, i.e. access over the legitimate path to the
    PLC. Honeypot-sourced events are already Critical under DR-1, and the decoy has
    no baseline to deviate from.

    raw_events timestamps are UTC; the configured window is evaluated in its own
    timezone (see OperationalHours.covers).
    """
    if event.get("source") != "monitor":
        return None

    hours = context.thresholds.operational_hours
    try:
        moment = parse_event_timestamp(event["timestamp"])
    except (KeyError, ValueError):
        context.logger.warning("DR-4 skipped unparseable timestamp: %r", event.get("timestamp"))
        return None

    if hours.covers(moment):
        return None
    if context.recent_alert_exists("DR-4", event.get("src_ip")):
        return None

    local = moment.astimezone(hours.zone)
    return Alert(
        rule_id="DR-4",
        severity=SEVERITY_MEDIUM,
        protocol=str(event.get("protocol") or "modbus"),
        description=(
            f"Modbus access from {event.get('src_ip')} at {local.strftime('%Y-%m-%d %H:%M')} "
            f"{hours.zone_name} falls outside operational hours "
            f"{hours.start.strftime('%H:%M')}-{hours.end.strftime('%H:%M')}"
        ),
        src_ip=event.get("src_ip"),
        dst_ip=event.get("dst_ip"),
        event_id=event.get("id"),
    )


def rule_dr5_source_not_on_allow_list(
    event: Mapping[str, Any], context: RuleContext
) -> Optional[Alert]:
    """DR-5 | Source IP/MAC not on the known-asset allow-list | Unrecognized device on the network | Medium

    SPEC.md Section 8 says "IP/MAC"; raw_events records the source IP only, so
    this implementation is IP-based. Adding source MAC capture to the monitor
    would be required to honour the MAC half.
    """
    if event.get("source") != "monitor":
        return None
    src_ip = event.get("src_ip")
    if src_ip is None or src_ip in context.thresholds.known_asset_allow_list:
        return None
    if context.recent_alert_exists("DR-5", src_ip):
        return None
    return Alert(
        rule_id="DR-5",
        severity=SEVERITY_MEDIUM,
        protocol=str(event.get("protocol") or "modbus"),
        description=(
            f"Unrecognized device {src_ip} sent Modbus traffic to {event.get('dst_ip')}; "
            "it is not on the known-asset allow-list"
        ),
        src_ip=src_ip,
        dst_ip=event.get("dst_ip"),
        event_id=event.get("id"),
    )


def rule_dr6_abnormally_high_request_rate(
    event: Mapping[str, Any], context: RuleContext
) -> Optional[Alert]:
    """DR-6 | Abnormally high polling/request frequency from one source | Possible scanning or fuzzing behavior | Medium

    Counts monitor-sourced events from the same source in the configured trailing
    window. The window ends at the event being classified, so the rule fires when
    the rate that event completes exceeds the limit.
    """
    if event.get("source") != "monitor":
        return None
    src_ip = event.get("src_ip")
    if src_ip is None:
        return None

    thresholds = context.thresholds
    try:
        moment = parse_event_timestamp(event["timestamp"])
    except (KeyError, ValueError):
        context.logger.warning("DR-6 skipped unparseable timestamp: %r", event.get("timestamp"))
        return None

    window_start = (moment - timedelta(seconds=thresholds.polling_window_seconds))
    count = context.monitor_events_in_window(
        src_ip,
        window_start.isoformat(timespec="milliseconds").replace("+00:00", "Z"),
        moment.isoformat(timespec="milliseconds").replace("+00:00", "Z"),
    )
    if count <= thresholds.polling_rate_limit:
        return None
    if context.recent_alert_exists("DR-6", src_ip):
        return None

    return Alert(
        rule_id="DR-6",
        severity=SEVERITY_MEDIUM,
        protocol=str(event.get("protocol") or "modbus"),
        description=(
            f"{count} Modbus requests from {src_ip} within "
            f"{thresholds.polling_window_seconds}s exceeds the configured limit of "
            f"{thresholds.polling_rate_limit} — possible scanning or fuzzing behaviour"
        ),
        src_ip=src_ip,
        dst_ip=event.get("dst_ip"),
        event_id=event.get("id"),
    )


@dataclass(frozen=True)
class RuleDefinition:
    """Registry entry: which events a rule classifies, and how."""

    rule_id: str
    source: str  # 'monitor' | 'honeypot'
    evaluate: Any
    # The protocol whose rows this rule understands. DR-1..DR-6 read Modbus columns
    # (function_code, register_address) that are NULL on a GOOSE row, so without this
    # gate a rule such as DR-4 — which only asks "is this monitor traffic outside
    # operational hours?" — would fire on GOOSE frames and raise a Modbus alert for
    # them. SPEC.md 20.3 keeps both protocols in one alerts table and one engine, so
    # the split has to be explicit; Phase 2's GR-1..GR-4 register here with
    # protocol='goose' from engine/goose_rules.py.
    protocol: str = "modbus"


MODBUS_RULES: Tuple[RuleDefinition, ...] = (
    RuleDefinition("DR-1", "honeypot", rule_dr1_any_honeypot_interaction),
    RuleDefinition("DR-2", "monitor", rule_dr2_function_code_outside_allow_list),
    RuleDefinition("DR-3", "monitor", rule_dr3_write_outside_operational_range),
    RuleDefinition("DR-4", "monitor", rule_dr4_outside_operational_hours),
    RuleDefinition("DR-5", "monitor", rule_dr5_source_not_on_allow_list),
    RuleDefinition("DR-6", "monitor", rule_dr6_abnormally_high_request_rate),
)


def evaluate_event(
    event: Mapping[str, Any], context: RuleContext
) -> Sequence[Alert]:
    """Apply every rule that matches this event's source and protocol, in registry order.

    Rows written before the protocol column existed, or by a caller that omitted it,
    default to Modbus — which is what they were.
    """
    source = event.get("source")
    protocol = str(event.get("protocol") or "modbus")
    alerts = []
    for rule in MODBUS_RULES:
        if rule.source != source or rule.protocol != protocol:
            continue
        alert = rule.evaluate(event, context)
        if alert is not None:
            alerts.append(alert)
    return alerts
