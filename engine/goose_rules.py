#!/usr/bin/env python3
"""GridSnare GOOSE detection rules GR-1..GR-4 (SPEC.md Section 20.3).

Each rule classifies one row of `raw_events` written by the GOOSE traffic monitor
(``protocol='goose'``, see goose/goose_monitor.py) and returns an `Alert` or None.
The polling loop that drives them and the `alerts` table they feed live in
engine/correlator.py, exactly as for the Modbus rules DR-1..DR-6 in
engine/rules.py — SPEC.md 20.3 puts both rule families in one engine and one
alerts table, distinguished by the `protocol` column.

SPEC.md Section 20.3, verbatim:

    | GR-1 | StNum/SqNum sequence violation (e.g. SqNum resets without a StNum
      increment, or duplicate StNum/SqNum pairs from the same publisher) |
      Indicates a replayed frame ... | High |
    | GR-2 | Source MAC address does not match the known-publisher allow-list for
      a given GoCB reference | Indicates spoofing — a legitimate relay's MAC is
      fixed and known | Critical |
    | GR-3 | Retransmission interval deviates from the configured GOOSE timing
      profile ... | Anomalous timing suggests an unauthorized or malfunctioning
      publisher | Medium |
    | GR-4 | Any GOOSE traffic referencing the decoy IED's GoCB | Decoy has no
      legitimate subscribers/publishers | Critical |

The decoy's own frames are the reference this segment is judged against, so GR-2
and GR-4 treat the decoy's link address as the known publisher for its control
block and everything else as an impostor. GR-2 leaves the decoy's own block to
GR-4 so an impostor on it produces one finding, not two. All of that is
configuration (``engine.goose`` in config.yaml, SPEC.md Section 8), not code:
nothing here hardcodes a MAC, a control block, or a threshold.

Every rule is deterministic and stateless across engine restarts: each reads its
history from `raw_events` (indexed on ``src_mac``/``gocb_ref``), so re-judging an
event after a restart chooses the same verdict. Nothing here writes to the
database; the caller persists whatever is returned.
"""

from __future__ import annotations

import logging
import sqlite3
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, FrozenSet, Optional, Tuple

from engine.rules import (
    SEVERITY_CRITICAL,
    SEVERITY_HIGH,
    SEVERITY_MEDIUM,
    Alert,
    RuleConfigError,
    RuleDefinition,
    parse_event_timestamp,
)

LOG = logging.getLogger("gridsnare.engine.goose_rules")

# The protocol tag and source this rule family applies to (SPEC.md 20.3 / Section 9).
PROTOCOL = "goose"
SOURCE = "monitor"


@dataclass(frozen=True)
class GooseThresholds:
    """Validated ``engine.goose`` configuration (SPEC.md Section 8)."""

    decoy_gocb_ref: str
    decoy_src_mac: str
    known_publishers: Mapping[str, FrozenSet[str]]
    timing_window_seconds: float
    timing_max_frames_per_window: int
    cooldown_seconds: int

    @classmethod
    def from_mapping(cls, section: Mapping[str, Any]) -> "GooseThresholds":
        if not isinstance(section, Mapping):
            raise RuleConfigError(
                "config.yaml must contain an engine.goose mapping (SPEC.md Section 20.3)"
            )

        decoy_gocb_ref = _require_text(section, "decoy_gocb_ref")
        decoy_src_mac = _require_text(section, "decoy_src_mac").lower()

        raw_publishers = section.get("known_publishers")
        if not isinstance(raw_publishers, Mapping) or not raw_publishers:
            raise RuleConfigError(
                "engine.goose.known_publishers must be a non-empty mapping of "
                "GoCB reference -> list of allowed source MACs"
            )
        known: Dict[str, FrozenSet[str]] = {}
        for gocb_ref, macs in raw_publishers.items():
            name = str(gocb_ref).strip()
            if not name:
                raise RuleConfigError("engine.goose.known_publishers keys must be non-empty")
            if not isinstance(macs, (list, tuple)) or not macs:
                raise RuleConfigError(
                    f"engine.goose.known_publishers[{name!r}] must be a non-empty list "
                    "of source MACs"
                )
            known[name] = frozenset(str(mac).strip().lower() for mac in macs)

        # The decoy's own control block must have a known publisher, or GR-2 would
        # flag the decoy's legitimate frames as spoofing. Fail loudly rather than
        # start the engine in a configuration that alerts on its own reference.
        if decoy_gocb_ref not in known:
            raise RuleConfigError(
                f"engine.goose.known_publishers must include the decoy's own control "
                f"block {decoy_gocb_ref!r}, or its legitimate frames fail GR-2"
            )

        return cls(
            decoy_gocb_ref=decoy_gocb_ref,
            decoy_src_mac=decoy_src_mac,
            known_publishers=known,
            timing_window_seconds=_positive_float(section, "timing_window_seconds"),
            timing_max_frames_per_window=_positive_int(section, "timing_max_frames_per_window"),
            cooldown_seconds=_non_negative_int(section, "cooldown_seconds", 300),
        )


def _require_text(section: Mapping[str, Any], key: str) -> str:
    value = section.get(key)
    if not isinstance(value, str) or not value.strip():
        raise RuleConfigError(f"engine.goose.{key} must be a non-empty string")
    return value.strip()


def _positive_float(section: Mapping[str, Any], key: str) -> float:
    raw = section.get(key)
    try:
        parsed = float(raw)
    except (TypeError, ValueError) as exc:
        raise RuleConfigError(f"engine.goose.{key} must be a number, got {raw!r}") from exc
    if parsed <= 0:
        raise RuleConfigError(f"engine.goose.{key} must be greater than zero")
    return parsed


def _positive_int(section: Mapping[str, Any], key: str) -> int:
    raw = section.get(key)
    try:
        parsed = int(raw)
    except (TypeError, ValueError) as exc:
        raise RuleConfigError(f"engine.goose.{key} must be an integer, got {raw!r}") from exc
    if parsed <= 0:
        raise RuleConfigError(f"engine.goose.{key} must be greater than zero")
    return parsed


def _non_negative_int(section: Mapping[str, Any], key: str, default: int) -> int:
    raw = section.get(key, default)
    try:
        parsed = int(raw)
    except (TypeError, ValueError) as exc:
        raise RuleConfigError(f"engine.goose.{key} must be an integer, got {raw!r}") from exc
    if parsed < 0:
        raise RuleConfigError(f"engine.goose.{key} must not be negative")
    return parsed


@dataclass
class GooseRuleContext:
    """Everything a GOOSE rule needs beyond the row itself.

    Deliberately separate from ``engine.rules.RuleContext``: that one carries the
    Modbus ``DetectionThresholds`` (IPs, function codes, an allow-list of addresses);
    these rules carry the GOOSE vocabulary instead. Sharing one context would mean
    either type carrying fields the other never reads.
    """

    connection: sqlite3.Connection
    thresholds: GooseThresholds
    logger: logging.Logger = LOG

    def previous_frame(self, src_mac: str, gocb_ref: str, before_id: Any) -> Optional[sqlite3.Row]:
        """The immediately preceding frame from one publisher, or None.

        Ordered by row id rather than timestamp: id is the monitor's capture order and
        never ties, while two frames can share a millisecond. ``id < before_id`` scopes
        it to frames already read this pass, so the comparison always runs forward.
        """
        return self.connection.execute(
            "SELECT id, timestamp, st_num, sq_num FROM raw_events "
            "WHERE protocol = 'goose' AND src_mac = ? AND gocb_ref = ? AND id < ? "
            "ORDER BY id DESC LIMIT 1",
            (src_mac, gocb_ref, before_id),
        ).fetchone()

    def frames_in_window(self, src_mac: str, gocb_ref: str,
                         window_start_iso: str, now_iso: str) -> int:
        """Frames one publisher emitted inside a trailing window, inclusive of both ends."""
        row = self.connection.execute(
            "SELECT COUNT(*) FROM raw_events "
            "WHERE protocol = 'goose' AND src_mac = ? AND gocb_ref = ? "
            "AND timestamp BETWEEN ? AND ?",
            (src_mac, gocb_ref, window_start_iso, now_iso),
        ).fetchone()
        return int(row[0]) if row else 0

    def cooldown_active(self, rule_id: str) -> bool:
        """Has this rule already fired inside its cooldown window?

        Used only by GR-3, whose subject is a *rate*: without this a sustained flood
        would write one row per packet. GR-1, GR-2 and GR-4 are per-event by design
        (like DR-1/DR-2/DR-3) because every offending frame is its own finding.
        """
        cooldown = self.thresholds.cooldown_seconds
        if cooldown <= 0:
            return False
        cutoff = (
            datetime.now(timezone.utc) - timedelta(seconds=cooldown)
        ).isoformat(timespec="milliseconds").replace("+00:00", "Z")
        row = self.connection.execute(
            "SELECT 1 FROM alerts WHERE rule_id = ? AND timestamp >= ? LIMIT 1",
            (rule_id, cutoff),
        ).fetchone()
        return row is not None


# ---------------------------------------------------------------------------
# GR-1 .. GR-4
# ---------------------------------------------------------------------------

def rule_gr1_sequence_violation(
    event: Mapping[str, Any], context: GooseRuleContext
) -> Optional[Alert]:
    """GR-1 | StNum/SqNum sequence violation | Indicates a replayed frame | High

    A legitimate publisher's sequence numbers follow one pattern (IEC 61850-8-1):
    SqNum increments within a state, and a state change increments StNum and resets
    SqNum. A frame that breaks either half is a replay — captured bytes re-sent out
    of order, which is why the rule compares each frame against its immediate
    predecessor from the same publisher rather than against a stored value.

    Two violations are detected, both named in the SPEC.md row:
      * SqNum does not advance within a StNum (a reset, or an exact duplicate pair);
      * StNum goes backwards.
    A frame that simply continues the sequence, or that advances StNum (any SqNum,
    because the reset value is the library's to choose), is not a violation.
    """
    if str(event.get("protocol") or "") != PROTOCOL:
        return None
    src_mac = event.get("src_mac")
    gocb_ref = event.get("gocb_ref")
    st_num = event.get("st_num")
    sq_num = event.get("sq_num")
    if src_mac is None or gocb_ref is None or st_num is None or sq_num is None:
        return None

    previous = context.previous_frame(src_mac, gocb_ref, event.get("id"))
    if previous is None or previous["st_num"] is None or previous["sq_num"] is None:
        # No history for this publisher: the first frame cannot violate a sequence.
        return None

    prev_st = int(previous["st_num"])
    prev_sq = int(previous["sq_num"])
    cur_st = int(st_num)
    cur_sq = int(sq_num)

    if cur_st == prev_st and cur_sq <= prev_sq:
        reason = (
            f"duplicate StNum/SqNum pair ({cur_st}/{cur_sq})"
            if cur_sq == prev_sq
            else f"SqNum dropped from {prev_sq} to {cur_sq} without a StNum increment"
        )
    elif cur_st < prev_st:
        reason = f"StNum went backwards from {prev_st} to {cur_st}"
    else:
        return None

    previous_id = int(previous["id"])
    return Alert(
        rule_id="GR-1",
        severity=SEVERITY_HIGH,
        protocol=PROTOCOL,
        description=(
            f"GOOSE sequence violation from {src_mac} on {gocb_ref}: {reason} "
            f"(previous raw_events id {previous_id}) — a legitimate publisher "
            f"increments SqNum within a StNum and resets it only on a StNum change; "
            f"this indicates a replayed frame"
        ),
        src_ip=None,
        dst_ip=None,
        event_id=event.get("id"),
    )


def rule_gr2_unknown_publisher(
    event: Mapping[str, Any], context: GooseRuleContext
) -> Optional[Alert]:
    """GR-2 | Source MAC not on the known-publisher allow-list for a GoCB | Spoofing | Critical

    Each control block has a fixed, known publisher. A frame whose (GoCB, source MAC)
    is not the allow-listed pair is spoofing — an attacker's own frame wearing a
    control block it has no business publishing. A control block the allow-list does
    not mention at all has no known publisher on this segment, which is the same
    finding, so it is flagged too.

    The decoy's own control block is deliberately excluded: GR-4 owns it, and this
    keeps an impostor there to a single Critical finding rather than two.
    """
    if str(event.get("protocol") or "") != PROTOCOL:
        return None
    src_mac = event.get("src_mac")
    gocb_ref = event.get("gocb_ref")
    if src_mac is None or gocb_ref is None:
        return None

    thresholds = context.thresholds
    gocb_ref = str(gocb_ref)
    if gocb_ref == thresholds.decoy_gocb_ref:
        return None  # GR-4 handles any traffic on the decoy's own control block

    src_mac_norm = str(src_mac).lower()
    allowed = thresholds.known_publishers.get(gocb_ref)
    if allowed is not None and src_mac_norm in allowed:
        return None

    if allowed is None:
        detail = f"control block {gocb_ref} has no known publisher on this segment"
    else:
        detail = (
            f"{src_mac} is not an allow-listed publisher for {gocb_ref} "
            f"(allowed: {sorted(allowed)})"
        )

    return Alert(
        rule_id="GR-2",
        severity=SEVERITY_CRITICAL,
        protocol=PROTOCOL,
        description=(
            f"GOOSE source spoofing: {detail} — a legitimate relay's source MAC is "
            f"fixed and known for its control block"
        ),
        src_ip=None,
        dst_ip=None,
        event_id=event.get("id"),
    )


def rule_gr3_timing_deviation(
    event: Mapping[str, Any], context: GooseRuleContext
) -> Optional[Alert]:
    """GR-3 | Retransmission timing deviates from the configured profile | Medium

    A conforming publisher retransmits on a decaying burst after a state change and
    then holds a heartbeat (IEC 61850-8-1; the shape is ``goose.retransmission_profile_ms``
    plus ``goose.heartbeat_seconds``). A publisher emitting far more often than that
    profile can produce is anomalous — an unauthorized or malfunctioning device.

    The check is a *rate* over a short trailing window rather than a single
    inter-arrival comparison, and that choice is measured rather than stylistic. The
    decoy's real frames jitter widely against the configured profile (a configured
    10ms first retransmission arrives anywhere from ~18ms to ~250ms under normal
    Docker scheduling), so a per-interval check against the profile would alert on the
    legitimate publisher — the exact false positive TC-8 forbids. A rate the profile
    cannot reach survives that jitter: the decoy peaks at ~6 frames in any one-second
    window, while a flood is two orders of magnitude above it.

    This detects the too-fast direction. The too-slow direction is not flagged,
    because a publisher that is simply idle or has just restarted leaves the same
    fingerprint as one transmitting abnormally slowly, and this rule refuses to
    guess which — the dashboard's sensor-health view reports a silent source for what
    it is instead.
    """
    if str(event.get("protocol") or "") != PROTOCOL:
        return None
    src_mac = event.get("src_mac")
    gocb_ref = event.get("gocb_ref")
    if src_mac is None or gocb_ref is None:
        return None

    thresholds = context.thresholds
    try:
        moment = parse_event_timestamp(event["timestamp"])
    except (KeyError, ValueError):
        context.logger.warning("GR-3 skipped unparseable timestamp: %r", event.get("timestamp"))
        return None

    window_start = moment - timedelta(seconds=thresholds.timing_window_seconds)
    count = context.frames_in_window(
        src_mac,
        gocb_ref,
        window_start.isoformat(timespec="milliseconds").replace("+00:00", "Z"),
        moment.isoformat(timespec="milliseconds").replace("+00:00", "Z"),
    )
    if count <= thresholds.timing_max_frames_per_window:
        return None
    if context.cooldown_active("GR-3"):
        return None

    return Alert(
        rule_id="GR-3",
        severity=SEVERITY_MEDIUM,
        protocol=PROTOCOL,
        description=(
            f"GOOSE retransmission timing anomaly from {src_mac} on {gocb_ref}: "
            f"{count} frame(s) in {thresholds.timing_window_seconds:g}s exceeds the "
            f"configured maximum of {thresholds.timing_max_frames_per_window} — faster "
            f"than the retransmission profile can produce"
        ),
        src_ip=None,
        dst_ip=None,
        event_id=event.get("id"),
    )


def rule_gr4_decoy_gocb(
    event: Mapping[str, Any], context: GooseRuleContext
) -> Optional[Alert]:
    """GR-4 | Any GOOSE traffic referencing the decoy IED's GoCB | Critical

    The decoy's control block is bait: no real device on this segment is that relay,
    so no other publisher may reference it. The decoy's own frames are the legitimate
    reference — they come from ``decoy_src_mac`` — so this fires on any *other*
    source claiming the decoy's control block, which is what injecting a trip looks
    like (SPEC.md 20.6 TC-7).
    """
    if str(event.get("protocol") or "") != PROTOCOL:
        return None
    gocb_ref = event.get("gocb_ref")
    src_mac = event.get("src_mac")
    if gocb_ref is None or src_mac is None:
        return None

    thresholds = context.thresholds
    if str(gocb_ref) != thresholds.decoy_gocb_ref:
        return None
    if str(src_mac).lower() == thresholds.decoy_src_mac:
        return None  # the decoy's own publication is the reference, not an intrusion

    return Alert(
        rule_id="GR-4",
        severity=SEVERITY_CRITICAL,
        protocol=PROTOCOL,
        description=(
            f"GOOSE frame references the decoy IED's control block {gocb_ref} from "
            f"{src_mac} (not the decoy's own {thresholds.decoy_src_mac}) — the decoy "
            f"has no legitimate subscribers or publishers, so this is a forged trip "
            f"or an impersonation"
        ),
        src_ip=None,
        dst_ip=None,
        event_id=event.get("id"),
    )


GOOSE_RULES: Tuple[RuleDefinition, ...] = (
    RuleDefinition("GR-1", SOURCE, rule_gr1_sequence_violation, protocol=PROTOCOL),
    RuleDefinition("GR-2", SOURCE, rule_gr2_unknown_publisher, protocol=PROTOCOL),
    RuleDefinition("GR-3", SOURCE, rule_gr3_timing_deviation, protocol=PROTOCOL),
    RuleDefinition("GR-4", SOURCE, rule_gr4_decoy_gocb, protocol=PROTOCOL),
)


def evaluate_goose_event(
    event: Mapping[str, Any], context: GooseRuleContext
) -> Sequence[Alert]:
    """Apply GR-1..GR-4 to one event, in registry order.

    Returns [] for anything that is not a GOOSE row, so the caller can run this
    alongside the Modbus evaluator on every event without a protocol check of its own.
    """
    if str(event.get("protocol") or "") != PROTOCOL:
        return []
    alerts = []
    for rule in GOOSE_RULES:
        alert = rule.evaluate(event, context)
        if alert is not None:
            alerts.append(alert)
    return alerts
