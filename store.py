#!/usr/bin/env python3
"""GridSnare shared data store — `raw_events` schema and migrations (SPEC.md 7.4).

Two writers, one table
----------------------
Both protocol traffic monitors write the same table:

  * ``monitor/traffic_monitor.py`` — Modbus TCP, ``protocol='modbus'`` (SPEC.md 7.2)
  * ``goose/goose_monitor.py``     — IEC 61850 GOOSE, ``protocol='goose'`` (SPEC.md 20.2)

They run in different container images, so the schema lives here rather than inside
either of them. A copy per image would be a second thing to keep in step, and the
failure mode of drift is silent: whichever writer starts first would define the
table, and the other would then fail — or worse, succeed while writing into columns
that mean something different than it thinks. One definition, imported by both.

Both Dockerfiles copy this file to ``/app/store.py``.

Why the table is wider than any one protocol
--------------------------------------------
SPEC.md Section 7.4 defines two core tables, ``raw_events`` and ``alerts``, "indexed
on source IP and timestamp for correlation queries" — it does not fix the column
list. Phase 1 added the Modbus fields; Phase 2 needs the GOOSE fields (StNum, SqNum,
source MAC, GoCB reference — SPEC.md 20.2). They coexist in one table, distinguished
by ``protocol`` (SPEC.md 20.3: alerts "join the existing DR-1 through DR-7 ... in the
same correlation engine and ``alerts`` table, distinguished by a ``protocol`` field").

A row therefore populates its own protocol's columns and leaves the others NULL. That
is deliberate: a GOOSE frame has no IP address or function code, and inventing one
(putting a MAC in ``src_ip``, say) would make the store lie to every reader that
queries it — including the rules that key off those columns.

``src_ip``/``dst_ip`` are therefore nullable: a GOOSE frame is layer 2 and has no IP
to record. SQLite cannot drop a NOT NULL constraint with ALTER TABLE, so a store that
predates those columns is migrated by rebuilding the table — see
``_rebuild_raw_events``. The rebuild copies every row, including ``id``, so
``alerts.event_id`` keeps pointing at the same events.

Migrating an existing store
---------------------------
``ensure_schema`` brings any existing store up to date in place: it rebuilds the table
if the nullable constraints are missing and adds any absent GOOSE columns. The
``data/events.db`` file holds captured history, so a schema change must not require
discarding it. On an already-current database it is a no-op, which lets every writer
call it unconditionally at startup.
"""

from __future__ import annotations

import sqlite3
from pathlib import Path
from typing import List, Sequence, Tuple

# Bumped when the column set changes. Recorded via PRAGMA user_version so a reader can
# tell at a glance which shape of the store it opened; the actual migration is driven
# by inspecting the table, not by this number, so a store carrying extra or missing
# columns still converges on the definition below.
SCHEMA_VERSION = 2

# The full column set, in order. Used by the rebuild to copy the columns a store
# already has, and to assert the desired shape.
RAW_EVENT_COLUMNS: Sequence[str] = (
    # identity
    "id", "timestamp", "source", "protocol",
    # Modbus TCP (Phase 1, SPEC.md 7.2) — nullable, because a GOOSE row has none
    "src_ip", "src_port", "dst_ip", "dst_port", "unit_id", "function_code",
    "register_address", "quantity", "value", "values_json",
    # IEC 61850 GOOSE (Phase 2, SPEC.md 20.2) — nullable, because a Modbus row has none
    "src_mac", "dst_mac", "app_id", "gocb_ref", "goid", "st_num", "sq_num",
    "conf_rev", "time_allowed_to_live_ms", "vlan_id", "vlan_priority",
)

# `{table}` is substituted so the rebuild can create `raw_events_new` from the same
# definition it uses for a fresh store — one definition, no drift between the table a
# new install gets and the table an upgrade produces.
RAW_EVENTS_TABLE = """
CREATE TABLE IF NOT EXISTS {table} (
    id                INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp         TEXT    NOT NULL,  -- capture time, ISO-8601 UTC
    source            TEXT    NOT NULL,  -- 'monitor' | 'honeypot' (SPEC.md Section 9)
    protocol          TEXT    NOT NULL,  -- 'modbus' | 'goose' (SPEC.md Section 20.3)

    -- Modbus TCP fields (Phase 1, SPEC.md 7.2). NULL on a GOOSE row: a GOOSE frame
    -- is layer 2 and has no address, port, unit or function code.
    src_ip            TEXT,
    src_port          INTEGER,
    dst_ip            TEXT,
    dst_port          INTEGER,
    unit_id           INTEGER,           -- Modbus unit / slave id
    function_code     INTEGER,
    register_address  INTEGER,           -- start address addressed by the request
    quantity          INTEGER,           -- coils/registers addressed
    value             INTEGER,           -- value written by a single-coil/register write
    values_json       TEXT,              -- JSON array, values written by a multiple write

    -- IEC 61850 GOOSE fields (Phase 2, SPEC.md 20.2). NULL on a Modbus row: the
    -- publisher is identified by its MAC and control block, not an IP.
    src_mac           TEXT,              -- publisher's source MAC (GR-2 key)
    dst_mac           TEXT,              -- multicast destination (01-0c-cd-...)
    app_id            INTEGER,           -- GOOSE APPID, 0x0000-0x3FFF
    gocb_ref          TEXT,              -- e.g. GSDECOY/PROT/LLN0$GO$gcbProtTrip
    goid              TEXT,              -- human-readable GoID chosen by the publisher
    st_num            INTEGER,           -- state number: increments on a state change (GR-1)
    sq_num            INTEGER,           -- sequence number: resets to 0 with StNum (GR-1)
    conf_rev          INTEGER,           -- configuration revision
    time_allowed_to_live_ms INTEGER,     -- TAL: subscriber timeout (GR-3 timing context)
    vlan_id           INTEGER,           -- 802.1Q VID (0 = priority-tagged, VID 0)
    vlan_priority     INTEGER            -- 802.1Q PCP, 0-7
);
"""

# Created after the table is guaranteed to have every indexed column. On a store that
# Phase 1 created, the table already exists, so CREATE TABLE IF NOT EXISTS is a no-op
# and the GOOSE columns arrive only via migration — building the indexes in the same
# statement as the table fails with "no such column: src_mac" for exactly the
# databases that need migrating.
RAW_EVENTS_INDEXES = """
CREATE INDEX IF NOT EXISTS idx_raw_events_timestamp
    ON raw_events(timestamp);
CREATE INDEX IF NOT EXISTS idx_raw_events_src_ip_timestamp
    ON raw_events(src_ip, timestamp);
-- GR-1/GR-2/GR-4 query a publisher's history by MAC and by control block, so index
-- those the way the Phase 1 rules index source IP rather than relying on a scan.
CREATE INDEX IF NOT EXISTS idx_raw_events_src_mac_timestamp
    ON raw_events(src_mac, timestamp);
CREATE INDEX IF NOT EXISTS idx_raw_events_gocb_timestamp
    ON raw_events(gocb_ref, timestamp);
"""

# Added by Phase 2, in declaration order. Listed separately so a migration can report
# exactly which columns it added rather than claiming a migration wholesale.
GOOSE_COLUMNS: Sequence[Tuple[str, str]] = (
    ("src_mac", "TEXT"),
    ("dst_mac", "TEXT"),
    ("app_id", "INTEGER"),
    ("gocb_ref", "TEXT"),
    ("goid", "TEXT"),
    ("st_num", "INTEGER"),
    ("sq_num", "INTEGER"),
    ("conf_rev", "INTEGER"),
    ("time_allowed_to_live_ms", "INTEGER"),
    ("vlan_id", "INTEGER"),
    ("vlan_priority", "INTEGER"),
)

# Columns that must accept NULL for both protocols to share the table. Phase 1 declared
# the Modbus ones NOT NULL; that is correct for a Modbus-only store and wrong for one
# that also holds GOOSE.
MUST_BE_NULLABLE: Sequence[str] = ("src_ip", "dst_ip")


def _table_info(connection: sqlite3.Connection, table: str) -> List[Tuple]:
    return list(connection.execute(f"PRAGMA table_info({table})"))


def _table_exists(connection: sqlite3.Connection, table: str) -> bool:
    row = connection.execute(
        "SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = ?", (table,)
    ).fetchone()
    return row is not None


def _column_names(connection: sqlite3.Connection, table: str) -> List[str]:
    return [row[1] for row in _table_info(connection, table)]


def _needs_rebuild(connection: sqlite3.Connection) -> bool:
    """True if an existing table still constrains a column that must be nullable."""
    not_null = {row[1]: bool(row[3]) for row in _table_info(connection, "raw_events")}
    return any(not_null.get(column) for column in MUST_BE_NULLABLE)


def _rebuild_raw_events(connection: sqlite3.Connection) -> None:
    """Rebuild raw_events against the current definition, preserving every row.

    SQLite cannot remove a NOT NULL constraint with ALTER TABLE, so the standard
    approach applies: build the table as it should be, copy the data across, swap it
    in. `id` is copied explicitly — alerts.event_id references raw_events.id, and
    renumbering the events would silently repoint that history at different traffic.
    """
    existing = set(_column_names(connection, "raw_events"))
    carried = [column for column in RAW_EVENT_COLUMNS if column in existing]
    column_list = ", ".join(carried)

    # Both monitors call ensure_schema at startup, so two containers can begin this
    # rebuild at the same moment. BEGIN IMMEDIATE takes the write lock up front and
    # the re-check inside the transaction means the loser sees the winner's finished
    # work and does nothing, rather than racing to create the same temp table.
    connection.commit()  # close any implicit transaction so BEGIN is legal
    connection.execute("BEGIN IMMEDIATE")
    try:
        if not _needs_rebuild(connection):
            connection.execute("ROLLBACK")
            return
        # A previously interrupted attempt must not be mistaken for the target table
        # by CREATE TABLE IF NOT EXISTS below.
        connection.execute("DROP TABLE IF EXISTS raw_events_new")
        connection.execute(RAW_EVENTS_TABLE.format(table="raw_events_new"))
        connection.execute(
            f"INSERT INTO raw_events_new ({column_list}) SELECT {column_list} FROM raw_events"
        )
        connection.execute("DROP TABLE raw_events")
        connection.execute("ALTER TABLE raw_events_new RENAME TO raw_events")
        connection.execute("COMMIT")
    except Exception:
        connection.execute("ROLLBACK")
        raise


def ensure_schema(connection: sqlite3.Connection) -> List[str]:
    """Create the table if absent, and bring an existing one up to date in place.

    Returns the names of the GOOSE columns actually added, so a caller can log a real
    migration rather than claiming one happened.
    """
    if not _table_exists(connection, "raw_events"):
        connection.execute(RAW_EVENTS_TABLE.format(table="raw_events"))
    elif _needs_rebuild(connection):
        _rebuild_raw_events(connection)

    existing = set(_column_names(connection, "raw_events"))
    added: List[str] = []
    for name, column_type in GOOSE_COLUMNS:
        if name in existing:
            continue
        # ALTER TABLE ADD COLUMN cannot add a NOT NULL column without a default, and
        # none of these should be: NULL means "this row is not that protocol", which
        # is the truth for every Modbus row already in the store.
        connection.execute(f"ALTER TABLE raw_events ADD COLUMN {name} {column_type}")
        added.append(name)

    # Only now that every indexed column is guaranteed to exist.
    connection.executescript(RAW_EVENTS_INDEXES)

    connection.execute(f"PRAGMA user_version = {SCHEMA_VERSION}")
    return added


def open_database(path: str) -> sqlite3.Connection:
    """Open (creating if needed) the shared store and bring its schema up to date."""
    database_path = Path(path)
    database_path.parent.mkdir(parents=True, exist_ok=True)

    # check_same_thread=False: writes come from a capture thread, guarded by a lock in
    # each monitor (see TrafficMonitor._store / GooseMonitor._store).
    connection = sqlite3.connect(database_path, timeout=10.0, check_same_thread=False)
    # A rollback journal, not WAL.
    #
    # The store is a bind mount from Windows (Docker Desktop's 9p/virtiofs). WAL keeps
    # its index in a second `-shm` file that every connection must mmap, and that
    # mapping fails across containers on this mount. The symptom is `unable to open
    # database file` in new processes and other containers while the container that
    # already holds the file keeps writing.
    #
    # The cost is the ordinary one: readers and the writer serialise instead of running
    # concurrently. At a few small transactions per second (one insert per captured frame,
    # one query per dashboard refresh) with a busy timeout in place, that is not a
    # constraint worth an unusable store.
    connection.execute("PRAGMA journal_mode=DELETE")
    connection.execute("PRAGMA synchronous=NORMAL")
    ensure_schema(connection)
    connection.commit()
    return connection
