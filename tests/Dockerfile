# GridSnare test runner — SPEC.md Section 12 (Phase 1) / 20.6 (Phase 2)
#
# This image exists so the test plan runs the same way every service does, inside
# Docker (README instruction 3: no packages installed on the host). It carries the
# code under test rather than mounting the working tree, so a run cannot pick up
# uncommitted edits that the running monitor/dashboard containers do not have.
#
# Build context is the repository root (see docker-compose.yml).

FROM python:3.12-slim

# Pinned test dependencies, from the single requirements file the repo already has.
COPY requirements.txt /tmp/requirements.txt
RUN pip install --no-cache-dir -r /tmp/requirements.txt

WORKDIR /app

# The same files the monitor image runs, so the engine a test advances (`--once`)
# is the same engine the stack runs.
COPY config.yaml /app/config.yaml
COPY engine/ /app/engine/
COPY tests/ /app/tests/

# The shared SQLite store is mounted at /app/data by docker-compose.yml, which is
# the path config.yaml already points every component at.
CMD ["python", "-m", "pytest", "tests", "-v"]
