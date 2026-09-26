# GridSnare protocol traffic monitor — Python 3 + Scapy (SPEC 7.2)
#
# Build context is the repository root (see docker-compose.yml) so later steps
# can pull in the root requirements.txt, config.yaml and shared modules.
#
# Scapy needs no libpcap here: on Linux it captures through raw AF_PACKET
# sockets, which is why the monitor service is given NET_RAW/NET_ADMIN.
#
# store.py is copied in below because traffic_monitor.py imports the raw_events
# schema from it. The Phase 2 GOOSE monitor does not use Scapy — it decodes raw
# frames with the shared codec in goose/goose_frame.py — but it writes that same
# table, which is why the schema is shared rather than defined per monitor.

FROM python:3.12-slim

# Pinned to current releases; once the root requirements.txt is populated,
# replace this line with `COPY requirements.txt .` + `pip install -r`.
#   scapy  - live capture + Modbus/TCP decoding (SPEC.md Section 7.2)
#   pyyaml - reads config.yaml, so ports and the DB path stay config-driven
#            instead of hardcoded (SPEC.md Section 8)
# libpcap is deliberately not installed: Scapy captures through raw AF_PACKET
# sockets on Linux, and this monitor filters on TCP port in Python.
RUN pip install --no-cache-dir scapy==2.7.0 pyyaml==6.0.3

WORKDIR /app

COPY monitor/ /app/
# SPEC.md Section 11: one container hosts the monitor + engine + dashboard, so the
# engine ships in this image and runs alongside the capture loop.
COPY engine/ /app/engine/
# The raw_events schema is shared with the Phase 2 GOOSE monitor (which runs in the
# goose image), so it lives in one module rather than a copy per image — see store.py.
COPY store.py /app/store.py
# The Modbus request decoder is shared with the honeypot log ingester (honeypot/
# log_ingest.py), which parses the same exchange out of Conpot's log, so it too lives
# in one module rather than a copy per image — see modbus_codec.py.
COPY modbus_codec.py /app/modbus_codec.py
COPY config.yaml /app/config.yaml

# -u so events appear in `docker compose logs` as they happen.
CMD ["python", "-u", "traffic_monitor.py"]
