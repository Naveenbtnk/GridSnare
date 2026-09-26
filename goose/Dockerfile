# GridSnare Phase 2 — decoy IED image (SPEC.md Section 20.2, 20.5)
#
# Builds libiec61850 from a pinned, hash-verified release tarball and installs its
# SWIG Python bindings, so the decoy relay can publish GOOSE through the library's
# own GoosePublisher API rather than a hand-rolled frame generator.
#
# SPEC.md 20.5 is explicit that "libiec61850 is built inside the Docker image, not
# installed on the host", and README instruction 3 says the same. This image is
# therefore the only place the library exists.
#
# One image, two Phase 2 services (docker-compose.yml): the `goose` service runs the
# decoy IED, and `goose-monitor` runs the GOOSE traffic monitor (SPEC.md 20.2). The
# monitor does not need libiec61850 — it decodes raw frames with goose/goose_frame.py
# — but it writes the same store, so sharing this image avoids a third build with its
# own pinned dependency set for no gain.
#
# Two stages, because the build needs a toolchain the running decoy should not
# carry: a real protection relay on a substation LAN would not ship gcc + cmake,
# and a decoy is meant to look like the device it claims to be. The runtime stage
# below keeps only the shared library and the compiled Python extension.

# ---------------------------------------------------------------------------
# Stage 1 — build libiec61850 and its Python bindings
# ---------------------------------------------------------------------------
FROM python:3.12-slim-bookworm AS builder

# Pinned, and verified by SHA-256 before it is unpacked: the same rule applied to
# the vendored Chart.js and the dashboard typeface. A substituted archive fails the
# build here rather than silently becoming part of the decoy.
ARG LIBIEC61850_VERSION=1.6.2
ARG LIBIEC61850_SHA256=7ad44f9ebe16a67205f54fac9b53c551cb1cf01c947dc8a401ad550047027df7

RUN apt-get update \
 && apt-get install -y --no-install-recommends \
      build-essential \
      cmake \
      swig \
      ca-certificates \
      curl \
 && rm -rf /var/lib/apt/lists/*

WORKDIR /src

RUN set -eux; \
    curl -sSL -o libiec61850.tar.gz \
      "https://github.com/mz-automation/libiec61850/archive/refs/tags/v${LIBIEC61850_VERSION}.tar.gz"; \
    echo "${LIBIEC61850_SHA256}  libiec61850.tar.gz" | sha256sum -c -; \
    tar xzf libiec61850.tar.gz; \
    mv "libiec61850-${LIBIEC61850_VERSION}" libiec61850; \
    rm libiec61850.tar.gz

# One upstream patch, and only one: pyiec61850/iec61850.i declares two R-GOOSE-only
# functions that CMake does not compile unless mbedtls is enabled, which left the
# binding unimportable ("undefined symbol: GoosePublisher_createRemote"). The patch
# adds two %ignore lines; it is applied with `--dry-run` first so a future upstream
# change fails the build here with a clear reason instead of a confusing link error.
# The tarball itself stays hash-verified above — this patch is ours, not a replacement
# for that check, and it is reviewable in goose/pyiec61850-r-goose-ignore.patch.
COPY goose/pyiec61850-r-goose-ignore.patch /src/pyiec61850-r-goose-ignore.patch
RUN set -eux; \
    patch -p1 -d libiec61850 --dry-run -i /src/pyiec61850-r-goose-ignore.patch; \
    patch -p1 -d libiec61850 -i /src/pyiec61850-r-goose-ignore.patch

# BUILD_PYTHON_BINDINGS=ON is what produces pyiec61850 (SWIG). The publisher side
# of that binding is the part Phase 2 needs: goose_publisher.h is wrapped, along
# with a CommParameters_setDstAddress helper, because a C array cannot be set
# field-by-field from Python.
#
# Examples and the static library are off: neither is used at runtime, and the
# shared library is what the SWIG module links against.
RUN set -eux; \
    cmake -S libiec61850 -B build \
      -DCMAKE_BUILD_TYPE=Release \
      -DBUILD_PYTHON_BINDINGS=ON \
      -DBUILD_EXAMPLES=OFF \
      -DBUILD_TESTING=OFF \
      -DCMAKE_INSTALL_PREFIX=/usr/local; \
    cmake --build build --parallel "$(nproc)"; \
    DESTDIR=/stage cmake --install build

# ---------------------------------------------------------------------------
# Stage 2 — runtime: the decoy IED only
# ---------------------------------------------------------------------------
FROM python:3.12-slim-bookworm

LABEL org.opencontainers.image.title="GridSnare IEC 61850 GOOSE (decoy IED + traffic monitor)"

# Runtime dependency, pinned inline as the other service images do (see the note in
# requirements.txt). The decoy reads the GoCB identity, APPID and timing profile
# from config.yaml, because SPEC.md Section 8 keeps those out of the code.
#
# This was missing at first and the container crash-looped on
# "ModuleNotFoundError: No module named 'yaml'" — worth noting because the decoy's
# restart policy turned a missing import into a visible failure loop rather than a
# silent one.
RUN pip install --no-cache-dir "PyYAML==6.0.3"

# The SWIG module is loaded at runtime, so the shared library it links against must
# be present and findable. Copying the install tree and running ldconfig keeps the
# SONAME resolution honest instead of relying on a development symlink.
COPY --from=builder /stage/usr/local/lib/ /usr/local/lib/
COPY --from=builder /stage/usr/local/lib/python3.12/site-packages/ /usr/local/lib/python3.12/site-packages/
RUN ldconfig \
 && python -c "import pyiec61850, yaml; print('pyiec61850 + yaml import OK')"

# The decoy shares the repo's config rather than hardcoding GoCB references, appId
# and timing profile: SPEC.md Section 8 requires thresholds to be configuration.
#
# goose_frame.py is the shared GOOSE/BER codec. It lives in the repo (not in this
# image) so the decoy, the lab tooling and the GOOSE traffic monitor all speak the
# same wire format; the decoy needs it for the receive half of SPEC.md 20.2.
COPY goose/decoy_ied.py /app/goose/decoy_ied.py
COPY goose/goose_frame.py /app/goose/goose_frame.py
COPY goose/goose_monitor.py /app/goose/goose_monitor.py
COPY goose/__init__.py /app/goose/__init__.py

# The raw_events schema, shared with the Phase 1 Modbus monitor because both write the
# same table from different images — see store.py for why one copy beats two.
COPY store.py /app/store.py

WORKDIR /app

# Fail fast and loudly if the bindings are missing: a decoy that cannot publish is
# worse than one that refuses to start, because it looks alive on the dashboard
# while the GOOSE segment is unwatched.
CMD ["python", "-u", "goose/decoy_ied.py"]
