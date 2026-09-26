# GridSnare alert dashboard — Flask + Chart.js (SPEC.md Sections 7.5 and 10)
#
# Build context is the repository root (see docker-compose.yml) so this image can
# pick up config.yaml alongside the app.

FROM python:3.12-slim

# Pinned to current releases; once the root requirements.txt is populated, replace
# this line with `COPY requirements.txt .` + `pip install -r`.
#   flask  - the dashboard app (SPEC.md Section 10)
#   pyyaml - reads config.yaml, so bind address, port, refresh interval and window
#            sizes stay config-driven rather than hardcoded (SPEC.md Section 8)
RUN pip install --no-cache-dir flask==3.1.3 pyyaml==6.0.3

WORKDIR /app

# Chart.js is vendored at build time instead of loaded from a CDN: the monitored
# segment is isolated (SPEC.md Section 11) and the page must render without the
# viewer's browser needing internet access. Fetching with urllib keeps curl/apt out
# of the image.
#
# The bytes are checked against the sha256 of chart.js 4.5.1 that this image was
# built and tested with, so a substituted or truncated download fails the build
# instead of shipping a silently broken or tampered chart library.
ARG CHARTJS_SHA256=48444a82d4edcb5bec0f1965faacdde18d9c17db3063d042abada2f705c9f54a
RUN mkdir -p static \
 && python -c "import hashlib, urllib.request; data = urllib.request.urlopen('https://unpkg.com/chart.js@4.5.1/dist/chart.umd.min.js').read(); digest = hashlib.sha256(data).hexdigest(); assert digest == '${CHARTJS_SHA256}', f'chart.js sha256 mismatch: got {digest}'; open('static/chart.umd.min.js', 'wb').write(data); print('vendored chart.js:', len(data), 'bytes, sha256 verified')"

# Typeface, vendored for the same reason as Chart.js: the page has to render with
# no internet access (SPEC.md Section 11), so a webfont CDN is not an option.
#
# Plus Jakarta Sans, latin subset, four weights — ~12 KB each, SIL Open Font
# License 1.1, redistributable. Source: the @fontsource package on jsDelivr, which
# is a versioned, immutable URL. Each file's sha256 is checked, so a substituted or
# truncated download fails the build instead of shipping a silently wrong face.
#
# Only the latin subset is fetched: the dashboard's content is ASCII plus the
# occasional en dash, and pulling cyrillic/vietnamese subsets would ship ~10x the
# bytes for glyphs nothing on the page uses.
ARG PLUS_JAKARTA_VERSION=5.3.0
ARG PJS_SHA256_400=221a4135d06a4b33abbd535e9a0da4e565d19545ddd9267c4e678a916d54d9b6
ARG PJS_SHA256_500=bad081c8dbc15aed6c5e4cde5461914f7b3bdc295b7a7aed177e4beddb79bffa
ARG PJS_SHA256_600=8872bb5c9111df9bd3162c2394aee6354d782b13408a4dd5bbf65c48207206e6
ARG PJS_SHA256_700=2050755bf475817c96ac7d914c7f07cc3c2d11ff4b3fb4747b8d41de584aad17
RUN set -eu; mkdir -p static/fonts; \
    for pair in "400:${PJS_SHA256_400}" "500:${PJS_SHA256_500}" "600:${PJS_SHA256_600}" "700:${PJS_SHA256_700}"; do \
      weight="${pair%%:*}"; want="${pair#*:}"; \
      python -c "import hashlib, sys, urllib.request; weight, want = sys.argv[1], sys.argv[2]; url = f'https://cdn.jsdelivr.net/npm/@fontsource/plus-jakarta-sans@${PLUS_JAKARTA_VERSION}/files/plus-jakarta-sans-latin-{weight}-normal.woff2'; data = urllib.request.urlopen(url).read(); got = hashlib.sha256(data).hexdigest(); assert got == want, f'font {weight} sha256 mismatch: got {got}, wanted {want}'; open(f'static/fonts/plus-jakarta-sans-latin-{weight}.woff2', 'wb').write(data); print('vendored font', weight, len(data), 'bytes, sha256 verified')" "$weight" "$want"; \
    done

COPY dashboard/app.py /app/app.py
COPY dashboard/templates/ /app/templates/
COPY dashboard/static/ /app/static/
COPY config.yaml /app/config.yaml

# -u so startup and per-request lines stream into `docker compose logs`.
CMD ["python", "-u", "app.py"]
