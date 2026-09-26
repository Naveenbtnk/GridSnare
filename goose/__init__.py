"""Decoy IED (IEC 61850 GOOSE) for the GridSnare lab, plus the shared wire codec.

``goose_frame.py`` is deliberately not decoy-specific: it is the single GOOSE/BER
implementation used by the decoy (receive half of SPEC.md 20.2), by the lab tooling
in ``tests/goose_lab.py``, and by the GOOSE traffic monitor. Keeping one codec means
"valid GOOSE" cannot mean two different things in two different places.
"""
