# 0003 — Canonical token-bearing npm packument reads may reveal hidden metadata

Date: 2026-10-30. Status: accepted. Source: publishing-proxy Gate 1 C35.

An npm packument GET cannot reliably reveal whether a write will follow it. Therefore any canonical packument GET with a valid client certificate and developer token may return the selected upstream's metadata despite Probation group read policy, including `npm view` or an install that never writes. Tokenless metadata, other reads, and artifact downloads remain group-filtered.
