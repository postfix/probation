# 0002 — Upstream writers may read hidden package metadata

Date: 2026-10-30. Status: accepted. Source: publishing-proxy Gate 1 C34.

An npm management operation needs the selected upstream's package metadata even when the writer's Probation group cannot read that package. A valid client certificate and developer token may obtain that metadata through the canonical packument route; this grants neither artifact bytes nor permission to write. The selected upstream still decides whether to accept each write.
