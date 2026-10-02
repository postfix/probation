# Executed reproductions — Gate 3 reopen (2026-09-25)

Run by the main agent against `target/debug/package-firewall serve` with a scratch config
(`log_file_path` set, `listen 127.0.0.1:18099`). These are the executed evidence behind C87 and the
G3-T12 closure; everything else in the reopen is structural.

## 1. `RUST_LOG` silences the audit trail (C87, G3-T9)

One `GET /npm/left-pad/1.3.0` per run, four `RUST_LOG` states:

| `RUST_LOG` | stdout | NDJSON sink |
|---|---|---|
| unset | 2170 bytes, decision line present | 2 records |
| `info` | 2170 bytes, decision line present | 2 records |
| `hyper=debug` | **0 bytes** | 2 records |
| set but empty | **0 bytes** | 2 records |

The set-but-empty case is the shape a systemd unit or compose file produces from an unset variable.

## 2. The window's loss count reaches the console past a full queue (G3-T12)

`log_queue_max_bytes = 32768` (one record), 400 concurrent requests, `RUST_LOG` unset:

- sink took **178** `request_decided` records
- stdout summary line reported **`dropped_file: 222`**
- 178 + 222 = **400** — reconciles exactly

Confirms `emit` (`src/http/logging.rs`) writes the counts with `tracing::info!` **before**
`sinks.offer(Record::RequestSummary(..))`. **Tier: manual** — the run predates C87's pin, so it
witnesses the ordering, not the pin that guarantees the console stays enabled.

## 3. Stream separation (recorded, not acted on)

stdout and stderr captured separately, one request: stdout 2170 bytes carrying the decision line, the
summary, `listening`, `shutting down` and two blocklist `ERROR`s; **stderr 0 bytes**. The audit trail
shares a stream with operational diagnostics. Splitting them was considered and **not taken** (YAGNI,
user instruction 2026-09-25).
