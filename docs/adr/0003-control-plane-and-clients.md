# ADR 0003: Rust control plane and shared clients

Status: accepted
Date: 18 July 2026

## Context

The prototype duplicates contracts between Pydantic and Zod, keeps correctness state in files and process memory, and couples orchestration to a Python CLI. The long-term product needs durable jobs, process-tree control, artifact integrity, a TUI, a desktop app, and cross-platform distribution. A big-bang rewrite would discard working domain behavior before conformance exists.

## Decision

Use an evolutionary shared-core architecture:

- Rust owns the durable local orchestrator, policy engine, repository acquisition/snapshots, SQLite state, content-addressed artifacts, process supervision, executor interface, local API, CLI, and Ratatui TUI.
- Python remains the initial reference adapter for current capture/evaluation knowledge.
- TypeScript owns Node capture adapters and the React presentation layer.
- Tauri 2 hosts the desktop client. Its capabilities limit frontend-to-native IPC, but do not isolate repository or generated code.
- CLI, TUI, GUI, and static reports are projections of one versioned run/event contract. No client owns hidden orchestration rules.
- The daemon is optional for one-shot CLI use but authoritative for durable/reconnectable runs.
- Local transport prefers Unix domain sockets on macOS/Linux and named pipes on Windows. Loopback HTTP requires a short-lived capability, strict origin validation, no wildcard CORS, and loopback-only binding.

SQLite is the local job/event source of truth with one orchestrator writer and concurrent readers. WAL is allowed only with a patched SQLite release: 3.51.3 or later, or an upstream-patched line such as 3.50.7/3.44.6. The upstream WAL documentation reports a rare corruption bug in earlier WAL versions under concurrent write/checkpoint conditions. The chosen embedded SQLite version is pinned and exercised by crash/recovery tests. WAL is never placed on a network filesystem.

The Rust migration begins only after contract v2 and the safe Python reference path exist. The Python prototype acts as a conformance oracle for intended domain behavior, not for its unsafe mutation/execution design.

## Consequences

- Cross-platform process and state behavior get a small typed trusted core.
- Language/provider behavior can evolve without putting target runtimes in the daemon.
- Rust adds implementation and packaging cost, so migration is phased and contract-driven.
- The GUI can close/restart without changing run correctness.
- SQLite checkpointing, backup, busy handling, and version pinning become explicit operational responsibilities.

## Rejected alternatives

- Python for all layers: viable for an internal tool, but weaker for distribution, process supervision, TUI integration, and the intended trusted core.
- Immediate Rust rewrite: rejected because it would replace domain logic before fixtures and contracts stabilize.
- Next.js or Electron as the authority: rejected because filesystem/process access and a local security boundary should not live in a web presentation process.
- Hosted control plane first: rejected because private-code tenancy and worker isolation would dominate the product before the local workflow is trustworthy.

## Primary-source constraints

- [SQLite WAL](https://sqlite.org/wal.html) defines concurrency, same-host limitations, checkpoint behavior, and the 2026 WAL-reset fix requirements.
- [Tauri permissions](https://v2.tauri.app/security/permissions/), [capabilities](https://v2.tauri.app/security/capabilities/), and [runtime authority](https://v2.tauri.app/security/runtime-authority/) define frontend command grants. PROMPTECTOMY treats these as IPC controls, not a code sandbox.

## Verification

The component and migration boundaries are in [system design](../architecture/system-design.md). Cross-client and recovery tests are `STATE-*`, `API-*`, `CLI-*`, `TUI-*`, and `GUI-*` in [testing and benchmarks](../architecture/testing-and-benchmarks.md).
