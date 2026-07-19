# PROMPTECTOMY

PROMPTECTOMY finds recurring LLM calls that can become deterministic code, asks Codex to draft replacements, and produces evidence showing what should change and what should stay on a model.

[View the hackathon demo](https://promptectomy.vercel.app) | [Quickstart](QUICKSTART.md) | [Architecture](docs/architecture/system-design.md) | [Threat model](docs/architecture/threat-model.md)

The public demo is a recorded replay of a real verified hackathon run. It does not execute repositories in Vercel.

## Why this exists

Extraction, classification, and routing often begin as model calls because that is the fastest way to ship. Once enough representative traffic exists, some of those calls are better expressed as ordinary code: faster, cheaper, deterministic, and easy to test. Other calls remain genuinely generative and should keep using a model.

PROMPTECTOMY is designed to make that distinction with evidence instead of guesswork.

## What works today

The current pre-v1 branch provides a deliberately narrow, safety-first foundation:

- local, non-mutating inspection and audit of Python and TypeScript repositories;
- explicit supported, unsupported, ambiguous, zero-finding, failed, and cancelled outcomes;
- private, unverified Codex patch drafts behind an exact egress policy;
- an accepted local OCI execution boundary with no network, an empty allowlisted environment, read-only source mounts, resource limits, cancellation, and cleanup receipts;
- canonical Contract v2 schemas with mechanically generated Python, TypeScript, and Rust bindings;
- owner-only SQLite state and a content-addressed artifact store with transactional events, crash reconciliation, tamper detection, and frozen reports;
- a capability-protected local API contract with bounded bodies, strict Host and Origin checks, idempotency, and event cursors;
- a Rust trusted core, private local daemon, and canonical state/report CLI with typed exits, restart-safe migration, and bounded out-of-process adapter supervision;
- safe JSON and Markdown run reports;
- a Next.js dashboard that replays the winning hackathon result.

Inspect, Audit, and Draft do not execute target repository code. Drafts are data until a later isolated evaluation accepts them. The legacy hackathon mutation and hot-swap commands fail closed.

The safe Python reference remains the current repository inspection and audit path. The Rust daemon and CLI now own the trusted local state and report boundary, including Python v2 import. Rust repository inspection still returns a typed unsupported result until the Phase 4 acquisition and language adapters are connected. Remote acquisition, evaluation, TUI, desktop GUI, and explicit branch-based Apply are not finished.

## Quickstart

Prerequisites: Python 3.12, [`uv`](https://docs.astral.sh/uv/), and Git.

```bash
git clone https://github.com/zippyg/codex-build-hack.git
cd codex-build-hack/engine
uv sync --frozen
uv run promptectomy doctor --json
uv run promptectomy inspect /path/to/local/repository --json
uv run promptectomy audit /path/to/local/repository --json
```

For a complete synthetic first run with no private repository, follow [QUICKSTART.md](QUICKSTART.md).

## Why Codex is central

Codex is the repository-aware engineering agent in the loop, not a chat widget attached to the report.

In the target workflow, deterministic controls first discover and classify callsites. A trusted connector then gives Codex only the approved source slices and evidence needed for one bounded task. Codex drafts a patch in tool-owned storage. The parent system, not Codex, evaluates that candidate against hidden evidence and issues the verdict. Applying an accepted patch is a separate explicit action.

This separation matters: Codex supplies the engineering judgment and implementation ability, while PROMPTECTOMY owns authority, isolation, evidence, and receipts.

## Trust model

```text
repository or archive
        |
  non-executing inventory and audit
        |
 exact egress manifest -> Codex drafts in tool-owned storage
        |
 accepted isolated executor evaluates candidate
        |
 digest-bound evidence and report
        |
 explicit preview and branch-based Apply
```

The core rules are simple:

1. Read-only modes do not mutate or execute the target.
2. Untrusted code never runs in the control plane or clients.
3. Credentials stay inside the connector that owns them.
4. Unsupported and insufficient evidence remain visible.
5. Apply is separate, explicit, stale-checked, recoverable, and never targets the default branch.

See the [system design](docs/architecture/system-design.md), [privacy boundary](docs/architecture/privacy-and-data-egress.md), and [threat model](docs/architecture/threat-model.md) for the accepted v1 design.

## Hackathon result

PROMPTECTOMY won the Codex Community Hackathon in London on 18 July 2026. In the event demonstration it compiled two low-entropy calls and kept the freeform call on the model:

| Callsite | Decision | Sealed holdout | Demonstrated latency |
| --- | --- | ---: | ---: |
| `extract_ticket_facts` | compile | 52/52 | about 900 ms to 0.006 ms |
| `route_ticket` | compile | 60/60 | about 900 ms to 0.0005 ms |
| `draft_empathetic_reply` | keep model | freeform generation | unchanged |

The demonstrated pipeline reduced estimated model cost by 44.79 percent. Agreement means preservation of recorded behavior, not proof that the original model output was objectively correct.

## Repository layout

```text
engine/                  Python reference, CLI, executor, and tests
ui/                      Next.js recorded dashboard
docs/adr/                accepted architecture decisions
docs/architecture/       design, privacy, security, and evidence
docs/product/            product scope and non-goals
docs/specs/              public contracts and compatibility notes
```

## Development

```bash
cd engine
uv sync --frozen
uv run pytest -q

cd ../rust
cargo fmt --all --check
cargo clippy --workspace --all-targets --all-features --locked -- -D warnings
cargo test --workspace --all-features --locked

cd ../ui
bun install --frozen-lockfile
bun run typecheck
bun run build
bunx playwright test
```

Contributor guidance lives in [AGENTS.md](AGENTS.md). The repository remains private while stable v1 and its license are finalized. No open-source license has been granted yet.
