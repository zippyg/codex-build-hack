# PROMPTECTOMY

**Codex finds the LLM calls that should be code, writes deterministic replacements, and proves them against recorded traffic it never saw. Calls that still need a model stay on the model.**

[Open the live interactive demo](https://promptectomy.vercel.app)

The public site replays a verified engine run. It does not execute a repository on Vercel.

Built from a new repository during the Codex Community Hackathon in London on 18 July 2026.

## The result in 30 seconds

PROMPTECTOMY turned two recurring model calls into deterministic Python and refused to replace the third:

| Callsite | Verdict | Sealed holdout | Latency |
| --- | --- | ---: | ---: |
| `extract_ticket_facts` | COMPILED | 52/52 | about 900 ms to 0.006 ms |
| `route_ticket` | COMPILED | 60/60 | about 900 ms to 0.0005 ms |
| `draft_empathetic_reply` | KEEP MODEL | Freeform generation | unchanged |

Whole-pipeline model cost fell **44.79 percent**. It did not fall to zero because the freeform reply still earned its tokens.

As a negative control, the scanner audited `microsoft/markitdown`, found three genuine vision/LLM callsites, and kept all three. PROMPTECTOMY is deliberately not a regex that deletes every model call.

## Why this matters

Teams use a model to ship extraction and classification quickly, then never revisit it. Low-entropy calls remain slow, costly, nondeterministic, and difficult to test even when their accumulated traffic has already specified the behavior.

PROMPTECTOMY turns that traffic into an executable specification:

1. Record the call input, normalized output, latency, and estimated cost in a local ledger.
2. Ask Codex to audit the code and identify low-entropy candidates.
3. Split traffic into train, dev, and holdout buckets by canonical request hash.
4. Give Codex only train and dev fixtures in an isolated Git worktree.
5. Let Codex write and repair a deterministic replacement.
6. Have the parent process grade the untouched holdout and issue the verdict.
7. Persist the receipts as an event stream that the dashboard can replay or follow live.

Agreement means preservation of the recorded model behavior. It is not a claim that the recorded model was objective ground truth.

## Why Codex is central

Codex is the compiler and the surgeon, not a chat box bolted onto the UI.

- It audits the target repository under a strict JSON output schema.
- It receives the executable specification as train and dev fixtures.
- It writes each replacement inside an isolated worktree.
- It repairs its own implementation against those visible fixtures.
- It never receives the holdout used for the demonstrated verdict.

Codex also built this project during the event. The Git history begins at 11:17 BST and records the contract freeze, engine build, kill gate, public-repository scan, dashboard, and verification work.

## Try the event demo

Prerequisites: Python 3.12, `uv`, `bun`, Git, and an authenticated Codex CLI.

```bash
git clone https://github.com/zippyg/codex-build-hack.git
cd codex-build-hack/engine
uv sync --frozen
uv run pytest -q

# Create the keyless synthetic traffic used by the event demo.
uv run python -m demo.triager.capture 240

# Audit, synthesize in isolated worktrees, verify, and save events.
uv run promptectomy run .. --events human
```

The run writes:

```text
.promptectomy/run/audit.json
.promptectomy/run/events.ndjson
.promptectomy/registry.json
engine/promptectomy/generated/*.py
```

## Scan another repository

Audit a local checkout:

```bash
cd engine
uv run promptectomy scan /path/to/repository --out /tmp/promptectomy-audit.json
```

Audit a public Git URL through an isolated shallow clone:

```bash
uv run promptectomy scan https://github.com/microsoft/markitdown --out /tmp/markitdown-audit.json
```

`scan` is audit-only. Full compilation still requires captured traffic and a supported Python/OpenAI adapter. The CLI now fails explicitly when those prerequisites are absent rather than reporting a misleading zero-work success.

## Open a live local report

After a run, start the event API:

```bash
cd engine
uv run promptectomy serve ..
```

In another terminal, start the dashboard:

```bash
cd ui
bun install --frozen-lockfile
bun dev
```

Open:

```text
http://127.0.0.1:4319/?live=http://127.0.0.1:4320/events
```

The same dashboard can play the frozen event fixture for a reliable 90-second judging video or consume the local SSE stream from an actual run.

## CLI

```text
promptectomy scan <path-or-public-git-url>  audit LLM callsites
promptectomy run <local-checkout>           compile captured candidates
promptectomy doctor <local-checkout>        show missing prerequisites
promptectomy serve <local-checkout>         expose run state and SSE
promptectomy accept <callsite>              enable an accepted replacement
promptectomy disable <callsite>             route back to the model
```

`run --events human` is the terminal progress view. There is no separate full-screen TUI in this hackathon build.

## Architecture

```text
target code + captured ledger
            |
        Codex audit
            |
 canonical hash split
      /     |      \
  train    dev   sealed holdout
      \     /
   Codex worktree
          |
 generated pure function
          |
   parent replay verdict
          |
 registry + NDJSON event log
          |
 local SSE API -> Next.js report
```

### Engine

Python 3.12 with `uv`: capture shim, append-only ledger, Codex scanner, Git worktree synthesis, replay, scoring, verifier, registry, Typer CLI, and local FastAPI report bridge.

### Dashboard

Next.js with `bun`: request wall, cost and latency meters, Codex activity, verdict receipts, replacement state, recorded replay controls, and live SSE mode.

### Contracts

Pydantic models in `engine/promptectomy/contracts.py` and matching Zod schemas in `ui/lib/contracts.ts` define the wire protocol.

## Honest prototype boundary

This is a hackathon prototype, not a production traffic optimizer.

- The public Vercel deployment is a recorded verified replay, not a hosted engine.
- General source auditing works for local checkouts and public Git URLs. General compilation does not yet work without captured traffic and a supported adapter.
- Capture coverage is intentionally narrow.
- The demonstrated holdout is absent from the synthesis worktree, but one-time-use state is process-local rather than durable across separate CLI invocations.
- Generated code must be treated as untrusted. The production design requires out-of-process execution, an allowlisted environment, resource limits, artifact hash binding, and explicit acceptance.
- Do not use the current hot-swap path on private repositories, real customer traffic, or production systems without completing the security plan.

## Post-hackathon product plan

The accepted Phase 0 design turns this prototype into a local-first, repository-to-evidence-to-patch product without pretending every codebase is equally supported. It separates read-only Inspect/Audit, tool-owned Draft, explicit branch-based Apply, and Integrate authority; targets a Rust control plane with Python and TypeScript adapters; and defines shared CLI, TUI, GUI, report, privacy, executor, contract, test, and open-source gates.

Start with:

- [product vision and scope](docs/product/vision-and-scope.md);
- [target system design](docs/architecture/system-design.md);
- [security threat model](docs/architecture/threat-model.md);
- [Phase 1A implementation handoff](docs/architecture/phase-1a-handoff.md).

These are target decisions, not claims about the hackathon build. Phase 1A is deliberately limited to non-mutating Python reference behavior and unverified patch artifacts.

## Repository layout

```text
engine/                 Python package, CLI, demo, and tests
ui/                     Next.js dashboard and Playwright tests
docs/                   contracts, submission pack, and source material
.agent/                 local plans, receipts, audits, logs, and handoff state
```

## Verify

```bash
cd engine
uv sync --frozen
uv run pytest -q

cd ../ui
bun install --frozen-lockfile
bun run typecheck
bun run build
bunx playwright test
```

## Event submission boundary

The London form requires a public GitHub repository and a directly uploaded working-product video of at most 90 seconds. Publishing the repository and submitting the form are deliberate human actions. This repository contains no automation that submits an entry.
