# Quickstart

This walkthrough inspects a synthetic repository without sending data, executing its code, or modifying it.

## Prerequisites

- Python 3.12
- [`uv`](https://docs.astral.sh/uv/)
- Git

Rust 1.92 is only required for the Rust daemon and canonical state/report CLI.

## Install from source

```bash
git clone https://github.com/zippyg/codex-build-hack.git
cd codex-build-hack/engine
uv sync --frozen
uv run promptectomy --help
```

## Create a disposable example

```bash
fixture_dir="$(mktemp -d)"
state_dir="$(mktemp -d)"

printf '%s\n' \
  'from openai import OpenAI' \
  'client = OpenAI()' \
  'result = client.responses.create(model="gpt-5", input="classify this")' \
  > "$fixture_dir/app.py"
```

## Inspect and audit

```bash
PROMPTECTOMY_HOME="$state_dir" uv run promptectomy doctor "$fixture_dir" --json
PROMPTECTOMY_HOME="$state_dir" uv run promptectomy inspect "$fixture_dir" --json
PROMPTECTOMY_HOME="$state_dir" uv run promptectomy audit "$fixture_dir" --json
PROMPTECTOMY_HOME="$state_dir" uv run promptectomy status --json
```

Expected facts:

- the Python OpenAI Responses callsite is reported;
- the highest support level is `L1`;
- no source file changes;
- no repository code execution;
- no network request;
- a safe local run projection under the private state directory.

Audit is deterministic and local. A verified replacement requires evidence capture, an approved Codex egress policy, and an accepted isolated executor. PROMPTECTOMY fails closed when those prerequisites are absent.

## Read a report

Copy the `run_id` from the Audit output:

```bash
PROMPTECTOMY_HOME="$state_dir" uv run promptectomy report RUN_ID --format markdown
```

Reports describe support, findings, work performed, limitations, and errors without embedding source bodies or credentials.

## Try the Rust control plane

Build the canonical CLI:

```bash
cd ../rust
cargo build --release --bins --locked
./target/release/promptectomy --json doctor
```

Run the private local daemon in one terminal:

```bash
./target/release/promptectomy --json daemon
```

The Rust CLI currently owns trusted local state, migration, status, watch, cancellation, and JSON or Markdown reports. It does not yet inspect a repository. `inspect`, `audit`, `draft`, and `apply` fail with typed unsupported results until their later safety gates are connected.

## Next

- [Product scope](docs/product/vision-and-scope.md)
- [System design](docs/architecture/system-design.md)
- [Privacy and data egress](docs/architecture/privacy-and-data-egress.md)
- [Threat model](docs/architecture/threat-model.md)
