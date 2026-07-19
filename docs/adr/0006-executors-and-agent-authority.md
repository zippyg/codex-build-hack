# ADR 0006: Executors and agent authority

Status: accepted
Date: 18 July 2026

## Context

The prototype imports generated Python into the parent process after an AST blocklist check and passes almost the entire parent environment to the Codex subprocess. Repository content can also prompt-inject an agent. These are production no-go boundaries.

## Decision

Untrusted repository code, generated code, tests, build scripts, dependency scripts, and agent shell tools never run in the trusted core or client processes. The core sends immutable manifests to an executor adapter and accepts only declared artifacts, sanitized logs, resource records, and a termination cause.

### Executor tiers

| Tier | Backend | Eligible behavior |
|---|---|---|
| A | No accepted isolation | Inspect/Audit and policy-permitted unverified patch generation only; verified Draft disabled |
| B | OS process sandbox | Narrow, platform-specific trusted tool operations; no arbitrary repository/generated code |
| C | OCI container through an accepted local runtime | Recommended local native builds/tests with non-root, read-only source, offline execution, quotas, and no host sockets |
| D | Wasmtime/WASI | Compatible pure candidates/evaluators with explicit preopens and capabilities |
| E | gVisor/Firecracker-class worker | Later hosted or higher-risk workloads under a separate design |

An executor manifest declares snapshot and runtime image digests, command/args, read-only mounts, writable scratch, empty environment plus allowlist, network policy, CPU/memory/PID/file/disk/time/output limits, expected artifacts, toolchain, and dependency policy. Unsupported limit enforcement fails closed for verified Draft.

OCI is not accepted merely because a container starts. Acceptance tests must prove non-root execution, no privileged mode, no host/container-runtime socket, read-only root/source mounts, isolated scratch, disabled network, bounded process tree, resource/output limits, safe device/capability/seccomp policy, and cleanup. Wasmtime is a narrower capability backend, not a universal project runner. Tauri capabilities and the AST guard are not executor tiers.

Dependency acquisition is a separate, explicit, networked phase. It respects the repository lockfile, approved registries/hosts, integrity metadata, size/time budgets, and install-script policy. Candidate evaluation is offline against the acquired digest set.

### Agent runtime

The core defines a provider-neutral `AgentRuntime`; Codex is the first adapter. The trusted model connector owns the Codex/model authentication and may contact only configured model endpoints. Agent tools, repository commands, generated code, and test processes run inside the offline executor and cannot access connector credentials, control channels, host environment, user credential stores, or hidden holdout content.

An AgentRuntime is ineligible for supported Draft if it cannot separate model transport from tool execution. Official Codex surfaces support programmatic runs and structured output, but their availability does not waive PROMPTECTOMY's executor acceptance. The [Codex SDK](https://developers.openai.com/codex/sdk) and [`codex exec --output-schema`](https://developers.openai.com/codex/cli/reference) are integration options behind this boundary.

Phase 1A makes a narrower binding decision for unverified patch generation: call an API-available Codex coding model through the OpenAI Responses API from the trusted connector, omit every tool definition, require strict structured output, and transmit only the source slices already approved in the egress manifest. As of this decision, [GPT-5.3-Codex](https://developers.openai.com/api/docs/models/gpt-5.3-codex) supports the Responses endpoint and structured outputs. The selected model string, reasoning setting, request-schema digest, prompt digest, content manifest, response ID, usage, and returned model metadata are recorded.

The general Phase 1A path must not launch `codex exec`, a Codex SDK thread, MCP, shell, file, web, hosted-shell, apply-patch, or computer-use tools. A model request is data in and typed candidate data out. If the direct Responses transport, no-tool request shape, model capability, schema validation, egress approval, or budget cannot be proved, Draft returns `safe_agent_transport_unavailable` or the more specific typed policy error and creates no candidate patch. Later phases may admit agentic Codex surfaces only after their filesystem, tool, credential, network, and executor boundaries pass the same conformance tests.

Agent roles are bounded scanner/context curator, synthesizer, test adversary, security reviewer, and narrow patcher. Every invocation has one typed goal, readable/writable roots, tools, network status, environment names, time/token/spend/output budgets, attempt limit, stop condition, parent cancellation, prompt bundle digest, and explicit prohibition on Apply/Integrate authority. Repeated failure becomes a typed terminal result.

Prompts are versioned assets with trusted instructions separated from untrusted repository excerpts, typed input/output, evidence/uncertainty requirements, attacks and regression fixtures, model compatibility, and stable/candidate/deprecated lifecycle. Hidden holdouts remain parent-owned and inaccessible to candidate-generation agents.

## Consequences

- Verified Draft is unavailable on a machine without an accepted executor. Audit remains useful.
- Local setup is more demanding, but the product never falls back to host execution.
- Codex can remain central without making the model or agent the final correctness authority.
- Model calls can use a network while tool execution remains offline only if the runtime architecture proves that separation.

## Rejected alternatives

- AST allow/blocklisting as sandbox: rejected because Python and other language runtimes expose too many dynamic escape paths.
- Ordinary subprocess with a timeout: rejected because it retains host filesystem, credentials, network, and process-tree risk.
- Give the agent the model credential: rejected because repository prompt injection could exfiltrate it through tools.
- Autonomous repair until green: rejected because unbounded retries confuse activity with evidence and increase attack surface.
- OCI-only forever: rejected because some hosts lack it and hosted risk may require stronger isolation.

## Verification

Threats `EXEC-*`, `AGENT-*`, `CRED-*`, and `HOLD-*` and tests `EXEC-*`, `CONNECTOR-*`, `AGENT-*`, `CANCEL-*`, and `EVAL-*` in [the threat model](../architecture/threat-model.md) and [testing plan](../architecture/testing-and-benchmarks.md) are mandatory. Phase 1A implements only the no-tool trusted connector and unverified-output portion of this ADR. Phase 1B begins executor work.
