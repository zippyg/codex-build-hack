# ADR 0001: Authority and non-mutation

Status: accepted
Date: 18 July 2026

## Context

The hackathon `run` command writes fixtures, event logs, registry data, generated modules, branches, and worktrees inside the target checkout. That behavior made the demo possible but is the wrong default for a general repository tool. Analysis, candidate development, application, and integration have different risks and must not share an implicit authority grant.

## Decision

PROMPTECTOMY has five modes. Each run records an immutable authority manifest before work begins.

| Mode | Read target | Write target | Execute target/generated code | External transmission | Persisted output |
|---|---|---|---|---|---|
| Inspect | Selected repository paths and Git metadata | Never | Never | None by default; optional minimized source only under a separate egress grant | Safe inventory, exclusions, support report, digests |
| Audit | Inspect access plus explicitly selected evidence references | Never | Never by default | Bounded Codex context only if preflight grants named files/classes and destination | Findings, evidence gaps, safe events, report |
| Draft | Immutable tool-owned snapshot and authorized evidence | Never | Only inside an accepted executor; otherwise patch is `unverified` | Bounded model context under the recorded grant; executor tools remain offline | Candidate patch/tests, evaluation or unverified status, report, receipt |
| Apply | Target Git metadata, selected files, receipt, patch | Named non-default branch only after preview | Approved checks only in the accepted executor | No new egress unless separately granted | Applied diff/commit reference, recovery reference, apply receipt |
| Integrate | Integration-specific | Only declared integration configuration after a new grant | Integration-specific isolated checks | Named service endpoints only | Integration config, audit record, uninstall/rollback instructions |

Further rules:

1. Mode escalation creates a new action and authority record. Audit cannot silently become Draft or Apply.
2. Inspect, Audit, and Draft preserve the byte-level digest of every target file, Git index, refs, config, hooks, worktree list, and untracked set. A changed digest is a failed run and release blocker.
3. Draft storage is outside the target checkout and outside its `.git` directory. It has a distinct run ID, private permissions, quota, retention, and cleanup record.
4. Apply requires an exact snapshot match or an explicit stale-state refusal. It requires a named destination branch, full diff preview, valid eligible receipt, clean-state policy, recovery reference, and approved post-apply checks.
5. Direct Apply to the default branch is disabled in v1. Force operations and destructive cleanup are prohibited.
6. Untrusted repository text, generated code, and dependency scripts never execute in the core, daemon, CLI, TUI, GUI, or report renderer.
7. Agents cannot create authority, widen file/tool/network access, access a hidden holdout, or apply a patch.
8. Cancellation revokes active capabilities, terminates the complete worker tree, records retained artifacts, and runs separately retryable cleanup.

The preflight manifest includes source identity and revision, selected paths, mode, reads, writes, commands, executor and limits, network destinations, environment variable names, model/runtime, budget, source/trace egress classes, retention, cancellation, and cleanup. It never displays or stores secret values in normal events.

## Consequences

- The default product path becomes honest and safe to inspect even when Draft isolation is unavailable.
- The UI needs explicit authority transitions instead of a single optimistic progress flow.
- Phase 1A can produce an unverified patch but cannot claim verified Draft before Phase 1B supplies an accepted executor.
- More runs end as unsupported or policy-denied. That is intended.
- Apply and Integrate require separate threat models and acceptance gates.

## Rejected alternatives

- Preserve `run` as a scan-to-hot-swap command: rejected because it combines read, mutation, agent write, execution, and activation.
- Ask for broad permission once: rejected because consent is not meaningful when later actions have materially different authority.
- Rely on Git rollback after mutation: rejected because rollback can discard or confuse user work and does not prevent code execution or egress.

## Verification

Tests `INV-AUTH-01` through `INV-AUTH-07` and `INV-NM-01` through `INV-NM-05` in [testing and benchmarks](../architecture/testing-and-benchmarks.md) are mandatory. The authority state machine and manifest schema are defined in [contract v2](../architecture/contracts-v2.md).
