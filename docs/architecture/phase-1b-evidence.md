# Phase 1B accepted OCI executor evidence

Date: 19 July 2026

Status: accepted.

## Scope and authority

Phase 1B adds a closed executor manifest, typed receipts, a reviewed OCI runner image, a single accepted local backend cell, and a separate dependency-acquisition contract. It does not connect the executor to Verified Draft. It does not add host execution, repository acquisition, Contract v2, Rust, TUI, GUI, Apply, deployment, or publication.

Offline evaluation has no weaker fallback. A reachable Docker daemon or a successful command is not enough to produce `accepted: true`. Acceptance requires the hostile profile to pass against the exact image content and runtime identity. Networked dependency acquisition is a separate operation and currently returns typed `dependency_network_policy_unavailable` without opening a network or starting a process.

## Accepted support cell

Only this cell is accepted by Phase 1B:

| Dimension | Accepted value |
| --- | --- |
| Host | Apple Silicon macOS |
| Tested host | macOS 26.5.1, build 25F80 |
| OCI runtime | OrbStack 2.2.1 |
| Docker client | 27.1.1 |
| Docker server/API | 29.4.0 / 1.54 |
| Container runtime | containerd 2.2.2, runc 1.4.2 |
| Runtime kernel | 7.0.11-orbstack-00360-gc9bc4d96ac70 |
| Architecture | aarch64 |
| Context | `orbstack` |

Linux hosts, Windows hosts, Docker Desktop, Colima, remote contexts, and other architectures are unaccepted. They fail with typed `unsupported_executor_context`; Phase 1B makes no portability claim for them.

## Image and runner identity

- Base: official `python:3.12.13-slim-bookworm`.
- Pinned multi-platform base manifest: `sha256:d50fb7611f86d04a3b0471b46d7557818d88983fc3136726336b2a4c657aa30b`.
- Tested arm64 base manifest: `sha256:c18c7a910432dde3311fc54d02e5d5220f3ebe26fec43ff15745982863dd7b3b`.
- Packaged runner digest: `sha256:30f140ea38cd4287d6d7c91043732df0e23df72c9484057108b913a3a8b4489b`.
- Final locally built image ID: `sha256:23b8908a955aa2b7eb602845e08b50e1821d072ed67e510580d2392fbffec4f0`.

Docker image IDs from local BuildKit builds are not treated as reproducible release identities. Acceptance instead binds the exact reviewed arm64 RootFS diff-ID tuple, exact security-relevant image configuration, exact labels, and the runner bytes. The executor copies the runner from a stopped container and hashes it before any process from the image can execute. A regression creates an image with preserved labels but modified runner bytes and proves typed `executor_image_invalid` rejection.

Primary references used for the control design:

- <https://docs.docker.com/reference/cli/docker/container/create/>
- <https://docs.docker.com/reference/cli/docker/container/run/>
- <https://docs.docker.com/engine/containers/resource_constraints/>
- <https://docs.docker.com/engine/security/>
- <https://docs.orbstack.dev/>
- <https://hub.docker.com/_/python>
- <https://github.com/docker-library/python/tree/3362634339580d3232e65a66dd5a36c47ae7ff14/3.12/slim-bookworm>

## Enforced controls

The host verifies the created container before start. Required controls are:

- UID/GID `65532:65532`, `no-new-privileges`, all capabilities dropped, builtin seccomp, no privileged mode;
- read-only root and force-recursive read-only source bind with private propagation;
- private `noexec,nosuid,nodev` scratch and temporary filesystems;
- network none, IPC none, private cgroup namespace, no ports, binds, host sockets, or devices;
- exact child environment allowlist with credential-like and runtime-control names rejected;
- digest-bound snapshot identity including paths, types, bytes, and execution-relevant modes;
- CPU quota and CPU-time limit, memory plus swap ceiling, PID ceiling, file descriptor and file-size limits, scratch quota, wall timeout, output quota, artifact quota, cancellation, and targeted process-tree cleanup;
- regular, single-link, no-follow artifact reads from declared relative scratch paths only;
- bounded and sanitized output with ANSI, control, bidi, and credential-like content removed from previews.

The manifest and every receipt model are strict and reject unknown fields. Unsupported controls, stale snapshots, unsafe paths, unavailable images, invalid protocols, cancellation, timeouts, resource failures, command failures, and artifact failures remain distinct typed outcomes.

## Hostile acceptance profile

`promptectomy executor-doctor --image <digest> --context orbstack --json` runs seven gates:

1. inspected static OCI configuration;
2. non-root, exact environment, read-only filesystem, no socket/device, no DNS/network, no capabilities, and no privilege escalation;
3. output flood termination;
4. memory flood and OOM typing;
5. forked process-tree wall timeout;
6. cancellation and targeted cleanup;
7. cleanup receipts for every probe.

Five consecutive final profiles passed with the same profile digest:

`sha256:15a101b934c2aee32605031d61fab667429143eaa8dfaaf53c3f005d9a563df6`

The final global Docker label query found no owned containers. A separate CPU stress repetition produced 12 of 12 typed `executor_cpu_limit_exceeded` results with no orphan.

The broader real-container matrix also covers PID pressure, file and scratch overflow, artifact overflow, symlink and hardlink artifacts, source symlinks, public permissions, chmod-only staleness, parent-path writes, host-secret canaries, protocol spoofing, non-zero command exits, terminal escapes, and unreviewed contexts.

## Verification receipts

From `engine/`:

- `PROMPTECTOMY_OCI_IMAGE=sha256:23b8908a955aa2b7eb602845e08b50e1821d072ed67e510580d2392fbffec4f0 uv run pytest -q`: 110 passed, 0 failed, 0 skipped. One third-party Starlette/httpx deprecation warning remains.
- `env -u PROMPTECTOMY_OCI_IMAGE uv run pytest -q`: 96 passed, 14 skipped, 0 failed. The optional real-OCI tests skip cleanly when no reviewed image is selected.
- `uv run ruff check .`: passed.
- `uv lock --check`: passed.
- 20 accepted no-op executions after one profile: median 314.5 ms, nearest-rank p95 360 ms, max 437 ms, no owned containers.
- Hostile acceptance profile: 3,174 ms in the recorded benchmark.

Final wheel:

- Path: `/tmp/promptectomy-phase1b-final.yUvk5x/promptectomy-0.1.0-py3-none-any.whl`.
- SHA-256: `8aa2849c75d295e9c56f39c25f00af702b0ec6f59c89917d3ae318e06de4a043`.
- Package inspection confirmed `executor.py`, `executor_contracts.py`, the Dockerfile, runner, and schema assets are present.

Hostile clean installation outside the source tree is deliberately Phase 1C and is not claimed here.

## Review closure

The first adversarial diff review rejected label-only runner trust and found a cancellation-test skip bug. Both were fixed. The first security rerun also exposed transient cleanup receipt reporting and intermittent CPU evidence; cleanup receipts were made authoritative per targeted removal, five repeated acceptance profiles passed, and 12 repeated CPU-limit runs typed correctly.

The corrected revision received fresh diff and security sign-off with no remaining P0/P1/P2. The security reviewer independently reproduced 110 passing tests, five identical acceptance profiles, the runner-byte hash, 12 correctly typed CPU limits, and an empty owned-container inventory.

Zain explicitly approved the already-installed OrbStack runtime for PROMPTECTOMY's local isolated executor on this Mac on 19 July 2026. This closes the Phase 1B manual runtime gate.

No Phase 1B command stages, edits, restores, or decides `engine/promptectomy/generated/route_ticket.py`.
