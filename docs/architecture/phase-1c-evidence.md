# Phase 1C hostile clean-install evidence

Status: accepted
Date: 19 July 2026
Branch: `zc/product-v1`

## Result

The Python reference and accepted OCI boundary pass outside the source checkout from a locked, reproducible wheel. The release artifact contains only the Phase 1A/1B safe control surface and required schemas/executor assets. Generated replacements and obsolete hackathon execution modules are absent.

Artifact:

- filename: `promptectomy-0.1.0-py3-none-any.whl`;
- SHA-256: `5465a0b24472ba3a9ea890a92277457fa58b2744255974eb125bb8a78473236c`;
- size: 46,702 bytes;
- two clean builds: byte-identical;
- full machine-readable inventory: [phase-1c-receipt.json](phase-1c-receipt.json).

## Reproducible acceptance command

```bash
cd engine
uv run python scripts/phase1c_acceptance.py \
  --image sha256:23b8908a955aa2b7eb602845e08b50e1821d072ed67e510580d2392fbffec4f0 \
  --receipt ../docs/architecture/phase-1c-receipt.json
```

The harness:

1. copies the candidate source into an owner-only disposable directory without reading or copying generated code;
2. exports every runtime, test, and build dependency from `uv.lock` with hashes;
3. builds once with locked build constraints and once offline from the isolated cache;
4. requires byte-identical wheels;
5. validates normalized archive paths, entry count and size limits, required assets, forbidden modules, and every SHA-256 and size in `RECORD`;
6. installs into one clean online environment and a second clean offline environment;
7. runs the hostile installed corpus with isolated HOME, TMP, XDG, state, and cache roots, no user site, and Python sockets disabled;
8. gives Docker an isolated context containing only the local OrbStack endpoint;
9. inventories exact installed versions and dependency license metadata;
10. proves zero owned containers and child processes, uninstalls the package from both environments, and removes the disposable root.

## Acceptance results

| Gate | Evidence |
| --- | --- |
| Installed hostile corpus | 83 passed in 18.97 seconds |
| Complete source matrix with accepted OCI image | 116 passed in 20.28 seconds |
| Source matrix without configured OCI image | 102 passed, 14 optional OCI tests skipped |
| Wheel reproducibility | two byte-identical builds |
| Installed location | isolated `site-packages`, outside checkout |
| Offline install | passed from the locked isolated cache |
| Python network during tests | disabled by `pytest-socket` |
| Target/source status | unchanged |
| Owned executor containers after tests | zero |
| Child processes after tests | zero |
| Uninstall | package, metadata, and entry point absent in both environments |
| Generated code in wheel | none |
| Legacy in-process execution/mutation modules in wheel | none |

The installed corpus covers dirty and linked Git worktrees, staged and unstaged changes, untracked files, nested repository metadata, symlinks, malformed and oversized inputs, Python and TypeScript callsites, unsupported providers/languages/operations, zero findings, privacy and credential canaries, policy violations, connector cancellation/failure, terminal control content, executor cancellation, resource exhaustion, network and privilege denial, and cleanup.

Remote Git and archive acquisition remain typed unsupported inputs at this phase. Their safe implementation is a later acquisition-boundary phase, not a fallback in the Python artifact.

## Package boundary

The wheel contains:

- CLI;
- safe reference analysis and contracts;
- trusted Responses connector;
- accepted OCI executor and contracts;
- packaged JSON schemas;
- reviewed executor image assets.

It excludes generated replacements and the old contracts, event bridge, AST guard, in-process replay, shim, scoring, synthesis, server, verification, and Git-worktree modules. Those remain source-history inputs for migration and are not importable from the installed product artifact.

## Supply-chain review

- Hatchling is pinned to `1.31.0` in both the PEP 517 build requirement and `uv.lock`.
- The receipt records 39 installed distributions and their declared license fields.
- Every third-party distribution has license metadata.
- PROMPTECTOMY intentionally has no license metadata until the explicit human license gate is approved.
- `pip-audit` reported no known vulnerabilities for the exported locked dependency set.
- Gitleaks scanned all 22 commits and reported no leaks after two exact, path-bound false-positive allowlists: a natural-language token-limit test description and the public CPython image GPG fingerprint.

## Fresh review

Semgrep ran 147 Python rules against the acceptance harness and tests with zero findings. Manual diff and security review checked command construction, environment isolation, path traversal, archive bounds, duplicate entries and RECORD rows, generated and legacy module exclusion, subprocess timeouts, credential inheritance, source-state comparison, executor cleanup, and uninstall behavior.

No P0, P1, critical, high, or medium finding remains in the Phase 1C change. The known Starlette TestClient deprecation warning is third-party migration debt and does not affect the accepted authority or artifact boundary.

## Rollback

Revert the Phase 1C commit. The prior Phase 1A/1B source remains intact, but its wheel must not be released because it packages generated and obsolete execution modules.
