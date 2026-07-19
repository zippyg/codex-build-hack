# Active Plan

## Goal

Deliver PROMPTECTOMY stable v1 from the accepted Phase 0 design through verified public open-source release. The authoritative master plan is `.agent/state/FORWARD_PLAN_2026-07-19.md`.

## Immutable boundary

- Implementation branch: `zc/product-v1`.
- Planning baseline commit: `cbbb89d5c5dc2e1e563b42dca15a4b6266201d6c`.
- `engine/promptectomy/generated/route_ticket.py` is protected user/live-demo work.
- Required SHA-256: `a4fcdab0f1baef70072620e1409d68e732c5a4549d3f36388a7213237dab961c`.
- Never stage, restore, overwrite, format, regenerate, commit, move, delete, or decide that file without Zain.

## Phases

- [x] Phase 0: accepted product, architecture, security, contract, UX, test, and governance decisions.
- [x] Phase 0T: create and push the implementation branch, commit planning only, prove inherited baseline, establish this ledger.
- [x] Phase 1A: honest non-mutating Python commands and unverified patch artifacts.
- [ ] Phase 1B: accepted isolated executor.
- [ ] Phase 1C: hostile clean-install acceptance.
- [ ] Phase 2: Contract v2, durable state/artifacts, local API, and reports.
- [ ] Phase 3: Rust control plane and canonical CLI.
- [ ] Phase 4: safe acquisition, stable adapters, capture, evidence, and privacy.
- [ ] Phase 5: isolated Codex synthesis and rigorous evaluation.
- [ ] Phase 6: Ratatui TUI.
- [ ] Phase 7: Tauri GUI, accessibility, and Claude-led visual polish.
- [ ] Phase 8: bounded agent office, safe Apply, and local integrations.
- [ ] Phase 9: release-candidate hardening and supply chain.
- [ ] Phase 10: human release gates, public release, and anonymous verification.

## Phase 0T receipt

- Branch `zc/product-v1` created from `8bab7bba966030e9c84af86352dc4a70e8462d4f`.
- Planning committed as `cbbb89d` and pushed to `origin/zc/product-v1`.
- Protected file excluded from the commit and still matches its required digest.
- Engine baseline: `uv sync --frozen`, 30 pytest tests passed with one third-party Starlette deprecation warning.
- UI baseline: frozen Bun install, TypeScript, and Next.js production build passed. The first Playwright attempt was contaminated by a pre-existing dev server/build collision; after terminating that verified repo-local dev server, the full rerun passed 10/10.
- Test-generated screenshot drift was restored because it was created by this baseline run. The protected user diff remains the only working-tree change.

## Phase 1A receipt

- The Python conformance oracle implements typed `doctor`, `inspect`, `audit`, `draft`, `status`, and `report` behavior without target mutation or repository/generated-code execution.
- Draft uses only the direct no-tool Responses boundary and can create only private `unverified` candidates under an exact egress manifest.
- The hostile synthetic matrix, Git-state receipts, privacy canaries, connector/schema limits, legacy-path gates, and wheel packaging checks pass: 73 pytest tests, 0 failures, 0 skipped.
- A fresh Python 3.12 wheel install passed help, doctor, inspect, status, report, and packaged-schema checks. The final artifact receipt is in `docs/architecture/phase-1a-evidence.md`.
- Architecture, diff, and security findings were reproduced and closed. No Phase 1B executor work started.

## Execution rule

Complete and evidence one phase, update this ledger/status/log, review and commit/push it, then continue. Do not mark the master goal complete at an intermediate phase.
