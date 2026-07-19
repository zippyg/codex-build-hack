use std::hint::black_box;
use std::time::Instant;

use promptectomy_contracts::{SCHEMA_BASE, SCHEMA_VERSION, artifact_id, canonical_json};
use promptectomy_core::{AuthorityManifest, BudgetLedger, CoreStore};
use serde_json::json;
use tempfile::tempdir;

fn authority() -> AuthorityManifest {
    let manifest = json!({
        "reads": ["selected_source_bytes"],
        "writes": ["tool_owned_state"],
        "commands": [],
        "executor": null,
        "network_destinations": [],
        "environment_names": [],
        "model": null,
        "budget": {
            "wall_ms": 60_000,
            "input_tokens": 1_000,
            "output_tokens": 1_000,
            "bytes": 1_000_000,
            "attempts": 100,
        },
        "egress_classes": [],
        "retention": {},
        "cancellation": "supervisor_verified",
        "cleanup": "tool_owned_state_only",
    });
    let value = json!({
        "schema_uri": format!("{SCHEMA_BASE}authority.schema.json"),
        "schema_version": SCHEMA_VERSION,
        "authority_id": "auth_019f0000-0000-7000-8000-000000000101",
        "subject_id": format!("action_snap_sha256_{}", "b".repeat(64)),
        "mode": "inspect",
        "manifest_digest": artifact_id(&canonical_json(&manifest).unwrap()),
        "manifest": manifest,
        "approved_at": "2026-07-19T00:00:00.000000Z",
        "expires_at": "2099-07-19T00:00:00.000000Z",
        "approval_origin": "interactive_local",
        "revoked": false,
    });
    AuthorityManifest::from_contract_json(
        &format!("snap_sha256_{}", "b".repeat(64)),
        &serde_json::to_vec(&value).unwrap(),
    )
    .unwrap()
}

fn micros(started: Instant) -> u64 {
    u64::try_from(started.elapsed().as_micros()).unwrap_or(u64::MAX)
}

fn p95(values: &mut [u64]) -> u64 {
    values.sort_unstable();
    let index = values
        .len()
        .saturating_mul(95)
        .div_ceil(100)
        .saturating_sub(1);
    values[index]
}

#[test]
#[ignore = "run through the Phase 3 acceptance harness"]
fn phase3_local_state_slo_benchmark() {
    let temporary = tempdir().unwrap();
    let root = temporary.path().join("state");
    let mut store = CoreStore::open(&root).unwrap();
    let run = store
        .create_run(
            &authority(),
            BudgetLedger {
                wall_ms: 60_000,
                input_tokens: 1_000,
                output_tokens: 1_000,
                bytes: 1_000_000,
                attempts: 100,
            },
        )
        .unwrap();

    let mut read_us = Vec::with_capacity(2_000);
    for _ in 0..2_000 {
        let started = Instant::now();
        black_box(store.run(&run.run_id).unwrap());
        read_us.push(micros(started));
    }
    let mut report_us = Vec::with_capacity(200);
    for _ in 0..200 {
        let started = Instant::now();
        black_box(store.report_json(&run.run_id).unwrap());
        report_us.push(micros(started));
    }
    drop(store);
    let recovery_started = Instant::now();
    let reopened = CoreStore::open(&root).unwrap();
    black_box(reopened.run(&run.run_id).unwrap());
    let recovery_us = micros(recovery_started);
    let read_p95_us = p95(&mut read_us);
    let report_p95_us = p95(&mut report_us);

    assert!(read_p95_us < 100_000, "local read p95 was {read_p95_us} us");
    assert!(
        report_p95_us < 100_000,
        "small report p95 was {report_p95_us} us"
    );
    assert!(
        recovery_us < 10_000_000,
        "single-run recovery was {recovery_us} us"
    );
    println!(
        "PHASE3_BENCHMARK_JSON={}",
        json!({
            "schema_version": "phase3-benchmark-1",
            "workload": {
                "runs": 1,
                "events_per_run": 1,
                "read_repetitions": read_us.len(),
                "report_repetitions": report_us.len(),
                "cache": "warm",
            },
            "measurements_us": {
                "local_read_p95": read_p95_us,
                "small_report_p95": report_p95_us,
                "restart_and_read": recovery_us,
            },
            "candidate_thresholds_us": {
                "local_read_p95": 100_000,
                "small_report_p95": 100_000,
                "restart_and_read": 10_000_000,
            },
            "passed": true,
        })
    );
}
