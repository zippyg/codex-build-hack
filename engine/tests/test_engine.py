from __future__ import annotations

from datetime import UTC, datetime
from pathlib import Path

import pytest

from promptectomy.contracts import LedgerEventV1, Usage
from promptectomy.ledger import append, load
from promptectomy.replay import replay
from promptectomy.scoring import score_classifier, score_structured
from promptectomy.splitting import bucket, split
from promptectomy.verify import HoldoutVerifier


def event(event_id: str, request: object, output: object, *, callsite_id: str = "extract_ticket_facts") -> LedgerEventV1:
    return LedgerEventV1(
        event_id=event_id,
        recorded_at=datetime.now(UTC).isoformat(),
        repo_sha="test",
        callsite_id=callsite_id,
        model="gpt-4.1-mini",
        request_input=request,
        response_normalized=output,
        usage=Usage(input_tokens=10, output_tokens=2, total_tokens=12),
        latency_ms=4,
    )


def test_splitting_groups_equal_requests_and_uses_all_three_buckets() -> None:
    events = [event(str(number), {"ticket": number}, {"ticket": number}) for number in range(600)]
    duplicate = event("duplicate", {"ticket": 7}, {"ticket": 7})
    splits = split(events + [duplicate])
    locations = [name for name, values in (("train", splits.train), ("dev", splits.dev), ("holdout", splits.holdout)) if any(item.event_id in {"7", "duplicate"} for item in values)]
    assert locations == [locations[0]]
    assert splits.train and splits.dev and splits.holdout
    assert bucket(events[7]) == bucket(duplicate)


def test_structured_scoring_is_canonical_json_exact() -> None:
    first = event("one", {"x": 1}, {"a": [1, 2], "b": "yes"})
    second = event("two", {"x": 2}, {"a": 2})
    result = score_structured([(first, {"b": "yes", "a": [1, 2]}), (second, {"a": "2"})])
    assert result.agreement == 0.5
    assert result.diffs[0].event_id == "two"


def test_classifier_scoring_reports_agreement_and_macro_f1() -> None:
    cases = [
        (event("one", "a", "billing", callsite_id="route_ticket"), "billing"),
        (event("two", "b", "account", callsite_id="route_ticket"), "billing"),
        (event("three", "c", "shipping", callsite_id="route_ticket"), "shipping"),
    ]
    result = score_classifier(cases)
    assert result.agreement == pytest.approx(2 / 3)
    assert result.macro_f1 == pytest.approx((2 / 3 + 0 + 1) / 3)
    assert [diff.event_id for diff in result.diffs] == ["two"]


def test_replay_and_single_use_holdout_verdict(tmp_path: Path) -> None:
    module = tmp_path / "sample_engine.py"
    module.write_text("def run(input, params):\n    return {'order_id': input['order_id']}\n", encoding="utf-8")
    events = [event("one", {"order_id": "DEMO-1"}, {"order_id": "DEMO-1"}), event("two", {"order_id": "DEMO-2"}, {"order_id": "DEMO-2"})]
    result = replay(module, events, "structured")
    assert result.error == ""
    assert result.passed == 2
    verdict = HoldoutVerifier().verify(module, events, "structured")
    assert verdict.status == "COMPILED"
    verifier = HoldoutVerifier()
    verifier.verify(module, events, "structured")
    with pytest.raises(RuntimeError, match="already run"):
        verifier.verify(module, events, "structured")


def test_ledger_redacts_credentials(tmp_path: Path) -> None:
    ledger = tmp_path / "ledger.jsonl"
    recorded = append(
        ledger,
        event("secret", {"ticket": "safe"}, {"ok": True}).model_copy(
            update={"request_params": {"Authorization": "Bearer should-not-reach-disk", "temperature": 0}}
        ),
    )
    assert recorded.request_params["Authorization"] == "[REDACTED]"
    assert "should-not-reach-disk" not in ledger.read_text(encoding="utf-8")
    assert load(ledger)[0].request_params["Authorization"] == "[REDACTED]"


def test_guard_rejects_impure_and_accepts_pure(tmp_path: Path) -> None:
    from promptectomy.guard import ImpureEngine, assert_pure

    bad = tmp_path / "bad.py"
    bad.write_text("import os\ndef run(input, params):\n    return os.getcwd()\n", encoding="utf-8")
    with pytest.raises(ImpureEngine):
        assert_pure(bad)

    exfil = tmp_path / "exfil.py"
    exfil.write_text("def run(input, params):\n    return open('/etc/passwd').read()\n", encoding="utf-8")
    with pytest.raises(ImpureEngine):
        assert_pure(exfil)

    good = tmp_path / "good.py"
    good.write_text("import re\ndef run(input, params):\n    return re.findall(r'\\\\d+', input)\n", encoding="utf-8")
    assert_pure(good)


def test_real_generated_modules_are_pure_and_loadable() -> None:
    from promptectomy.guard import assert_pure
    from promptectomy.replay import load_engine

    generated = Path(__file__).parents[1] / "promptectomy" / "generated"
    modules = [path for path in generated.glob("*.py")]
    for module in modules:
        assert_pure(module)
        assert callable(load_engine(module))
