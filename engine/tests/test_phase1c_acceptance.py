from __future__ import annotations

import base64
import csv
import hashlib
import io
import zipfile
from pathlib import Path

import pytest

from scripts.phase1c_acceptance import REQUIRED_WHEEL_FILES, verify_wheel


def _wheel(
    path: Path, additions: dict[str, bytes], *, duplicate_record: bool = False
) -> Path:
    members = {name: b"{}" for name in REQUIRED_WHEEL_FILES}
    members["promptectomy/__init__.py"] = b""
    members["promptectomy-0.1.0.dist-info/METADATA"] = (
        b"Name: promptectomy\nVersion: 0.1.0\n"
    )
    members.update(additions)
    record_name = "promptectomy-0.1.0.dist-info/RECORD"
    rows = []
    for name, content in members.items():
        digest = (
            base64.urlsafe_b64encode(hashlib.sha256(content).digest())
            .rstrip(b"=")
            .decode()
        )
        rows.append((name, f"sha256={digest}", str(len(content))))
    rows.append((record_name, "", ""))
    if duplicate_record:
        rows.append(("promptectomy/__init__.py", "sha256=invalid", "0"))
    output = io.StringIO()
    csv.writer(output, lineterminator="\n").writerows(rows)
    members[record_name] = output.getvalue().encode()
    with zipfile.ZipFile(path, "w") as archive:
        for name, content in members.items():
            archive.writestr(name, content)
    return path


def test_wheel_verifier_accepts_a_bounded_complete_inventory(tmp_path: Path) -> None:
    wheel = _wheel(tmp_path / "valid.whl", {})

    assert set(verify_wheel(wheel)) >= REQUIRED_WHEEL_FILES


@pytest.mark.parametrize(
    "name",
    [
        "../escape.py",
        "C:/escape.py",
        "promptectomy/generated/replacement.py",
        "promptectomy/replay.py",
    ],
)
def test_wheel_verifier_rejects_unsafe_or_legacy_members(
    tmp_path: Path, name: str
) -> None:
    wheel = _wheel(tmp_path / "unsafe.whl", {name: b"pass\n"})

    with pytest.raises(RuntimeError):
        verify_wheel(wheel)


def test_wheel_verifier_rejects_duplicate_record_rows(tmp_path: Path) -> None:
    wheel = _wheel(tmp_path / "duplicate-record.whl", {}, duplicate_record=True)

    with pytest.raises(RuntimeError, match="duplicate"):
        verify_wheel(wheel)
