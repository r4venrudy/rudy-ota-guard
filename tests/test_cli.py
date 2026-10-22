from __future__ import annotations

import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

from tests.helpers import (
    EPOCH,
    PAYLOAD,
    envelope,
    make_key,
    make_release,
    make_root,
    make_state,
    json_bytes,
    rotation_envelope,
)


PROJECT_ROOT = Path(__file__).resolve().parents[1]


class GuardCliTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.directory = Path(self.tmp.name)
        self.root_path = self._write("root.json", make_root())
        self.state_path = self._write("state.json", make_state())
        self.payload_path = self.directory / "payload.bin"
        self.payload_path.write_bytes(PAYLOAD)
        self.manifest_path = self._write("release.json", envelope(make_release()))
        self.env = os.environ.copy()
        self.env["PYTHONPATH"] = str(PROJECT_ROOT / "src") + os.pathsep + self.env.get("PYTHONPATH", "")

    def _write(self, name: str, value) -> Path:
        path = self.directory / name
        path.write_bytes(json_bytes(value))
        return path

    def run_cli(self, *args: str) -> subprocess.CompletedProcess[str]:
        return subprocess.run(
            [sys.executable, "-m", "otaguard", *map(str, args)],
            cwd=PROJECT_ROOT,
            env=self.env,
            text=True,
            capture_output=True,
            check=False,
            timeout=20,
        )

    def test_verify_success_is_json_and_does_not_mutate_inputs(self) -> None:
        original_state = self.state_path.read_bytes()
        result = self.run_cli(
            "verify",
            "--manifest", str(self.manifest_path),
            "--root", str(self.root_path),
            "--state", str(self.state_path),
            "--payload", str(self.payload_path),
            "--now", str(EPOCH),
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        data = json.loads(result.stdout)
        self.assertEqual(data["status"], "verified")
        self.assertEqual(self.state_path.read_bytes(), original_state)
        self.assertEqual(result.stderr, "")

    def test_invalid_signature_exits_two_with_json_error_and_no_traceback(self) -> None:
        invalid = json.loads(self.manifest_path.read_text(encoding="utf-8"))
        invalid["signatures"][0]["sig"] = "A" * 88
        invalid_path = self._write("invalid.json", invalid)
        result = self.run_cli(
            "verify",
            "--manifest", str(invalid_path),
            "--root", str(self.root_path),
            "--state", str(self.state_path),
            "--payload", str(self.payload_path),
            "--now", str(EPOCH),
        )
        self.assertEqual(result.returncode, 2)
        self.assertNotIn("Traceback", result.stderr + result.stdout)
        error = json.loads(result.stdout)
        self.assertIn("error", error)

    def test_io_failure_exits_three_without_leaking_traceback(self) -> None:
        result = self.run_cli(
            "verify",
            "--manifest", str(self.manifest_path),
            "--root", str(self.root_path),
            "--state", str(self.state_path),
            "--payload", str(self.directory / "missing-payload.bin"),
            "--now", str(EPOCH),
        )
        self.assertEqual(result.returncode, 3)
        self.assertNotIn("Traceback", result.stderr + result.stdout)
        self.assertIn("error", json.loads(result.stdout))

    def test_stage_and_abort_are_stdout_only_and_keep_input_state_unchanged(self) -> None:
        original_state = self.state_path.read_bytes()
        staged = self.run_cli(
            "stage",
            "--manifest", str(self.manifest_path),
            "--root", str(self.root_path),
            "--state", str(self.state_path),
            "--payload", str(self.payload_path),
            "--now", str(EPOCH),
        )
        self.assertEqual(staged.returncode, 0, staged.stderr)
        staged_state = json.loads(staged.stdout)
        if "state" in staged_state:
            staged_state = staged_state["state"]
        self.assertEqual(staged_state["pending"]["release_id"], "release-2")
        self.assertEqual(self.state_path.read_bytes(), original_state)

        staged_path = self._write("staged-state.json", staged_state)
        aborted = self.run_cli("abort", "--state", str(staged_path))
        self.assertEqual(aborted.returncode, 0, aborted.stderr)
        aborted_state = json.loads(aborted.stdout)
        if "state" in aborted_state:
            aborted_state = aborted_state["state"]
        self.assertIsNone(aborted_state["pending"])
        self.assertEqual(aborted_state["active_slot"], "A")
        self.assertEqual(staged_path.read_bytes(), json_bytes(staged_state))

    def test_commit_requires_explicit_health_flag(self) -> None:
        pending = {
            "schema": 1,
            "target": "device-1",
            "architecture": "amd64",
            "active_slot": "A",
            "last_sequence": 1,
            "rollback_index": 1,
            "active_release": "release-1",
            "pending": {
                "sequence": 2,
                "release_id": "release-2",
                "rollback_index": 2,
                "payload_sha256": make_release()["payload_sha256"],
                "payload_size": len(PAYLOAD),
                "slot": "B",
                "verified_at": EPOCH,
            },
        }
        pending_path = self._write("pending.json", pending)
        rejected = self.run_cli("commit", "--state", str(pending_path))
        self.assertEqual(rejected.returncode, 2)

        accepted = self.run_cli("commit", "--state", str(pending_path), "--healthy")
        self.assertEqual(accepted.returncode, 0, accepted.stderr)
        updated = json.loads(accepted.stdout)
        if "state" in updated:
            updated = updated["state"]
        self.assertEqual(updated["active_slot"], "B")
        self.assertIsNone(updated["pending"])
        self.assertEqual(pending_path.read_bytes(), json_bytes(pending))

    def test_rotate_root_command_emits_new_root_without_mutating_old_root_file(self) -> None:
        old_root = make_root()
        old_root_path = self._write("old-root.json", old_root)
        new_root = make_root(version=2, keys=[make_key("root-b")])
        transition_path = self._write("transition.json", rotation_envelope(new_root))
        old_bytes = old_root_path.read_bytes()
        result = self.run_cli(
            "rotate-root",
            "--manifest", str(transition_path),
            "--root", str(old_root_path),
            "--now", str(EPOCH),
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(json.loads(result.stdout), new_root)
        self.assertEqual(old_root_path.read_bytes(), old_bytes)

    def test_verified_release_is_replay_rejected_after_cli_commit(self) -> None:
        staged = self.run_cli(
            "stage",
            "--manifest", str(self.manifest_path),
            "--root", str(self.root_path),
            "--state", str(self.state_path),
            "--payload", str(self.payload_path),
            "--now", str(EPOCH),
        )
        self.assertEqual(staged.returncode, 0, staged.stderr)
        staged_state = json.loads(staged.stdout)
        staged_path = self._write("for-commit.json", staged_state)

        committed = self.run_cli("commit", "--state", str(staged_path), "--healthy")
        self.assertEqual(committed.returncode, 0, committed.stderr)
        committed_path = self._write("committed.json", json.loads(committed.stdout))

        replay = self.run_cli(
            "verify",
            "--manifest", str(self.manifest_path),
            "--root", str(self.root_path),
            "--state", str(committed_path),
            "--payload", str(self.payload_path),
            "--now", str(EPOCH),
        )
        self.assertEqual(replay.returncode, 2)
        self.assertEqual(json.loads(replay.stdout)["error"]["code"], "replay")


if __name__ == "__main__":
    unittest.main()
