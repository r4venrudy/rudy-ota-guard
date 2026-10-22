from __future__ import annotations

import copy
import json
import tempfile
import unittest
from pathlib import Path

from otaguard import core
from tests.helpers import (
    EPOCH,
    KEYS,
    PAYLOAD,
    ROOT_EXPIRY,
    envelope,
    make_key,
    make_release,
    make_root,
    make_state,
    public_b64,
    rotation_envelope,
    write_payload,
)


class GuardCoreTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.path = Path(self.tmp.name) / "payload.bin"
        write_payload(self.path)
        self.root = make_root()
        self.state = make_state()
        self.body = make_release()
        self.signed = envelope(self.body)

    def reject(self, operation, *args, **kwargs) -> core.GuardError:
        with self.assertRaises(core.GuardError) as caught:
            operation(*args, **kwargs)
        self.assertTrue(caught.exception.code)
        return caught.exception

    def test_valid_release_returns_deterministic_verification_report(self) -> None:
        first = core.verify_release(self.signed, self.root, self.state, self.path, EPOCH)
        second = core.verify_release(self.signed, self.root, self.state, self.path, EPOCH)
        self.assertEqual(first, second)
        self.assertEqual(
            first,
            {
                "status": "verified",
                "release_id": "release-2",
                "sequence": 2,
                "rollback_index": 2,
                "payload_sha256": self.body["payload_sha256"],
                "payload_size": len(PAYLOAD),
                "signers": ["root-a"],
                "inactive_slot": "B",
            },
        )

    def test_canonical_signing_bytes_match_independent_golden_vector(self) -> None:
        # The expected UTF-8/ASCII escaping and key order are written literally,
        # independent of the fixture signer and its calls into canonical_bytes.
        self.assertEqual(
            core.canonical_bytes({"z": 1, "a": "é"}),
            b'RUDY-OTA-GUARD-v1\n{"a":"\\u00e9","z":1}',
        )

    def test_signed_body_tampering_and_invalid_signature_fail_closed(self) -> None:
        tampered = copy.deepcopy(self.signed)
        tampered["signed"]["release_id"] = "release-changed"
        self.reject(core.verify_release, tampered, self.root, self.state, self.path, EPOCH)

        bad_signature = copy.deepcopy(self.signed)
        bad_signature["signatures"][0]["sig"] = "A" * 88
        self.reject(core.verify_release, bad_signature, self.root, self.state, self.path, EPOCH)

    def test_wrong_target_or_architecture_is_rejected(self) -> None:
        for body in (
            make_release(target="device-other"),
            make_release(architecture="arm64"),
        ):
            self.reject(core.verify_release, envelope(body), self.root, self.state, self.path, EPOCH)

    def test_sequence_replay_and_rollback_are_rejected(self) -> None:
        self.reject(
            core.verify_release,
            envelope(make_release(sequence=1)),
            self.root,
            self.state,
            self.path,
            EPOCH,
        )
        self.reject(
            core.verify_release,
            envelope(make_release(sequence=2, rollback_index=0)),
            self.root,
            self.state,
            self.path,
            EPOCH,
        )

    def test_expired_release_and_expired_root_are_rejected(self) -> None:
        expired_release = envelope(make_release(expires_at=EPOCH))
        self.reject(core.verify_release, expired_release, self.root, self.state, self.path, EPOCH)

        expired_root = make_root(expires_at=EPOCH)
        self.reject(core.validate_root, expired_root, EPOCH)
        self.reject(core.verify_release, self.signed, expired_root, self.state, self.path, EPOCH)

    def test_revoked_expired_and_not_yet_valid_signing_keys_are_rejected(self) -> None:
        cases = (
            make_key("root-a", revoked=True),
            make_key("root-a", expires_at=EPOCH),
            make_key("root-a", not_before=EPOCH + 1),
        )
        for key in cases:
            self.reject(
                core.verify_release,
                self.signed,
                make_root(keys=[key]),
                self.state,
                self.path,
                EPOCH,
            )

    def test_duplicate_key_ids_and_duplicate_public_keys_are_rejected(self) -> None:
        key_a = make_key("root-a")
        same_public_other_id = make_key("root-b", KEYS["root-a"])
        self.reject(core.validate_root, make_root(keys=[key_a, same_public_other_id]), EPOCH)
        self.reject(core.validate_root, make_root(keys=[key_a, copy.deepcopy(key_a)]), EPOCH)

    def test_root_unknown_role_enum_and_duplicate_roles_are_rejected(self) -> None:
        unknown_role = make_key("root-a", roles=["root", "release", "admin"])
        duplicate_role = make_key("root-a", roles=["root", "root"])
        self.reject(core.validate_root, make_root(keys=[unknown_role]), EPOCH)
        self.reject(core.validate_root, make_root(keys=[duplicate_role]), EPOCH)

    def test_noncanonical_base64_for_signature_and_public_key_is_rejected(self) -> None:
        malformed_signature = copy.deepcopy(self.signed)
        malformed_signature["signatures"][0]["sig"] = malformed_signature["signatures"][0]["sig"].rstrip("=")
        self.reject(
            core.verify_release,
            malformed_signature,
            self.root,
            self.state,
            self.path,
            EPOCH,
        )

        malformed_key = make_key("root-a")
        malformed_key["public_key"] = malformed_key["public_key"].rstrip("=")
        self.reject(core.validate_root, make_root(keys=[malformed_key]), EPOCH)

    def test_threshold_counts_distinct_eligible_public_keys(self) -> None:
        root = make_root(threshold=2, keys=[make_key("root-a"), make_key("root-b")])
        self.reject(core.verify_release, envelope(self.body, ["root-a"]), root, self.state, self.path, EPOCH)
        report = core.verify_release(
            envelope(self.body, ["root-a", "root-b"]), root, self.state, self.path, EPOCH
        )
        self.assertEqual(report["signers"], ["root-a", "root-b"])

        duplicate_record = envelope(self.body, ["root-a", "root-b"])
        duplicate_record["signatures"].append(copy.deepcopy(duplicate_record["signatures"][0]))
        with self.assertRaises(core.GuardError):
            core.verify_release(duplicate_record, root, self.state, self.path, EPOCH)

    def test_untrusted_unknown_signer_record_is_rejected(self) -> None:
        unknown = copy.deepcopy(self.signed)
        unknown["signatures"].append(
            {
                "keyid": "outsider",
                "sig": self.signed["signatures"][0]["sig"],
            }
        )
        self.reject(core.verify_release, unknown, self.root, self.state, self.path, EPOCH)

    def test_payload_hash_and_exact_length_are_checked(self) -> None:
        self.path.write_bytes(PAYLOAD + b"tamper")
        self.reject(core.verify_release, self.signed, self.root, self.state, self.path, EPOCH)

        self.path.write_bytes(PAYLOAD[:-1])
        self.reject(core.verify_release, self.signed, self.root, self.state, self.path, EPOCH)

    def test_release_with_existing_pending_state_is_rejected(self) -> None:
        pending = {
            "sequence": 2,
            "release_id": "release-2",
            "rollback_index": 2,
            "payload_sha256": self.body["payload_sha256"],
            "payload_size": len(PAYLOAD),
            "slot": "B",
            "verified_at": EPOCH,
        }
        state = make_state(pending=pending)
        self.reject(core.verify_release, self.signed, self.root, state, self.path, EPOCH)

    def test_stage_abort_and_health_gated_commit_preserve_a_b_invariants(self) -> None:
        staged = core.stage_release(self.signed, self.root, self.state, self.path, EPOCH)
        self.assertEqual(staged["active_slot"], "A")
        self.assertEqual(staged["last_sequence"], self.state["last_sequence"])
        self.assertEqual(staged["rollback_index"], self.state["rollback_index"])
        self.assertEqual(staged["pending"]["slot"], "B")

        self.reject(core.commit_release, staged, False)
        committed = core.commit_release(staged, True)
        self.assertEqual(committed["active_slot"], "B")
        self.assertEqual(committed["active_release"], "release-2")
        self.assertEqual(committed["last_sequence"], 2)
        self.assertEqual(committed["rollback_index"], 2)
        self.assertIsNone(committed["pending"])

        aborted = core.abort_release(staged)
        self.assertEqual(aborted["active_slot"], "A")
        self.assertEqual(aborted["active_release"], "release-1")
        self.assertEqual(aborted["last_sequence"], 1)
        self.assertEqual(aborted["rollback_index"], 1)
        self.assertIsNone(aborted["pending"])
        self.reject(core.abort_release, self.state)

    def test_root_rotation_requires_old_and_new_thresholds(self) -> None:
        old_root = make_root(threshold=2, keys=[make_key("root-a"), make_key("root-b")])
        new_root = make_root(
            version=2,
            threshold=2,
            keys=[make_key("release-a"), make_key("release-b")],
            expires_at=ROOT_EXPIRY + 1000,
        )
        good = rotation_envelope(
            new_root,
            old_signers=["root-a", "root-b"],
            new_signers=["release-a", "release-b"],
        )
        self.assertEqual(core.rotate_root(good, old_root, EPOCH), new_root)

        insufficient_old = rotation_envelope(
            new_root,
            old_signers=["root-a"],
            new_signers=["release-a", "release-b"],
        )
        self.reject(core.rotate_root, insufficient_old, old_root, EPOCH)

        insufficient_new = rotation_envelope(
            new_root,
            old_signers=["root-a", "root-b"],
            new_signers=["release-a"],
        )
        self.reject(core.rotate_root, insufficient_new, old_root, EPOCH)

    def test_revoked_old_key_counts_only_for_old_root_during_rotation(self) -> None:
        old_root = make_root(
            threshold=2,
            keys=[make_key("root-a"), make_key("root-b")],
        )
        new_root = make_root(
            version=2,
            threshold=2,
            keys=[
                make_key("root-a", revoked=True),
                make_key("root-b"),
                make_key("release-a"),
            ],
            expires_at=ROOT_EXPIRY + 1000,
        )
        transition = rotation_envelope(
            new_root,
            old_signers=["root-a", "root-b"],
            new_signers=["root-a", "root-b", "release-a"],
        )
        self.assertEqual(core.rotate_root(transition, old_root, EPOCH), new_root)

        # root-a is revoked in the new root, so new-root threshold must be met
        # by root-b plus release-a. Removing release-a leaves old threshold met
        # but makes the new threshold fail.
        missing_new_signer = rotation_envelope(
            new_root,
            old_signers=["root-a", "root-b"],
            new_signers=["root-a", "root-b"],
        )
        self.reject(core.rotate_root, missing_new_signer, old_root, EPOCH)

    def test_role_and_expiry_eligibility_are_evaluated_separately_for_each_root(self) -> None:
        old_role_root = make_root(
            threshold=2,
            keys=[
                make_key("root-a", roles=["release"]),
                make_key("root-b"),
                make_key("release-a"),
            ],
        )
        new_role_root = make_root(
            version=2,
            threshold=2,
            keys=[
                make_key("root-a", roles=["root"]),
                make_key("root-b"),
                make_key("release-b"),
            ],
            expires_at=ROOT_EXPIRY + 1000,
        )
        role_transition = rotation_envelope(
            new_role_root,
            old_signers=["root-a", "root-b", "release-a"],
            new_signers=["root-a", "root-b", "release-b"],
        )
        self.assertEqual(core.rotate_root(role_transition, old_role_root, EPOCH), new_role_root)
        self.reject(
            core.rotate_root,
            rotation_envelope(
                new_role_root,
                old_signers=["root-a", "root-b"],
                new_signers=["root-a", "root-b", "release-b"],
            ),
            old_role_root,
            EPOCH,
        )

        old_expiry_root = make_root(
            threshold=2,
            keys=[
                make_key("root-a", expires_at=EPOCH),
                make_key("root-b"),
                make_key("release-a"),
            ],
        )
        new_expiry_root = make_root(
            version=2,
            threshold=2,
            keys=[
                make_key("root-a", expires_at=ROOT_EXPIRY + 1000),
                make_key("root-b"),
                make_key("release-b"),
            ],
            expires_at=ROOT_EXPIRY + 2000,
        )
        expiry_transition = rotation_envelope(
            new_expiry_root,
            old_signers=["root-a", "root-b", "release-a"],
            new_signers=["root-a", "root-b", "release-b"],
        )
        self.assertEqual(core.rotate_root(expiry_transition, old_expiry_root, EPOCH), new_expiry_root)
        self.reject(
            core.rotate_root,
            rotation_envelope(
                new_expiry_root,
                old_signers=["root-a", "root-b"],
                new_signers=["root-a", "root-b", "release-b"],
            ),
            old_expiry_root,
            EPOCH,
        )

    def test_root_rotation_rejects_completely_unknown_signer(self) -> None:
        old_root = make_root()
        new_root = make_root(version=2, keys=[make_key("root-b")])
        unknown = rotation_envelope(new_root)
        unknown["signatures"].append(
            {"keyid": "outsider", "sig": unknown["signatures"][0]["sig"]}
        )
        self.reject(core.rotate_root, unknown, old_root, EPOCH)

    def test_rotation_rejects_old_root_expiry_nonconsecutive_version_and_duplicate_keys(self) -> None:
        old_root = make_root()
        new_root = make_root(version=2, keys=[make_key("root-b")])
        expired_old = make_root(expires_at=EPOCH)
        self.reject(core.rotate_root, rotation_envelope(new_root), expired_old, EPOCH)
        self.reject(core.rotate_root, rotation_envelope(make_root(version=3)), old_root, EPOCH)

        duplicate_pub = make_root(
            version=2,
            keys=[make_key("root-b"), make_key("release-a", KEYS["root-b"])],
        )
        self.reject(core.rotate_root, rotation_envelope(duplicate_pub), old_root, EPOCH)

    def test_strict_json_rejects_duplicate_keys_unknown_fields_and_boolean_numbers(self) -> None:
        path = Path(self.tmp.name) / "duplicate.json"
        path.write_text('{"schema":1,"schema":1}', encoding="utf-8")
        with self.assertRaises(core.GuardError):
            core.load_json(path)

        unknown = make_release()
        unknown["surprise"] = True
        self.reject(core.verify_release, envelope(unknown), self.root, self.state, self.path, EPOCH)

        boolean_integer = make_release()
        boolean_integer["sequence"] = True
        self.reject(
            core.verify_release,
            envelope(boolean_integer),
            self.root,
            self.state,
            self.path,
            EPOCH,
        )

    def test_numeric_fields_reject_booleans_strings_floats_and_out_of_range_values(self) -> None:
        for invalid in (True, "2", 2.0, (1 << 53)):
            root = make_root()
            root["version"] = invalid
            self.reject(core.validate_root, root, EPOCH)

        state = make_state()
        state["last_sequence"] = False
        self.reject(core.validate_state, state)

        state = make_state()
        state["rollback_index"] = -1
        self.reject(core.validate_state, state)

        state = make_state()
        state["pending"] = {
            "sequence": 2,
            "release_id": "release-2",
            "rollback_index": 2,
            "payload_sha256": make_release()["payload_sha256"],
            "payload_size": len(PAYLOAD),
            "slot": "B",
            "verified_at": True,
        }
        self.reject(core.validate_state, state)

        for invalid in (False, "2", 2.0, (1 << 53)):
            self.reject(core.verify_release, self.signed, self.root, self.state, self.path, invalid)

    def test_load_json_requires_bounded_regular_file(self) -> None:
        ordinary = Path(self.tmp.name) / "ordinary.json"
        ordinary.write_text('{"ok":true}', encoding="utf-8")
        self.assertEqual(core.load_json(ordinary), {"ok": True})
        self.reject(core.load_json, Path(self.tmp.name))

        symlink = Path(self.tmp.name) / "ordinary-link.json"
        try:
            symlink.symlink_to(ordinary)
        except (OSError, NotImplementedError):
            self.skipTest("symlink creation is unavailable in this Windows environment")
        self.reject(core.load_json, symlink)

    def test_json_file_size_limit_and_payload_size_limit(self) -> None:
        large_json = Path(self.tmp.name) / "large.json"
        large_json.write_bytes(b" " * (1024 * 1024 + 1))
        self.reject(core.load_json, large_json)

        large_payload = Path(self.tmp.name) / "large-payload.bin"
        with large_payload.open("wb") as handle:
            handle.truncate(256 * 1024 * 1024 + 1)
        self.reject(core.verify_release, self.signed, self.root, self.state, large_payload, EPOCH)


if __name__ == "__main__":
    unittest.main()
