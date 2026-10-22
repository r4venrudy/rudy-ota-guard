"""Prove the documented public examples regenerate byte-for-byte on every OS."""
from contextlib import redirect_stdout
import io
from pathlib import Path
import runpy
import tempfile
import unittest

from otaguard.core import load_json, rotate_root, verify_release


class ExampleBundleTests(unittest.TestCase):
    def test_public_example_bundle_regenerates_exactly_and_verifies(self):
        project = Path(__file__).resolve().parents[1]
        with tempfile.TemporaryDirectory() as directory:
            namespace = runpy.run_path(str(project / "scripts" / "make_demo.py"))
            namespace["main"].__globals__["ROOT"] = Path(directory)
            with redirect_stdout(io.StringIO()):
                namespace["main"]()
            generated = Path(directory) / "examples"
            expected_names = {"root.json", "state.json", "manifest.json", "payload.bin", "rotation.json"}
            self.assertEqual({p.name for p in generated.iterdir()}, expected_names)
            for name in expected_names:
                self.assertEqual((generated / name).read_bytes(), (project / "examples" / name).read_bytes(), name)
            root = load_json(generated / "root.json")
            result = verify_release(load_json(generated / "manifest.json"), root,
                                    load_json(generated / "state.json"), generated / "payload.bin", 1900000000)
            self.assertEqual(result["status"], "verified")
            self.assertEqual(result["signers"], ["release-a", "release-b"])
            self.assertEqual(rotate_root(load_json(generated / "rotation.json"), root, 1900000000)["version"], 2)


if __name__ == "__main__":
    unittest.main()
