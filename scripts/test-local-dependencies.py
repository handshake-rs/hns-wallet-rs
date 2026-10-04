#!/usr/bin/env python3
"""Regressions for workspace-relative paths and repository source escapes."""

import importlib.util
from pathlib import Path
import tempfile
import unittest


spec = importlib.util.spec_from_file_location("guard", Path(__file__).with_name("verify-local-dependencies.py"))
guard = importlib.util.module_from_spec(spec)
spec.loader.exec_module(guard)


class LocalDependencyTests(unittest.TestCase):
    def test_workspace_and_crate_relative_paths_with_exact_package_identity(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "crates/a").mkdir(parents=True)
            (root / "crates/b").mkdir()
            manifest = root / "crates/a/Cargo.toml"
            manifest.write_text('[dependencies]\nalias = { package="b", version="0.4.2", path="../b" }\n')
            guard.verify_manifest(root, manifest, {"b"})
            manifest = root / "Cargo.toml"
            manifest.write_text('[workspace.dependencies]\nb = { path="crates/b" }\n')
            guard.verify_manifest(root, manifest, {"b"})

    def test_external_wrong_crate_and_symlink_paths_are_rejected(self):
        with tempfile.TemporaryDirectory() as tmp:
            parent = Path(tmp)
            root = parent / "repo"
            (root / "crates/a").mkdir(parents=True)
            (root / "crates/b").mkdir()
            outside = parent / "b"
            outside.mkdir()
            (root / "crates/escape").symlink_to(outside, target_is_directory=True)
            manifest = root / "crates/a/Cargo.toml"
            for path in ("../../../b", "../a", "../escape"):
                manifest.write_text(f'[target."cfg(unix)".dev-dependencies]\nb = {{ path="{path}" }}\n')
                with self.assertRaises(ValueError):
                    guard.verify_manifest(root, manifest, {"b"})


if __name__ == "__main__":
    unittest.main()
