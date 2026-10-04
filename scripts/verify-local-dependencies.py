#!/usr/bin/env python3
"""Allow local dependencies only on this repository's public wallet crates."""

from pathlib import Path
import subprocess
import tomllib


ROOT = Path(__file__).resolve().parents[1]


def verify_manifest(root: Path, manifest: Path, public: set[str]) -> None:
    root = root.resolve()
    data = tomllib.loads(manifest.read_text())
    owners = [data, data.get("workspace", {}), *data.get("target", {}).values()]
    sections = [owner.get(section, {}) for owner in owners
                for section in ("dependencies", "dev-dependencies", "build-dependencies")]
    sections.extend(data.get("patch", {}).values())
    sections.append(data.get("replace", {}))
    for dependencies in sections:
        for alias, spec in dependencies.items():
            if not isinstance(spec, dict) or "path" not in spec:
                continue
            package = spec.get("package", alias)
            if package not in public:
                raise ValueError(f"{manifest}: unreviewed local dependency {package}")
            target = (manifest.parent / spec["path"]).resolve(strict=True)
            expected = (root / "crates" / package).resolve(strict=True)
            if target != expected or not target.is_relative_to(root):
                raise ValueError(f"{manifest}: local dependency {package} leaves its wallet crate")


def main() -> None:
    public = set((ROOT / "release/public-crates.txt").read_text().split())
    tracked = subprocess.check_output(["git", "ls-files", "-z"], cwd=ROOT)
    for name in tracked.split(b"\0"):
        if name and Path(name.decode()).name == "Cargo.toml":
            verify_manifest(ROOT, ROOT / name.decode(), public)
    print("Local dependencies resolve only to reviewed wallet crates inside this repository.")


if __name__ == "__main__":
    try:
        main()
    except (ValueError, OSError, subprocess.CalledProcessError) as error:
        raise SystemExit(f"Local dependency verification failed: {error}")
