#!/usr/bin/env python3
"""Refresh the offline Rust UI from a signature-verified Core release directory."""

import argparse
import hashlib
import json
from pathlib import Path, PurePosixPath
import shutil
import subprocess
import tarfile
import tempfile

ROOT = Path(__file__).resolve().parents[1]


def refresh(release):
    release = release.resolve()
    for name in ("release-manifest", "core-manifest"):
        subprocess.run(
            [
                "openssl",
                "pkeyutl",
                "-verify",
                "-rawin",
                "-pubin",
                "-inkey",
                str(ROOT / "vendor/core-source/assets/release-public.pem"),
                "-in",
                str(release / (name + ".json")),
                "-sigfile",
                str(release / (name + ".sig")),
            ],
            check=True,
        )
    manifest = json.loads((release / "core-manifest.json").read_text())
    version = manifest["version"]
    assert version.startswith("5.0.") and manifest["ui_api"] == 1
    packages = json.loads((release / "release-manifest.json").read_text())["packages"]
    with tempfile.TemporaryDirectory(dir=ROOT, prefix=".core-vendor-") as temp:
        temp = Path(temp)
        for kind in ("rust", "source"):
            name = f"kagnode-core-{version}-{kind}.tar.xz"
            item = next(p for p in packages if p["name"] == name)
            data = (release / name).read_bytes()
            assert (
                len(data) == item["size"]
                and hashlib.sha256(data).hexdigest() == item["sha256"]
            )
            dest = temp / kind
            dest.mkdir()
            with tarfile.open(release / name) as archive:
                for member in archive.getmembers():
                    path = PurePosixPath(member.name)
                    assert (
                        member.isfile()
                        and not path.is_absolute()
                        and ".." not in path.parts
                        and len(path.parts) > 1
                    )
                    output = dest.joinpath(*path.parts[1:])
                    output.parent.mkdir(parents=True, exist_ok=True)
                    output.write_bytes(archive.extractfile(member).read())
            if kind == "rust":
                fallback = json.loads((dest / "fallback/bundle.json").read_text())
                assert (
                    fallback["version"] == version
                    and fallback["source_commit"] == manifest["source_commit"]
                )
        import base64

        for name, item in manifest["files"].items():
            data = base64.b64decode(fallback["files"][name]["data"])
            assert (
                len(data) == item["size"]
                and hashlib.sha256(data).hexdigest() == item["sha256"]
            )
        shutil.copytree(temp / "source", temp / "rust/corresponding-source")
        for suffix in ("json", "sig"):
            shutil.copyfile(
                release / ("core-manifest." + suffix),
                temp / "rust" / ("core-manifest." + suffix),
            )
        shutil.rmtree(ROOT / "vendor/core-rust")
        shutil.copytree(temp / "rust", ROOT / "vendor/core-rust")
        shutil.copyfile(
            temp / "rust/fallback/bundle.json", ROOT / "assets/core-bundle.json"
        )
    lock = json.loads((ROOT / "core.lock.json").read_text())
    lock.update(
        baseline=version,
        adapter=version,
        source_commit=manifest["source_commit"],
        fallback_manifest_sha256=hashlib.sha256(
            (ROOT / "assets/core-bundle.json").read_bytes()
        ).hexdigest(),
        signed_ui_manifest_sha256=hashlib.sha256(
            (release / "core-manifest.json").read_bytes()
        ).hexdigest(),
    )
    (ROOT / "core.lock.json").write_text(json.dumps(lock, indent=2) + "\n")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("release", type=Path)
    refresh(parser.parse_args().release)
