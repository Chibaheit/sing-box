#!/usr/bin/env python3
"""Apply the reviewed patch layer to fresh, exact source checkouts."""

import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import tempfile

HERE = Path(__file__).resolve().parent
MANIFEST = json.loads((HERE / "manifest.json").read_text())


def git(root, *args):
    return subprocess.check_output(["git", "-C", str(root), *args], text=True).strip()


def require(condition, message):
    if not condition:
        raise ValueError(message)


def validate_manifest(manifest=MANIFEST):
    app = manifest["app"]
    require(type(app["previous_version_code"]) is int and app["previous_version_code"] >= 734,
            "Previous distributed version code must be at least 734")
    require(type(app["version_code"]) is int
            and app["previous_version_code"] < app["version_code"] <= 2100000000,
            "Version code must exceed every previously distributed custom build")
    require(re.fullmatch(re.escape(app["upstream_version"]) + r"-chibaheit\.[1-9][0-9]*",
                         app["version_name"]) is not None, "Invalid custom version name")
    require(manifest["libbox"]["local_version_tag"] == "v" + app["version_name"],
            "Core/app version mismatch")
    require(app["application_id"] == "io.chibaheit.sfa"
            and app["gradle_task"] == ":app:assembleOtherRelease",
            "Expected custom unsigned release")


def check_pins(core):
    validate_manifest()
    app = core / MANIFEST["app"]["path"]
    for name, root in (("core", core), ("app", app)):
        require(git(root, "rev-parse", "HEAD") == MANIFEST[name]["revision"],
                f"{name}: source revision mismatch")
    entry = git(core, "ls-tree", "HEAD", MANIFEST["app"]["path"]).split()
    require(entry[:3] == ["160000", "commit", MANIFEST["app"]["revision"]],
            "Core/app gitlink mismatch")
    require(not (app / "local.properties").exists(),
            "Refusing local.properties, including sdk.dir-only files; use ANDROID_HOME")
    require(not (app / "service-account-credentials.json").exists(),
            "Refusing Play publishing credentials")
    return app


def patch_paths(name):
    return [HERE / path for path in MANIFEST[name]["patches"]]


def verify(core):
    app = check_pins(core)
    for name, root in (("core", core), ("app", app)):
        patches = patch_paths(name)
        subprocess.run(["git", "-C", str(root), "apply", "--reverse", "--check",
                        *map(str, reversed(patches))], check=True)
        expected_paths = set()
        for patch in patches:
            expected_paths.update(line.split(" b/", 1)[1] for line in patch.read_text().splitlines()
                                  if line.startswith("diff --git "))
        actual_paths = set(git(root, "diff", "--name-only", "--ignore-submodules=all").splitlines())
        require(actual_paths == expected_paths, f"{name}: unexpected tracked source changes")
        require(not git(root, "diff", "--cached", "--name-only"), f"{name}: staged changes")
        # Reverse-check alone accepts unrelated edits inside a patched file. Compare
        # exact resulting blobs in a temporary index without touching the real index.
        with tempfile.TemporaryDirectory(prefix="android-patch-index-") as temporary:
            env = dict(os.environ, GIT_INDEX_FILE=str(Path(temporary) / "index"))
            base = ["git", "-C", str(root)]
            subprocess.run([*base, "read-tree", "HEAD"], env=env, check=True)
            subprocess.run([*base, "apply", "--cached", *map(str, patches)], env=env, check=True)
            result = subprocess.run([*base, "diff", "--exit-code", "--ignore-submodules=all",
                                     "--", *sorted(expected_paths)], env=env,
                                    stdout=subprocess.DEVNULL)
            require(result.returncode == 0, f"{name}: patched file contents differ")
    return app


def apply(core):
    app = check_pins(core)
    for name, root in (("core", core), ("app", app)):
        require(not git(root, "status", "--porcelain", "--untracked-files=all"),
                f"{name}: expected a fresh clean checkout")
        subprocess.run(["git", "-C", str(root), "apply", "--check",
                        *map(str, patch_paths(name))], check=True)
    for name, root in (("core", core), ("app", app)):
        subprocess.run(["git", "-C", str(root), "apply",
                        *map(str, patch_paths(name))], check=True)
    verify(core)


def provenance(core, tooling):
    verify(core)
    require(not git(tooling, "status", "--porcelain", "--", "build/android"),
            "Tooling differs from its recorded revision")
    result = json.loads(json.dumps(MANIFEST))
    result["tooling_revision"] = git(tooling, "rev-parse", "HEAD")
    result["patch_sha256"] = {
        str(path.relative_to(HERE)): hashlib.sha256(path.read_bytes()).hexdigest()
        for name in ("core", "app") for path in patch_paths(name)
    }
    result["core_describe"] = git(core, "describe", "--tags")
    require(result["core_describe"] == MANIFEST["libbox"]["local_version_tag"],
            "Non-deterministic core version tag")
    return result


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("mode", choices=("apply", "verify"))
    parser.add_argument("core", type=Path)
    args = parser.parse_args()
    (apply if args.mode == "apply" else verify)(args.core.resolve())
    print(f"Pinned Android patch layer: {args.mode} OK")
