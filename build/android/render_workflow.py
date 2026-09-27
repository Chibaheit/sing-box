#!/usr/bin/env python3
"""Render a standalone, commit-pinned workflow and patch OUTSIDE the repository."""

import argparse
import difflib
from pathlib import Path
import re

from prepare import HERE, MANIFEST, git, require, validate_manifest


def render(output, installed):
    validate_manifest()
    repository = Path(git(HERE, "rev-parse", "--show-toplevel"))
    output = output.resolve()
    require(not output.is_relative_to(repository), "Workflow delivery must be outside the repository")
    require(not git(repository, "status", "--porcelain", "--", "build/android"),
            "Commit tooling before rendering its immutable workflow")
    revision = git(repository, "rev-parse", "HEAD")
    require(re.fullmatch(r"[0-9a-f]{40}", revision), "Invalid tooling commit")
    template = (HERE / "custom-android.yml.in").read_text()
    require(template.count("@TOOLING_REVISION@") == 1, "Unexpected workflow template")
    text = template.replace("@TOOLING_REVISION@", revision).replace(
        "@VERSION_NAME@", MANIFEST["app"]["version_name"])
    output.mkdir(parents=True, exist_ok=True)
    stem = f"custom-android-release-{revision}"
    yaml_path = output / (stem + ".yml")
    patch_path = output / (stem + ".patch")
    require(not yaml_path.exists() and not patch_path.exists(), "Do not overwrite a delivery")
    yaml_path.write_text(text)
    patch = (
        "diff --git a/.github/workflows/custom-android.yml b/.github/workflows/custom-android.yml\n"
        + "".join(difflib.unified_diff(
            installed.read_text().splitlines(keepends=True), text.splitlines(keepends=True),
            fromfile="a/.github/workflows/custom-android.yml",
            tofile="b/.github/workflows/custom-android.yml"))
    )
    patch_path.write_text(patch)
    print(f"Tooling {revision}; manually install {yaml_path}")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("output_directory", type=Path)
    parser.add_argument("--installed", required=True, type=Path,
                        help="Read-back of the currently installed workflow on testing")
    args = parser.parse_args()
    render(args.output_directory, args.installed)
