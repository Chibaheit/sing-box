#!/usr/bin/env python3
"""Render a standalone, commit-pinned workflow and patch OUTSIDE the repository."""

import argparse
from pathlib import Path
import re

from prepare import HERE, git, require


def render(output):
    repository = Path(git(HERE, "rev-parse", "--show-toplevel"))
    output = output.resolve()
    require(not output.is_relative_to(repository), "Workflow delivery must be outside the repository")
    require(not git(repository, "status", "--porcelain", "--", "build/android"),
            "Commit tooling before rendering its immutable workflow")
    revision = git(repository, "rev-parse", "HEAD")
    require(re.fullmatch(r"[0-9a-f]{40}", revision), "Invalid tooling commit")
    template = (HERE / "custom-android.yml.in").read_text()
    require(template.count("@TOOLING_REVISION@") == 1, "Unexpected workflow template")
    text = template.replace("@TOOLING_REVISION@", revision)
    output.mkdir(parents=True, exist_ok=True)
    (output / "custom-android.yml").write_text(text)
    lines = text.splitlines()
    patch = (
        "diff --git a/.github/workflows/custom-android.yml b/.github/workflows/custom-android.yml\n"
        "new file mode 100644\n"
        "--- /dev/null\n"
        "+++ b/.github/workflows/custom-android.yml\n"
        f"@@ -0,0 +1,{len(lines)} @@\n"
        + "".join("+" + line + "\n" for line in lines)
    )
    (output / "custom-android.patch").write_text(patch)
    print(f"Tooling {revision}; manually install {output / 'custom-android.yml'}")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("output_directory", type=Path)
    render(parser.parse_args().output_directory)
