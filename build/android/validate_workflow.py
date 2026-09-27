#!/usr/bin/env python3
"""Check the delivered workflow's pins and narrow security/artifact contract."""

import argparse
from pathlib import Path
import re

import yaml

from prepare import HERE, MANIFEST, git, require


def validate(path):
    text = path.read_text()
    # BaseLoader preserves the YAML 1.2 Actions key "on" instead of treating
    # it as a YAML 1.1 boolean. actionlint separately checks the full schema.
    workflow = yaml.load(text, Loader=yaml.BaseLoader)
    require(workflow["on"] == {"workflow_dispatch": ""}, "Manual dispatch only, with no inputs")
    require(workflow["permissions"] == {"contents": "read"}, "Read-only repository permission")
    require(list(workflow["jobs"]) == ["build"], "Unexpected job")
    job = workflow["jobs"]["build"]
    require(job["runs-on"] == "ubuntu-24.04", "Unexpected runner")
    require("permissions" not in job, "Unexpected job permissions")
    require(job["environment"] == "android-release", "Protected release environment required")
    require(job["env"] == {"PYTHONDONTWRITEBYTECODE": "1"}, "No job-wide signing inputs")
    steps = job["steps"]
    uses = [step["uses"] for step in steps if "uses" in step]
    expected = [
        "actions/checkout@11d5960a326750d5838078e36cf38b85af677262",
        "actions/checkout@11d5960a326750d5838078e36cf38b85af677262",
        "actions/setup-go@40f1582b2485089dde7abd97c1529aa768e1baff",
        "actions/setup-java@cf277c60eb25467037889841efdb72551f06f6c3",
        "android-actions/setup-android@9fc6c4e9069bf8d3d10b2204b1fb8f6ef7065407",
        "actions/upload-artifact@ea165f8d65b6e75b540449e92b4886f43607fa02",
    ]
    require(uses == expected, "Unreviewed action or changed SHA")
    checkouts = [step["with"] for step in steps if step.get("uses", "").startswith("actions/checkout@")]
    require(checkouts[0]["ref"] == git(HERE, "rev-parse", "HEAD"), "Tooling pin mismatch")
    require(checkouts[1]["ref"] == MANIFEST["core"]["revision"], "Core pin mismatch")
    for checkout in checkouts:
        require(checkout["repository"] == "Chibaheit/sing-box", "Unexpected repository")
        require(checkout["persist-credentials"] == "false", "Credentials must not persist")
        require(re.fullmatch("[0-9a-f]{40}", checkout["ref"]), "Non-immutable source reference")
    require(checkouts[1]["fetch-depth"] == "1" and checkouts[1]["fetch-tags"] == "false",
            "Core must be shallow and tag-free for its local version tag")
    action_options = {step["uses"].split("@")[0]: step.get("with", {}) for step in steps if "uses" in step}
    require(action_options["actions/setup-go"]["go-version"] == MANIFEST["toolchain"]["go"],
            "Go version mismatch")
    require(action_options["actions/setup-go"]["cache"] == "false", "No Actions cache")
    require(action_options["actions/setup-java"]["java-version"] == MANIFEST["toolchain"]["java"],
            "JDK version mismatch")
    sdk = action_options["android-actions/setup-android"]
    require(sdk["cmdline-tools-version"] == MANIFEST["toolchain"]["cmdline_tools"],
            "SDK command-line tools mismatch")
    require(sdk["accept-android-sdk-licenses"] == "true", "License acceptance step required")
    upload = action_options["actions/upload-artifact"]
    require(set(upload["path"].splitlines()) == {
        "artifacts/*-RELEASE.apk", "artifacts/SHA256SUMS", "artifacts/certificate-sha256.txt",
        "artifacts/source-manifest.json", "artifacts/source-patch-bundle.tar.gz",
        "artifacts/core-source.tar.gz", "artifacts/app-source.tar.gz",
    }, "Artifact allowlist changed")
    require(upload["if-no-files-found"] == "error", "Missing artifacts must fail")
    require(upload["include-hidden-files"] == "false", "Do not upload hidden files")
    require(upload["name"] == f"Chibaheit-SFA-{MANIFEST['app']['version_name']}-arm64-v8a-RELEASE",
            "Artifact version mismatch")
    for forbidden in ("pull_request_target", "contents: write", "gh release",
                      "release.keystore", "update_android_version", "@latest"):
        require(forbidden not in text, f"Forbidden workflow content: {forbidden}")
    # This validator accepts only the reviewed template, not arbitrary shell with
    # a few safe-looking keywords. Secrets cannot be added to another step/scope.
    expected_text = (HERE / "custom-android.yml.in").read_text().replace(
        "@TOOLING_REVISION@", git(HERE, "rev-parse", "HEAD")).replace(
        "@VERSION_NAME@", MANIFEST["app"]["version_name"])
    require(text == expected_text, "Workflow differs from reviewed release template")
    for package in ("platforms;android-37.1", "platforms;android-36", "build-tools;37.0.0",
                    "ndk;28.0.13004108"):
        require(package in text, f"Missing SDK package: {package}")
    print("Workflow YAML parse, immutable pins, dispatch-only permission and artifact contract: OK")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("workflow", type=Path)
    validate(parser.parse_args().workflow)
