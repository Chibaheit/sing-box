#!/usr/bin/env python3
"""Fail-closed release signing. Never print private inputs or signer diagnostics."""

import argparse
import base64
import binascii
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import sys

from prepare import HERE, MANIFEST, require, validate_manifest


def expected_certificate():
    value = os.environ.get("CERT_SHA256", "")
    require(re.fullmatch(r"[0-9a-fA-F]{64}", value) is not None,
            "CERT_SHA256 must be the protected expected certificate SHA-256 (64 hex digits)")
    return value.lower()


def preflight():
    validate_manifest()
    for name in MANIFEST["signing"]["required_inputs"]:
        value = os.environ.get(name, "")
        require(bool(value), f"Missing signing input: {name}")
        require(all(c.isprintable() for c in value), f"Invalid signing input: {name}")
    expected_certificate()
    require(re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,127}", os.environ["KEY_ALIAS"]) is not None,
            "KEY_ALIAS must be a simple non-option alias")
    try:
        key = base64.b64decode(os.environ["KEYSTORE_B64"], validate=True)
    except (ValueError, binascii.Error):
        raise ValueError("KEYSTORE_B64 must be strict single-line base64") from None
    require(0 < len(key) <= 1024 * 1024, "Invalid decoded keystore size")
    return key


def sdk_tools():
    require(bool(os.environ.get("ANDROID_HOME")), "ANDROID_HOME is required")
    sdk = Path(os.environ["ANDROID_HOME"]) / "build-tools" / MANIFEST["toolchain"]["build_tools"]
    jar = sdk / "lib/apksigner.jar"
    require(hashlib.sha256(jar.read_bytes()).hexdigest()
            == MANIFEST["signing"]["apksigner_jar_sha256"], "Unreviewed apksigner JAR")
    return sdk


def unsigned_apk(core):
    directory = core / MANIFEST["app"]["path"] / MANIFEST["app"]["unsigned_apk_directory"]
    metadata = json.loads((directory / "output-metadata.json").read_text())
    require(metadata["artifactType"]["type"] == "APK"
            and metadata["variantName"] == "otherRelease"
            and metadata["applicationId"] == MANIFEST["app"]["application_id"],
            "Unexpected AGP release output metadata")
    elements = metadata["elements"]
    require(len(elements) == 1, "Expected exactly one AGP release output")
    entry = elements[0]
    require(entry["filters"] == [{"filterType": "ABI", "value": MANIFEST["app"]["abi"]}]
            and entry["versionCode"] == MANIFEST["app"]["version_code"]
            and entry["versionName"] == MANIFEST["app"]["version_name"],
            "AGP output identity/version/ABI mismatch")
    filename = entry["outputFile"]
    require(isinstance(filename, str) and Path(filename).name == filename
            and filename.endswith("-unsigned.apk"), "Expected local unsigned APK filename")
    apk = directory / filename
    require(not apk.is_symlink() and apk.is_file()
            and list(directory.glob("*.apk")) == [apk], "Unexpected unsigned APK inventory")
    return apk


def temporary_directory():
    require(bool(os.environ.get("RUNNER_TEMP")), "RUNNER_TEMP is required outside source")
    root = Path(os.environ["RUNNER_TEMP"]).resolve()
    require(root.is_dir() and root != Path("/"), "Invalid RUNNER_TEMP")
    excluded = [HERE.parents[1]]
    if os.environ.get("GITHUB_WORKSPACE"):
        excluded.append(Path(os.environ["GITHUB_WORKSPACE"]).resolve())
    require(not any(root.is_relative_to(path) for path in excluded),
            "Signing temporary directory must be outside source/workspace")
    temporary = root / "chibaheit-release-signing"
    require(not temporary.is_symlink(), "Refusing symlink signing directory")
    return temporary


def cleanup():
    temporary = temporary_directory()
    if temporary.exists():
        (temporary / "owner.jks").unlink(missing_ok=True)
        temporary.rmdir()


def sign_with_keystore(apk, signed, keystore, sdk):
    result = subprocess.run([
        str(sdk / "apksigner"), "sign", "--ks", str(keystore),
        "--ks-key-alias", os.environ["KEY_ALIAS"],
        "--ks-pass", "env:KEYSTORE_PASSWORD", "--key-pass", "env:KEY_PASSWORD",
        "--v1-signing-enabled", "true", "--v2-signing-enabled", "true",
        "--v3-signing-enabled", "true", "--v4-signing-enabled", "false",
        "--out", str(signed), str(apk),
    ], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    require(result.returncode == 0,
            f"Release signing failed (exit {result.returncode}); private diagnostics suppressed")


def sign(core, output):
    from collect import check_apk, release_certificate

    key = preflight()
    temporary = temporary_directory()
    require(not temporary.exists(), "Signing directory already exists; clean it before retrying")
    require(not output.exists(), "Signed output directory must be fresh")
    apk = unsigned_apk(core)
    require(not output.is_relative_to(core), "Signed outputs must be outside the source checkout")
    sdk = sdk_tools()
    check_apk(apk, subprocess.check_output(
        [str(sdk / "aapt"), "dump", "badging", str(apk)], text=True))
    subprocess.run([str(sdk / "zipalign"), "-c", "-P", "16", "4", str(apk)], check=True)
    unsigned = subprocess.run([str(sdk / "apksigner"), "verify", str(apk)],
                              stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    require(unsigned.returncode != 0, "Refusing already signed build output")
    temporary.mkdir(mode=0o700)
    keystore = temporary / "owner.jks"
    with keystore.open("xb") as stream:
        os.chmod(keystore, 0o600)
        stream.write(key)
    output.mkdir(parents=True)
    signed = output / "release.apk"
    sign_with_keystore(apk, signed, keystore, sdk)
    report = subprocess.check_output(
        [str(sdk / "apksigner"), "verify", "--verbose", "--print-certs", str(signed)], text=True)
    release_certificate(report)
    subprocess.run([str(sdk / "zipalign"), "-c", "-P", "16", "4", str(signed)], check=True)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("mode", choices=("preflight", "sign", "cleanup"))
    parser.add_argument("core", nargs="?", type=Path)
    parser.add_argument("output", nargs="?", type=Path)
    args = parser.parse_args()
    try:
        if args.mode == "preflight":
            preflight()
        elif args.mode == "cleanup":
            cleanup()
        else:
            require(args.core is not None and args.output is not None, "Core and output required")
            sign(args.core.resolve(), args.output.resolve())
    except ValueError as error:
        print(str(error), file=sys.stderr)
        sys.exit(1)
