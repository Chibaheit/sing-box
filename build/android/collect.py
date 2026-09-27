#!/usr/bin/env python3
"""Verify the real APK before producing an allowlisted artifact directory."""

import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import tarfile
import zipfile

from prepare import HERE, MANIFEST, git, provenance, require


def check_apk(apk, badging):
    app = MANIFEST["app"]
    package = re.search(r"^package: name='([^']+)' versionCode='([^']+)' versionName='([^']+)'",
                        badging, re.MULTILINE)
    require(package is not None, "APK package metadata missing")
    require(package.groups() == (app["application_id"], str(app["version_code"]), app["version_name"]),
            "APK identity/version mismatch")
    require(f"application-label:'{app['label']}'" in badging, "APK label mismatch")
    require("application-debuggable" in badging, "Expected DEBUG trial, not release")
    native = re.search(r"^native-code: (.+)$", badging, re.MULTILINE)
    require(native is not None and re.findall(r"'([^']+)'", native[1]) == [app["abi"]],
            "APK badging must advertise only arm64-v8a")
    with zipfile.ZipFile(apk) as archive:
        libraries = [n for n in archive.namelist() if n.startswith("lib/") and n.endswith(".so")]
        require(bool(libraries), "APK has no native libraries")
        require({n.split("/")[1] for n in libraries} == {app["abi"]},
                "APK contains an unintended ABI")
        require(f"lib/{app['abi']}/libbox.so" in libraries, "APK is missing libbox.so")
        for name in libraries:
            with archive.open(name) as stream:
                header = stream.read(20)
            require(len(header) == 20 and header[:6] == b"\x7fELF\x02\x01"
                    and int.from_bytes(header[18:20], "little") == 183,
                    f"{name}: not an AArch64 ELF64 library")


def certificate_digest(report):
    lines = report.splitlines()
    require(lines.count("Verifies") == 1 and "DOES NOT VERIFY" not in lines,
            "Expected successful apksigner verification")
    require([line for line in lines if line.startswith("Number of signers:")]
            == ["Number of signers: 1"], "Expected exactly one verified signer")
    certificates = [line for line in lines if "certificate SHA-256 digest:" in line]
    require(len(certificates) == 1, "Expected exactly one verified signing certificate")
    # Build-tools 37 names the single signer by scheme, not "Signer #1".
    value = re.fullmatch(
        r"(?:Signer #1|V(?:1|2|3\.0) Signer:) certificate SHA-256 digest: ([0-9a-fA-F]{64})",
        certificates[0])
    require(value is not None, "Unexpected signing certificate report format")
    return value[1].lower()


def source_files(root):
    entries = git(root, "ls-tree", "-r", "HEAD").splitlines()
    result = []
    for entry in entries:
        metadata, name = entry.split("\t", 1)
        if metadata.split()[1] != "blob":
            continue
        path = Path(name)
        if path.suffix.lower() in (".keystore", ".jks", ".p12", ".pfx", ".key"):
            continue
        if path.suffix.lower() == ".pem" and name not in (
            "common/certificate/chrome.pem", "common/certificate/mozilla.pem"
        ):
            continue
        if path.name in ("local.properties", "service-account-credentials.json"):
            continue
        result.append(name)
    return result


def archive_source(root, name, output):
    # Explicit blob paths mean the upstream keystore is never opened/archived.
    subprocess.run(["git", "-C", str(root), "archive", "--format=tar.gz",
                    f"--prefix={name}/", f"--output={output}", "HEAD", "--",
                    *source_files(root)], check=True)


def collect(core, tooling, output):
    record = provenance(core, tooling)
    app = core / MANIFEST["app"]["path"]
    apks = list((app / "app/build/outputs/apk/other/debug").glob("*.apk"))
    require(len(apks) == 1, f"Expected exactly one arm64 debug APK, found {len(apks)}")
    apk = apks[0]
    sdk = Path(os.environ["ANDROID_HOME"]) / "build-tools" / MANIFEST["toolchain"]["build_tools"]
    badging = subprocess.check_output([str(sdk / "aapt"), "dump", "badging", str(apk)], text=True)
    check_apk(apk, badging)
    report = subprocess.check_output(
        [str(sdk / "apksigner"), "verify", "--verbose", "--print-certs", str(apk)], text=True)
    print(report, end="", flush=True)
    fingerprint = certificate_digest(report)
    output.mkdir(parents=True, exist_ok=False)
    name = f"Chibaheit-SFA-{MANIFEST['app']['version_name']}-arm64-v8a-DEBUG.apk"
    shutil.copyfile(apk, output / name)
    (output / "certificate-sha256.txt").write_text(f"{fingerprint}  {name}\n")
    record["apk"] = name
    record["certificate_sha256"] = fingerprint
    record["github_run_id"] = os.environ.get("GITHUB_RUN_ID")
    record["github_run_attempt"] = os.environ.get("GITHUB_RUN_ATTEMPT")
    record["actual_go_version"] = subprocess.check_output(["go", "version"], text=True).strip()
    record["actual_java_version"] = subprocess.check_output(["java", "--version"], text=True).strip()
    (output / "source-manifest.json").write_text(json.dumps(record, indent=2) + "\n")
    with tarfile.open(output / "source-patch-bundle.tar.gz", "w:gz") as bundle:
        for path in sorted(HERE.rglob("*")):
            if path.is_file() and "__pycache__" not in path.parts:
                bundle.add(path, arcname="build/android/" + str(path.relative_to(HERE)))
        bundle.add(output / "source-manifest.json", arcname="source-manifest.json")
    archive_source(core, "core", output / "core-source.tar.gz")
    archive_source(app, "app", output / "app-source.tar.gz")
    lines = [f"{hashlib.sha256(p.read_bytes()).hexdigest()}  {p.name}\n"
             for p in sorted(output.iterdir())]
    (output / "SHA256SUMS").write_text("".join(lines))
    print(f"Verified DEBUG artifact: {output / name}")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("core", type=Path)
    parser.add_argument("tooling", type=Path)
    parser.add_argument("output", type=Path)
    args = parser.parse_args()
    collect(args.core.resolve(), args.tooling.resolve(), args.output.resolve())
