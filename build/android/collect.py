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
    require(all(char == "\n" or char.isprintable() for char in report),
            "Unexpected control character in signing report")
    require(lines.count("Verifies") == 1 and "DOES NOT VERIFY" not in lines,
            "Expected successful apksigner verification")
    require([line for line in lines if line.startswith("Number of signers:")]
            == ["Number of signers: 1"], "Expected exactly one verified signer")
    fields = {
        "certificate DN": r"\S(?:.*\S)?",
        "certificate SHA-256 digest": r"[0-9a-fA-F]{64}",
        "certificate SHA-1 digest": r"[0-9a-fA-F]{40}",
        "certificate MD5 digest": r"[0-9a-fA-F]{32}",
        "key algorithm": r"RSA|EC|DSA",
        "key size (bits)": r"[1-9][0-9]*",
        "public key SHA-256 digest": r"[0-9a-fA-F]{64}",
        "public key SHA-1 digest": r"[0-9a-fA-F]{40}",
        "public key MD5 digest": r"[0-9a-fA-F]{32}",
    }
    headers = {"Verifies", "Number of signers: 1", "Verified for SourceStamp: false"}
    for scheme, description in (
        ("1", "JAR signing"), ("2", "APK Signature Scheme v2"),
        ("3", "APK Signature Scheme v3"), ("3.1", "APK Signature Scheme v3.1"),
        ("3.2", "APK Signature Scheme v3.2"), ("4", "APK Signature Scheme v4"),
    ):
        for status in ("false",) if scheme in ("3.1", "3.2") else ("false", "true"):
            headers.add(f"Verified using v{scheme} scheme ({description}): {status}")
    seen_headers = set()
    records = []
    scopes = set()
    scope = None
    for line in lines:
        if line in headers:
            header = line.rsplit(": ", 1)[0]
            require(not records and header not in seen_headers,
                    "Duplicate or misplaced signing report header")
            seen_headers.add(header)
            continue
        match = re.fullmatch(r"(Signer #1|V(?:1|2|3\.0) Signer:) ([^:]+): (.+)", line)
        require(match is not None, "Unsupported signing report line or signer scope")
        label, field, value = match.groups()
        require(field in fields and re.fullmatch(fields[field], value) is not None,
                "Unsupported or malformed signing certificate field")
        if field == "certificate DN":
            records.append({})
            scope = label
            scopes.add(label)
        require(records and label == scope, "Missing or interleaved signing certificate record")
        require(field not in records[-1], "Duplicate signing certificate field")
        records[-1][field] = value.lower() if field.endswith(" digest") else value
    require(records and all(record.keys() == fields.keys() for record in records),
            "Incomplete signing certificate record")
    require("Signer #1" not in scopes or len(scopes) == 1,
            "Ambiguous mixed legacy and scheme signer scopes")
    # Repeated scheme records are one identity only if ALL reported details agree.
    require(all(record == records[0] for record in records),
            "Conflicting signing certificate records")
    return records[0]["certificate SHA-256 digest"]


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
    try:
        fingerprint = certificate_digest(report)
    except ValueError:
        print("Rejected public apksigner report: " + json.dumps(report, ensure_ascii=True),
              flush=True)
        raise
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
