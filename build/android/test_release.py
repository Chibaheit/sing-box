#!/usr/bin/env python3
"""Release security regressions; no permanent credentials or Android build."""

import argparse
import base64
import copy
import hashlib
import json
import os
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import patch
import zipfile

import collect
import prepare
import signing

APKSIGNER_JAR = None
AOSP_APK = None
JAVA_HOME = None


class ReleaseContract(unittest.TestCase):
    def test_release_manifest(self):
        app = prepare.MANIFEST["app"]
        self.assertEqual(app["gradle_task"], ":app:assembleOtherRelease")
        prepare.validate_manifest()
        self.assertGreaterEqual(app["version_code"], 735)
        self.assertEqual(len(prepare.MANIFEST["core"]["patches"]), 1)
        self.assertEqual(len(prepare.MANIFEST["app"]["patches"]), 4)

    def test_input_validation(self):
        env = {
            "KEYSTORE_B64": base64.b64encode(b"synthetic-not-a-keystore").decode(),
            "KEYSTORE_PASSWORD": "test-store-password",
            "KEY_ALIAS": "test-alias",
            "KEY_PASSWORD": "test-key-password",
            "CERT_SHA256": "ab" * 32,
        }
        with patch.dict(os.environ, env, clear=True):
            signing.preflight()
            for key in env:
                with self.subTest(missing=key), patch.dict(os.environ, {key: ""}):
                    with self.assertRaises(ValueError):
                        signing.preflight()
            for key, value in (("CERT_SHA256", "xy" * 32),
                               ("CERT_SHA256", "ab:" * 32),
                               ("KEYSTORE_B64", "%%%"), ("KEY_ALIAS", "-flag"),
                               ("KEY_PASSWORD", "line\nbreak")):
                with self.subTest(key=key), patch.dict(os.environ, {key: value}):
                    with self.assertRaises(ValueError):
                        signing.preflight()

    def test_version_monotonicity(self):
        for code in (733, 734, True, "735"):
            manifest = copy.deepcopy(prepare.MANIFEST)
            manifest["app"]["version_code"] = code
            with self.subTest(code=code), self.assertRaises(ValueError):
                prepare.validate_manifest(manifest)
        manifest = copy.deepcopy(prepare.MANIFEST)
        manifest["app"]["previous_version_code"] = manifest["app"]["version_code"]
        manifest["app"]["version_code"] += 1
        prefix, counter = manifest["app"]["version_name"].rsplit(".", 1)
        manifest["app"]["version_name"] = f"{prefix}.{int(counter) + 1}"
        manifest["libbox"]["local_version_tag"] = "v" + manifest["app"]["version_name"]
        prepare.validate_manifest(manifest)
        manifest["libbox"]["local_version_tag"] = prepare.MANIFEST["libbox"]["local_version_tag"]
        with self.assertRaises(ValueError):
            prepare.validate_manifest(manifest)

    def test_certificate_pin_is_independent(self):
        report = (prepare.HERE / "fixtures/apksigner-37-single-signer.txt").read_text()
        digest = collect.certificate_digest(report)
        with patch.dict(os.environ, {"CERT_SHA256": digest}):
            self.assertEqual(collect.release_certificate(report), digest)
        for expected in ("", "cd" * 32):
            with patch.dict(os.environ, {"CERT_SHA256": expected}):
                with self.assertRaises(ValueError):
                    collect.release_certificate(report)
        with patch.dict(os.environ, {"CERT_SHA256": digest}):
            with self.assertRaises(ValueError):
                collect.release_certificate(report.replace(
                    "Verified using v2 scheme (APK Signature Scheme v2): true",
                    "Verified using v2 scheme (APK Signature Scheme v2): false"))

    def test_missing_credentials_fail_before_build(self):
        with tempfile.TemporaryDirectory(prefix="release-early-test-") as temporary:
            env = {"PATH": os.environ["PATH"], "RUNNER_TEMP": temporary}
            result = subprocess.run(
                ["bash", str(prepare.HERE / "build.sh"), "/does-not-exist"],
                env=env, capture_output=True, text=True)
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("Missing signing input: KEYSTORE_B64", result.stderr)
            self.assertNotIn("does-not-exist", result.stderr)

    def test_archive_exclusions(self):
        for path in ("owner.jks", "app/release.keystore", "local.properties",
                     "signing.env", ".env", "tempkeys/key", "signenv", "owner.key",
                     "nested/keystores/secret", "service-account-credentials.json"):
            with self.subTest(path=path):
                self.assertFalse(collect.public_source_path(path))
        self.assertTrue(collect.public_source_path("LICENSE"))
        self.assertTrue(collect.public_source_path("common/certificate/chrome.pem"))

    def test_unsigned_output_metadata(self):
        with tempfile.TemporaryDirectory(prefix="release-metadata-test-") as temporary:
            core = Path(temporary)
            directory = (core / prepare.MANIFEST["app"]["path"]
                         / prepare.MANIFEST["app"]["unsigned_apk_directory"])
            directory.mkdir(parents=True)
            apk = directory / "SFA-arm64-v8a-unsigned.apk"
            apk.touch()
            metadata = {
                "artifactType": {"type": "APK"}, "variantName": "otherRelease",
                "applicationId": "io.chibaheit.sfa", "elements": [{
                    "filters": [{"filterType": "ABI", "value": "arm64-v8a"}],
                    "versionCode": prepare.MANIFEST["app"]["version_code"],
                    "versionName": prepare.MANIFEST["app"]["version_name"],
                    "outputFile": apk.name,
                }],
            }
            path = directory / "output-metadata.json"
            path.write_text(json.dumps(metadata))
            self.assertEqual(signing.unsigned_apk(core), apk)
            for field, value in (("outputFile", "../escape-unsigned.apk"),
                                 ("outputFile", "signed.apk"), ("versionCode", 734),
                                 ("filters", [])):
                changed = copy.deepcopy(metadata)
                changed["elements"][0][field] = value
                path.write_text(json.dumps(changed))
                with self.subTest(field=field), self.assertRaises(ValueError):
                    signing.unsigned_apk(core)
            path.write_text(json.dumps(metadata))
            (directory / "extra.apk").touch()
            with self.assertRaises(ValueError):
                signing.unsigned_apk(core)

    def test_signer_password_arguments_and_suppressed_diagnostics(self):
        env = {"KEY_ALIAS": "test-alias", "KEYSTORE_PASSWORD": "do-not-log-store",
               "KEY_PASSWORD": "do-not-log-key"}
        with patch.dict(os.environ, env), patch("signing.subprocess.run") as run:
            run.return_value.returncode = 1
            with self.assertRaisesRegex(ValueError, "private diagnostics suppressed"):
                signing.sign_with_keystore(Path("unsigned.apk"), Path("signed.apk"),
                                           Path("test.jks"), Path("/sdk"))
            args = run.call_args.args[0]
            self.assertIn("env:KEYSTORE_PASSWORD", args)
            self.assertIn("env:KEY_PASSWORD", args)
            self.assertNotIn(env["KEYSTORE_PASSWORD"], " ".join(args))
            self.assertNotIn(env["KEY_PASSWORD"], " ".join(args))
            self.assertEqual(run.call_args.kwargs["stderr"], subprocess.DEVNULL)
            self.assertEqual(run.call_args.kwargs["stdout"], subprocess.DEVNULL)

    def test_shell_failure_redaction_and_cleanup(self):
        # Run the actual shell wrapper; a controlled Python shim simulates failure
        # after key decoding without needing an SDK, keystore or source checkout.
        with tempfile.TemporaryDirectory(prefix="release-trap-test-") as temporary:
            root = Path(temporary)
            bin_dir = root / "bin"
            bin_dir.mkdir()
            shim = bin_dir / "python3"
            shim.write_text(
                "#!/usr/bin/env bash\nset -eu\n"
                'case "$2" in\n'
                'preflight) exit 0;;\n'
                'sign) mkdir -m 700 "$RUNNER_TEMP/chibaheit-release-signing"; '
                'printf synthetic > "$RUNNER_TEMP/chibaheit-release-signing/owner.jks"; exit 23;;\n'
                'cleanup) rm -f "$RUNNER_TEMP/chibaheit-release-signing/owner.jks"; '
                'rmdir "$RUNNER_TEMP/chibaheit-release-signing";;\nesac\n')
            shim.chmod(0o700)
            env = dict(os.environ, PATH=str(bin_dir) + os.pathsep + os.environ["PATH"],
                       RUNNER_TEMP=str(root), KEYSTORE_PASSWORD="SENTINEL-NOT-FOR-LOGS",
                       KEY_PASSWORD="SENTINEL-NOT-FOR-LOGS", KEYSTORE_B64="SENTINEL-NOT-FOR-LOGS")
            result = subprocess.run(["bash", "-x", str(prepare.HERE / "sign.sh"), "core", "out"],
                                    env=env, capture_output=True, text=True)
            self.assertEqual(result.returncode, 23)
            self.assertNotIn("SENTINEL-NOT-FOR-LOGS", result.stdout + result.stderr)
            self.assertFalse((root / "chibaheit-release-signing").exists())

    def test_temp_directory_guard_and_real_cleanup(self):
        with patch.dict(os.environ, {"RUNNER_TEMP": str(prepare.HERE)}):
            with self.assertRaises(ValueError):
                signing.temporary_directory()
        with tempfile.TemporaryDirectory(prefix="release-cleanup-test-") as temporary:
            with patch.dict(os.environ, {"RUNNER_TEMP": temporary}):
                root = signing.temporary_directory()
                root.mkdir(mode=0o700)
                (root / "owner.jks").write_bytes(b"synthetic")
                signing.cleanup()
                signing.cleanup()
                self.assertFalse(root.exists())

    def test_signing_failure_keystore_permissions(self):
        env = {
            "KEYSTORE_B64": base64.b64encode(b"synthetic-test-key").decode(),
            "KEYSTORE_PASSWORD": "test-store", "KEY_PASSWORD": "test-key",
            "KEY_ALIAS": "test", "CERT_SHA256": "ab" * 32,
        }
        with tempfile.TemporaryDirectory(prefix="release-permissions-test-") as temporary:
            root = Path(temporary)
            env["RUNNER_TEMP"] = str(root)
            with patch.dict(os.environ, env), \
                    patch("signing.unsigned_apk", return_value=root / "unsigned.apk"), \
                    patch("signing.sdk_tools", return_value=root), \
                    patch("collect.check_apk"), \
                    patch("signing.subprocess.check_output", return_value="synthetic-badging"), \
                    patch("signing.subprocess.run") as run:
                run.return_value.returncode = 1

                def fail_sign(apk, signed, keystore, sdk):
                    self.assertEqual(keystore.stat().st_mode & 0o777, 0o600)
                    self.assertEqual(keystore.parent.stat().st_mode & 0o777, 0o700)
                    self.assertEqual(keystore.read_bytes(), b"synthetic-test-key")
                    raise ValueError("synthetic signing failure")

                with patch("signing.sign_with_keystore", side_effect=fail_sign):
                    try:
                        with self.assertRaisesRegex(ValueError, "synthetic signing failure"):
                            signing.sign(root / "core", root / "signed")
                    finally:
                        signing.cleanup()
                self.assertFalse((root / "chibaheit-release-signing").exists())

    def test_workflow_secret_scopes_and_early_guard(self):
        import yaml
        import validate_workflow
        template = (prepare.HERE / "custom-android.yml.in").read_text()
        text = template.replace("@TOOLING_REVISION@", prepare.git(prepare.HERE, "rev-parse", "HEAD"))
        text = text.replace("@VERSION_NAME@", prepare.MANIFEST["app"]["version_name"])
        workflow = yaml.load(text, Loader=yaml.BaseLoader)
        steps = workflow["jobs"]["build"]["steps"]
        self.assertIn("preflight", steps[1]["run"])
        cleanup = next(step for step in steps if "Always remove" in step["name"])
        self.assertEqual(cleanup["if"], "${{ always() }}")
        with tempfile.TemporaryDirectory(prefix="release-workflow-test-") as temporary:
            path = Path(temporary) / "workflow.yml"
            path.write_text(text)
            validate_workflow.validate(path)
            for old, new in (("contents: read", "contents: write"),
                             ("workflow_dispatch:", "pull_request:"),
                             ("signing.py preflight", "echo bypass"),
                             ("${{ secrets.CERT_SHA256 }}", "attacker-controlled"),
                             ("*-RELEASE.apk", "**/*")):
                path.write_text(text.replace(old, new))
                with self.subTest(change=new), self.assertRaises(ValueError):
                    validate_workflow.validate(path)


class RealSigning(unittest.TestCase):
    def test_aosp_apk_with_disposable_test_key(self):
        if APKSIGNER_JAR is None:
            self.skipTest("Pass --apksigner-jar, --aosp-apk and --java-home for real signing")
        self.assertEqual(hashlib.sha256(APKSIGNER_JAR.read_bytes()).hexdigest(),
                         prepare.MANIFEST["signing"]["apksigner_jar_sha256"])
        contents = AOSP_APK.read_bytes()
        self.assertEqual(hashlib.sha1(b"blob " + str(len(contents)).encode() + b"\0"
                                     + contents).hexdigest(),
                         "e82f67be2a8825676255ef207c8a3a03c2661c91")
        with tempfile.TemporaryDirectory(prefix="aosp-disposable-test-key-") as temporary:
            root = Path(temporary)
            sdk = root / "build-tools" / prepare.MANIFEST["toolchain"]["build_tools"]
            (sdk / "lib").mkdir(parents=True)
            (sdk / "lib/apksigner.jar").symlink_to(APKSIGNER_JAR)
            launcher = sdk / "apksigner"
            launcher.write_text('#!/bin/sh\nexec "$TEST_JAVA" -jar "$TEST_SIGNER_JAR" "$@"\n')
            launcher.chmod(0o700)
            env = {
                "KEYSTORE_PASSWORD": "disposable-test-store-only",
                "KEY_PASSWORD": "disposable-test-key-only",
                "KEY_ALIAS": "disposable-test", "TEST_JAVA": str(JAVA_HOME / "bin/java"),
                "TEST_SIGNER_JAR": str(APKSIGNER_JAR), "ANDROID_HOME": str(root),
            }
            keystore = root / "disposable-test.jks"
            with patch.dict(os.environ, env):
                result = subprocess.run([
                    str(JAVA_HOME / "bin/keytool"), "-genkeypair", "-noprompt",
                    "-keystore", str(keystore), "-storetype", "JKS",
                    "-storepass:env", "KEYSTORE_PASSWORD", "-keypass:env", "KEY_PASSWORD",
                    "-alias", env["KEY_ALIAS"], "-keyalg", "RSA", "-keysize", "2048",
                    "-validity", "1", "-dname", "CN=disposable-test-only",
                ], capture_output=True)
                self.assertEqual(result.returncode, 0, "Disposable TEST key generation failed")
                certificate = subprocess.check_output([
                    str(JAVA_HOME / "bin/keytool"), "-exportcert", "-keystore", str(keystore),
                    "-storepass:env", "KEYSTORE_PASSWORD", "-alias", env["KEY_ALIAS"],
                ], stderr=subprocess.DEVNULL)
                digest = hashlib.sha256(certificate).hexdigest()
                unsigned = root / "unsigned.apk"
                with zipfile.ZipFile(AOSP_APK) as source, zipfile.ZipFile(unsigned, "w") as target:
                    for entry in source.infolist():
                        if not entry.filename.startswith("META-INF/"):
                            target.writestr(entry, source.read(entry))
                verify = [str(launcher), "verify", "--verbose", "--print-certs"]
                self.assertNotEqual(subprocess.run(
                    [*verify, str(unsigned)], capture_output=True).returncode, 0)
                signed = root / "signed.apk"
                signing.sign_with_keystore(unsigned, signed, keystore, signing.sdk_tools())
                report = subprocess.check_output([*verify, str(signed)], text=True)
                with patch.dict(os.environ, {"CERT_SHA256": digest}):
                    self.assertEqual(collect.release_certificate(report), digest)
                with patch.dict(os.environ, {"CERT_SHA256": "ab" * 32}):
                    with self.assertRaisesRegex(ValueError, "certificate mismatch"):
                        collect.release_certificate(report)
                with zipfile.ZipFile(signed, "a") as archive:
                    archive.writestr("tampered", b"must fail signature verification")
                self.assertNotEqual(subprocess.run(
                    [*verify, str(signed)], capture_output=True).returncode, 0)
            print("Real pinned apksigner: unsigned rejected, TEST-key APK verified, "
                  "wrong certificate/tampering rejected; temporary TEST key removed")
        self.assertFalse(root.exists())


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--apksigner-jar", type=Path)
    parser.add_argument("--aosp-apk", type=Path)
    parser.add_argument("--java-home", type=Path)
    args, remaining = parser.parse_known_args()
    supplied = (args.apksigner_jar, args.aosp_apk, args.java_home)
    if any(supplied) and not all(supplied):
        parser.error("All three real-signing tool/fixture paths are required together")
    APKSIGNER_JAR, AOSP_APK, JAVA_HOME = (
        path.resolve() if path else None for path in supplied)
    unittest.main(argv=[__file__, *remaining])
