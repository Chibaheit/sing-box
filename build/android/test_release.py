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
import sys
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


def workflow_build_job():
    import yaml
    return yaml.load((prepare.HERE / "custom-android.yml.in").read_text(),
                     Loader=yaml.BaseLoader)["jobs"]["build"]


class ReleaseContract(unittest.TestCase):
    def test_hosted_runtime_tests_are_explicit_and_gradle_is_optional(self):
        steps = workflow_build_job()["steps"]
        test_step = next(step for step in steps
                         if step.get("name") == "Test source patches and artifact rejection cases")
        self.assertEqual(test_step["run"].splitlines()[-1],
                         "python3 tooling/build/android/test_runtime.py -v")
        self.assertNotIn("GRADLE", test_step["run"])
        self.assertNotIn("env", test_step)

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

    def test_public_certificate_preflight_formats(self):
        public = ("F0:4E:F5:64:1E:42:D7:F9:8D:6E:69:C6:3F:E1:FF:2B:"
                  "6F:64:6B:26:C8:48:59:1C:F7:BD:C6:B7:6B:FD:0A:C6")
        normalized = public.replace(":", "").lower()
        env = {
            "PATH": os.environ["PATH"],
            "KEYSTORE_B64": base64.b64encode(b"synthetic-not-a-keystore").decode(),
            "KEYSTORE_PASSWORD": "synthetic-store", "KEY_PASSWORD": "synthetic-key",
            "KEY_ALIAS": "synthetic-alias",
        }
        for value in (public, public.lower(), normalized, normalized.upper()):
            with self.subTest(valid=value):
                result = subprocess.run(
                    [sys.executable, str(prepare.HERE / "signing.py"), "preflight"],
                    env=dict(env, CERT_SHA256=value), capture_output=True, text=True)
                self.assertEqual(result.returncode, 0, result.stderr)
                with patch.dict(os.environ, {"CERT_SHA256": value}, clear=True):
                    self.assertEqual(signing.expected_certificate(), normalized)

    def test_malformed_certificate_preflight(self):
        valid = ":".join(["AB"] * 32)
        env = {
            "KEYSTORE_B64": base64.b64encode(b"synthetic-not-a-keystore").decode(),
            "KEYSTORE_PASSWORD": "synthetic-store", "KEY_PASSWORD": "synthetic-key",
            "KEY_ALIAS": "synthetic-alias",
        }
        for value in ("", "AB" * 31, "AB" * 33, valid[:-3], valid + ":AB",
                      valid.replace(":", "", 1), valid.replace(":", "::", 1),
                      valid.replace(":", "-", 1), valid.replace(":", " "),
                      ":" + valid, valid + ":", " " + valid, valid + "\n",
                      valid[:-1] + "G", "A:" + valid[3:], "SHA256:" + valid,
                      ".".join(["AB"] * 32)):
            with self.subTest(value=value), patch.dict(
                    os.environ, dict(env, CERT_SHA256=value), clear=True):
                with self.assertRaisesRegex(ValueError, "CERT_SHA256"):
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
        with patch.dict(os.environ, {"CERT_SHA256": ":".join(
                digest[i:i + 2].upper() for i in range(0, 64, 2))}):
            self.assertEqual(collect.release_certificate(report), digest)
        for expected in ("", "cd" * 32, ":".join(["CD"] * 32)):
            with patch.dict(os.environ, {"CERT_SHA256": expected}):
                with self.assertRaises(ValueError):
                    collect.release_certificate(report)
        with patch.dict(os.environ, {"CERT_SHA256": digest}):
            with self.assertRaises(ValueError):
                collect.release_certificate(report.replace(
                    "Verified using v2 scheme (APK Signature Scheme v2): true",
                    "Verified using v2 scheme (APK Signature Scheme v2): false"))

    def test_missing_credentials_fail_before_build(self):
        steps = workflow_build_job()["steps"]
        guard = steps[1]
        self.assertEqual(guard["run"], "python3 tooling/build/android/signing.py preflight")
        self.assertEqual(set(guard["env"]), set(prepare.MANIFEST["signing"]["required_inputs"]))
        with tempfile.TemporaryDirectory(prefix="release-early-test-") as temporary:
            env = {"PATH": os.environ["PATH"], "RUNNER_TEMP": temporary}
            result = subprocess.run(
                [sys.executable, str(prepare.HERE / "signing.py"), "preflight"],
                env=env, capture_output=True, text=True)
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("Missing signing input: KEYSTORE_B64", result.stderr)

    @unittest.skipUnless(sys.platform == "linux", "Requires Linux /proc environment snapshots")
    def test_workflow_build_process_environment(self):
        job = workflow_build_job()
        step = next(step for step in job["steps"] if "build.sh" in step.get("run", ""))
        secrets = {
            "KEYSTORE_B64": base64.b64encode(b"SYNTHETIC-BUILD-KEYSTORE-SENTINEL").decode(),
            "KEYSTORE_PASSWORD": "SYNTHETIC-BUILD-STORE-SENTINEL",
            "KEY_PASSWORD": "SYNTHETIC-BUILD-KEY-SENTINEL",
            "KEY_ALIAS": "SYNTHETIC-BUILD-ALIAS-SENTINEL", "CERT_SHA256": "AC" * 32,
        }
        with tempfile.TemporaryDirectory(prefix="release-build-env-test-") as temporary:
            root = Path(temporary)
            (root / "tooling").symlink_to(prepare.HERE.parents[1], target_is_directory=True)
            (root / "source").mkdir()
            sdk = root / "sdk"
            for directory in ("licenses", "ndk/28.0.13004108", "platforms/android-37.1",
                              "platforms/android-36", "build-tools/37.0.0"):
                (sdk / directory).mkdir(parents=True)
            (sdk / "licenses/android-sdk-license").touch()
            (sdk / "ndk/28.0.13004108/source.properties").touch()
            (sdk / "build-tools/37.0.0/apksigner").touch(mode=0o700)
            bin_dir = root / "bin"
            bin_dir.mkdir()
            shim = bin_dir / "go"
            # Stop at the first Go command, before source preparation/compilation.
            # Read only our synthetic child tree, never the test runner's environment.
            shim.write_text(
                f"#!{sys.executable}\n"
                "import json, os\nfrom pathlib import Path\n"
                "pid = os.getpid()\nsnapshots = []\n"
                "while pid != int(os.environ['TEST_RUNNER_PID']):\n"
                "    proc = Path('/proc') / str(pid)\n"
                "    snapshots.append((proc / 'environ').read_bytes().decode().split('\\0'))\n"
                "    status = (proc / 'status').read_text().splitlines()\n"
                "    pid = int(next(line.split()[1] for line in status if line.startswith('PPid:')))\n"
                "Path(os.environ['TEST_REPORT']).write_text(json.dumps(snapshots))\n"
                "raise SystemExit(73)\n")
            shim.chmod(0o700)
            report = root / "environment.json"
            env = {
                "PATH": str(bin_dir) + os.pathsep + os.environ["PATH"],
                "ANDROID_HOME": str(sdk), "GITHUB_WORKSPACE": str(root),
                "TEST_REPORT": str(report), "TEST_RUNNER_PID": str(os.getpid()),
            }
            for scope in (job.get("env", {}), step.get("env", {})):
                for name, value in scope.items():
                    env[name] = next((sentinel for key, sentinel in secrets.items()
                                      if value == "${{ secrets." + key + " }}"), value)
            result = subprocess.run(["bash", "-c", step["run"]], cwd=root, env=env,
                                    capture_output=True, text=True)
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("Go 1.26.8 required", result.stderr)
            snapshots = json.loads(report.read_text())
            self.assertGreaterEqual(len(snapshots), 2)
            for index, entries in enumerate(snapshots):
                with self.subTest(process=index):
                    self.assertFalse(set(secrets) & {entry.partition("=")[0] for entry in entries})
                    for sentinel in secrets.values():
                        self.assertNotIn(sentinel, "\0".join(entries))
            self.assertFalse(set(secrets) & set(step.get("env", {})))

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
        self.assertEqual(workflow["jobs"]["build"]["env"], {"PYTHONDONTWRITEBYTECODE": "1"})
        required = prepare.MANIFEST["signing"]["required_inputs"]
        secret_steps = {
            "Require protected signing inputs before setup or build": required,
            "Sign release with the protected owner key": required,
            "Verify APK and assemble allowlisted provenance artifacts": ["CERT_SHA256"],
        }
        for step in steps:
            names = secret_steps.get(step["name"], [])
            self.assertEqual(step.get("env", {}),
                             {name: "${{ secrets." + name + " }}" for name in names})
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
                "KEY_PASSWORD": "disposable-test-store-only",
                "KEY_ALIAS": "disposable-test", "TEST_JAVA": str(JAVA_HOME / "bin/java"),
                "TEST_SIGNER_JAR": str(APKSIGNER_JAR), "ANDROID_HOME": str(root),
            }
            keystore = root / "disposable-test.p12"
            with patch.dict(os.environ, env):
                result = subprocess.run([
                    str(JAVA_HOME / "bin/keytool"), "-genkeypair", "-noprompt",
                    "-keystore", str(keystore), "-storetype", "PKCS12",
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
                os.environ["KEYSTORE_B64"] = base64.b64encode(keystore.read_bytes()).decode()
                os.environ["CERT_SHA256"] = ":".join(
                    digest[i:i + 2].upper() for i in range(0, 64, 2))
                self.assertEqual(signing.preflight(), keystore.read_bytes())
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
            print("Real pinned apksigner: unsigned rejected, PKCS12 TEST-key APK verified, "
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
