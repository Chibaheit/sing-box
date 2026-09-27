#!/usr/bin/env python3
"""Offline patch/ZIP tests and an optional, projected Kotlin ABI compiler test."""

import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import tempfile
import tarfile
import unittest
from unittest.mock import patch
import zipfile

import collect
import prepare

CORE_SOURCE = None
APP_SOURCE = None
KOTLIN_HOME = None


def checkout(source, revision, destination):
    subprocess.run(["git", "init", "-q", str(destination)], check=True)
    subprocess.run(["git", "-C", str(destination), "fetch", "-q", "--no-tags",
                    "--depth=1", str(source), revision], check=True)
    subprocess.run(["git", "-C", str(destination), "checkout", "-q", "--detach", "FETCH_HEAD"],
                   check=True)


class Patches(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temporary = tempfile.TemporaryDirectory(prefix="custom-android-test-")
        cls.addClassCleanup(cls.temporary.cleanup)
        cls.core = Path(cls.temporary.name) / "core"
        cls.app = cls.core / prepare.MANIFEST["app"]["path"]
        checkout(CORE_SOURCE, prepare.MANIFEST["core"]["revision"], cls.core)
        checkout(APP_SOURCE, prepare.MANIFEST["app"]["revision"], cls.app)

    def test_patch_red_green_and_fail_closed(self):
        # RED: pristine upstream must not satisfy the custom-build contract.
        with self.assertRaises(subprocess.CalledProcessError):
            prepare.verify(self.core)
        print("RED confirmed: pristine pinned sources reject custom verification")
        with self.assertRaises(ValueError):
            self.assert_custom_sources()
        prepare.apply(self.core)
        prepare.verify(self.core)
        self.assert_custom_sources()
        print("GREEN confirmed: exact patch layer passes source contract")
        with self.assertRaises(ValueError):
            prepare.apply(self.core)
        local = self.app / "local.properties"
        local.write_text("sdk.dir=/not/a/signing/config\n")
        with self.assertRaisesRegex(ValueError, "local.properties"):
            prepare.verify(self.core)
        local.unlink()
        vendor = self.app / "app/src/other/java/io/nekohasekai/sfa/vendor/Vendor.kt"
        original = vendor.read_text()
        vendor.write_text(original + "\n// unexpected same-file edit\n")
        with self.assertRaisesRegex(ValueError, "contents differ"):
            prepare.verify(self.core)
        vendor.write_text(original)
        prepare.verify(self.core)
        self.assert_artifact_collection()
        bad_core = Path(self.temporary.name) / "wrong"
        checkout(CORE_SOURCE, prepare.MANIFEST["core"]["revision"], bad_core)
        subprocess.run(["git", "-C", str(bad_core), "-c", "user.name=Test",
                        "-c", "user.email=test@example.invalid", "commit", "-q", "--allow-empty",
                        "-m", "wrong source revision"], check=True)
        with self.assertRaisesRegex(ValueError, "revision mismatch"):
            prepare.check_pins(bad_core)

    def assert_artifact_collection(self):
        output = Path(self.temporary.name) / "synthetic-artifacts"
        apk_dir = self.app / "app/build/outputs/apk/other/debug"
        apk_dir.mkdir(parents=True)
        fixture = ArtifactChecks()
        fixture.setUp()
        self.addCleanup(fixture.doCleanups)
        fixture.write_zip({"lib/arm64-v8a/libbox.so": fixture.elf})
        (apk_dir / "synthetic.apk").write_bytes(fixture.apk.read_bytes())
        real_check_output = subprocess.check_output

        def tool_output(args, **kwargs):
            executable = Path(args[0]).name
            if executable == "aapt":
                return fixture.badging
            if executable == "apksigner":
                return "Signer #1 certificate SHA-256 digest: " + "ab" * 32 + "\n"
            if executable in ("go", "java"):
                return "SYNTHETIC TEST TOOL OUTPUT\n"
            return real_check_output(args, **kwargs)

        with patch("collect.provenance", return_value={"synthetic_test": True}), \
                patch("subprocess.check_output", side_effect=tool_output), \
                patch.dict(os.environ, {"ANDROID_HOME": "/synthetic-sdk"}):
            collect.collect(self.core, CORE_SOURCE, output)
        expected = {
            "Chibaheit-SFA-1.14.1-chibaheit.1-arm64-v8a-DEBUG.apk",
            "certificate-sha256.txt", "source-manifest.json", "SHA256SUMS",
            "source-patch-bundle.tar.gz", "core-source.tar.gz", "app-source.tar.gz",
        }
        self.assertEqual({p.name for p in output.iterdir()}, expected)
        record = json.loads((output / "source-manifest.json").read_text())
        self.assertTrue(record["synthetic_test"])
        self.assertEqual(record["certificate_sha256"], "ab" * 32)
        checksums = (output / "SHA256SUMS").read_text().splitlines()
        self.assertEqual(len(checksums), len(expected) - 1)
        for line in checksums:
            digest, name = line.split("  ", 1)
            self.assertEqual(digest, hashlib.sha256((output / name).read_bytes()).hexdigest())
        with tarfile.open(output / "source-patch-bundle.tar.gz") as bundle:
            self.assertIn("build/android/manifest.json", bundle.getnames())
        with tarfile.open(output / "app-source.tar.gz") as bundle:
            self.assertNotIn("app/app/release.keystore", bundle.getnames())
        print("Synthetic collector test passed; no Android compilation/signing was performed")

    def assert_custom_sources(self):
        app = self.app
        manifest = prepare.MANIFEST
        build = (app / "app/build.gradle.kts").read_text()
        prepare.require('applicationId = "io.chibaheit.sfa"' in build, "Not custom")
        for token in ('namespace = "io.nekohasekai.sfa"', 'isUniversalApk = false',
                      'include("arm64-v8a")', 'buildConfigField("boolean", "CUSTOM_BUILD", "true")',
                      'signingConfig = signingConfigs.getByName("debug")'):
            self.assertIn(token, build)
        self.assertNotIn('include("armeabi-v7a"', build)
        for strings in (app / "app/src/main/res").glob("values*/strings.xml"):
            text = strings.read_text()
            if 'name="app_name"' in text:
                self.assertIn('name="app_name" translatable="false">Chibaheit SFA</string>', text)
        vendor = (app / "app/src/other/java/io/nekohasekai/sfa/vendor/Vendor.kt").read_text()
        self.assertIn("override val hasCustomUpdate = !BuildConfig.CUSTOM_BUILD", vendor)
        self.assertEqual(vendor.count("check(!BuildConfig.CUSTOM_BUILD)"), 2)
        github = app / "app/src/github/java/io/nekohasekai/sfa/vendor"
        checker = (github / "GitHubUpdateChecker.kt").read_text()
        self.assertLess(checker.index("check(!BuildConfig.CUSTOM_BUILD)"),
                        checker.index("val releases = getReleases"))
        worker = (github / "UpdateWorker.kt").read_text()
        self.assertEqual(worker.count("BuildConfig.CUSTOM_BUILD || !Settings.autoUpdateEnabled"), 2)
        activity = (app / "app/src/main/java/io/nekohasekai/sfa/compose/MainActivity.kt").read_text()
        self.assertIn("!BuildConfig.CUSTOM_BUILD && Settings.checkUpdateEnabled", activity)
        self.assertIn("!BuildConfig.CUSTOM_BUILD && !Settings.updateCheckPrompted", activity)
        vpn = (app / "app/src/main/java/io/nekohasekai/sfa/bg/VPNService.kt").read_text()
        self.assertRegex(vpn, r'if \(!protect\(fd\)\) \{\s+throw IOException\(')
        self.assertIn("AutoDetectInterfaceControl(fd int32) error",
                      (self.core / "experimental/libbox/platform.go").read_text())
        self.assertIn("return w.iif.AutoDetectInterfaceControl(int32(fd))",
                      (self.core / "experimental/libbox/service.go").read_text())
        self.assertIn("return platformInterface.AutoDetectInterfaceControl(int(fileDescriptor))",
                      (self.core / "protocol/tailscale/system_binding.go").read_text())
        box = (app / "app/src/main/java/io/nekohasekai/sfa/bg/BoxService.kt").read_text()
        self.assertNotIn("promotePowerReportDraft", box)
        self.assertEqual(box.count("Libbox.discardPowerReportDraft()"), 2)
        self.assertIn("func DiscardPowerReportDraft()",
                      (self.core / "experimental/libbox/power_report.go").read_text())
        wrapper = (app / "app/src/main/java/io/nekohasekai/sfa/bg/PlatformInterfaceWrapper.kt").read_text()
        self.assertIn("override fun usePlatformAutoRedirect(): Boolean = false", wrapper)
        self.assertIn("override fun createAutoRedirect(options: ByteArray?, "
                      "handler: AutoRedirectHandler?): AutoRedirectSession", wrapper)
        self.assertIn('throw UnsupportedOperationException("Platform auto-redirect is not '
                      'supported by this build")', wrapper)
        builder = (self.core / "cmd/internal/build_libbox/main.go").read_text()
        tags = []
        for line in builder.splitlines():
            if line.strip().startswith("sharedTags = append(sharedTags,"):
                tags.extend(re.findall(r'"([^"]+)"', line))
        self.assertEqual(tags, manifest["libbox"]["tags"])
        self.assertIn("VERSION_NAME=" + manifest["app"]["version_name"],
                      (app / "version.properties").read_text())
        self.assertIn("VERSION_CODE=734", (app / "version.properties").read_text())
        self.assertIn("distributionSha256Sum=" + manifest["toolchain"]["gradle_sha256"],
                      (app / "gradle/wrapper/gradle-wrapper.properties").read_text())
        self.assertNotIn("app/release.keystore", collect.source_files(app))
        archive = Path(self.temporary.name) / "source.tar.gz"
        collect.archive_source(app, "app", archive)
        with tarfile.open(archive) as source:
            self.assertIn("app/LICENSE", source.getnames())
            self.assertNotIn("app/app/release.keystore", source.getnames())
        collect.archive_source(self.core, "core", archive)
        with tarfile.open(archive) as source:
            for name in ("core/LICENSE", "core/go.mod", "core/go.sum",
                         "core/common/certificate/chrome.pem", "core/common/certificate/mozilla.pem"):
                self.assertIn(name, source.getnames())


class ArtifactChecks(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix="synthetic-apk-test-")
        self.addCleanup(self.temporary.cleanup)
        self.apk = Path(self.temporary.name) / "synthetic.zip"
        self.badging = (
            "package: name='io.chibaheit.sfa' versionCode='734' versionName='1.14.1-chibaheit.1'\n"
            "application-label:'Chibaheit SFA'\napplication-debuggable\nnative-code: 'arm64-v8a'\n"
        )
        self.elf = b"\x7fELF\x02\x01" + bytes(12) + (183).to_bytes(2, "little")

    def write_zip(self, entries):
        with zipfile.ZipFile(self.apk, "w") as archive:
            for name, data in entries.items():
                archive.writestr(name, data)

    def test_expected_shape(self):
        self.write_zip({"lib/arm64-v8a/libbox.so": self.elf})
        collect.check_apk(self.apk, self.badging)

    def test_reject_identity_version_release_and_universal(self):
        self.write_zip({"lib/arm64-v8a/libbox.so": self.elf})
        for bad in (self.badging.replace("io.chibaheit.sfa", "io.nekohasekai.sfa"),
                    self.badging.replace("734", "739"), self.badging.replace("1.14.1", "1.14.2"),
                    self.badging.replace("Chibaheit SFA", "sing-box"),
                    self.badging.replace("application-debuggable", ""),
                    self.badging.replace("'arm64-v8a'", "'arm64-v8a' 'x86_64'")):
            with self.subTest(bad=bad), self.assertRaises(ValueError):
                collect.check_apk(self.apk, bad)

    def test_reject_missing_extra_or_mislabeled_libraries(self):
        for entries in ({}, {"lib/arm64-v8a/other.so": self.elf},
                        {"lib/arm64-v8a/libbox.so": self.elf, "lib/x86/libbox.so": self.elf},
                        {"lib/arm64-v8a/libbox.so": b"not ELF"},
                        {"lib/arm64-v8a/libbox.so": self.elf[:18] + (62).to_bytes(2, "little")}):
            with self.subTest(entries=list(entries)), self.assertRaises(ValueError):
                self.write_zip(entries)
                collect.check_apk(self.apk, self.badging)

    def test_certificate_report(self):
        line = "Signer #1 certificate SHA-256 digest: " + "AB" * 32 + "\n"
        self.assertEqual(collect.certificate_digest(line), "ab" * 32)
        for report in ("", line + line, line.replace("AB", "XY")):
            with self.assertRaises(ValueError):
                collect.certificate_digest(report)


class LibboxAPI(unittest.TestCase):
    def test_pinned_kotlin_api_seam(self):
        if KOTLIN_HOME is None:
            self.skipTest("Pass --kotlin-home for the narrow Kotlin compiler regression")
        java_home = Path(os.environ["JAVA_HOME"])
        with tempfile.TemporaryDirectory(prefix="libbox-api-test-") as temporary:
            root = Path(temporary)
            core = root / "core"
            app = core / prepare.MANIFEST["app"]["path"]
            checkout(CORE_SOURCE, prepare.MANIFEST["core"]["revision"], core)
            checkout(APP_SOURCE, prepare.MANIFEST["app"]["revision"], app)
            prepare.apply(core)

            # Project only the failed ABI seam, not Android services or an APK.
            platform = (core / "experimental/libbox/platform.go").read_text()
            self.assertIn("UsePlatformAutoRedirect() bool", platform)
            self.assertIn("CreateAutoRedirect(options []byte, handler AutoRedirectHandler) "
                          "(AutoRedirectSession, error)", platform)
            reports = (core / "experimental/libbox/power_report.go").read_text()
            report_functions = re.findall(r"^func ([A-Z]\w*)\(\) \{", reports, re.MULTILINE)
            self.assertEqual(report_functions, ["DiscardPowerReportDraft"])
            java_sources = {
                "PlatformInterface": (
                    "public interface PlatformInterface {\n"
                    "boolean usePlatformAutoRedirect();\n"
                    "AutoRedirectSession createAutoRedirect(byte[] options, "
                    "AutoRedirectHandler handler) throws Exception;\n}"
                ),
                "AutoRedirectHandler": "public interface AutoRedirectHandler {}",
                "AutoRedirectSession": "public interface AutoRedirectSession {}",
                "Libbox": (
                    "public class Libbox {\npublic static int calls;\n"
                    + "\n".join(f"public static void {name[0].lower() + name[1:]}() "
                                "{ calls++; }" for name in report_functions)
                    + "\n}"
                ),
            }
            for name, source in java_sources.items():
                (root / f"{name}.java").write_text("package io.nekohasekai.libbox;\n" + source)
            classes = root / "classes"
            subprocess.run([str(java_home / "bin/javac"), "-d", str(classes),
                            *map(str, sorted(root.glob("*.java")))], check=True)
            bg = app / "app/src/main/java/io/nekohasekai/sfa/bg"
            wrapper = (bg / "PlatformInterfaceWrapper.kt").read_text()
            overrides = re.findall(
                r"    override fun (?:usePlatformAutoRedirect|createAutoRedirect)\b[^\n]*"
                r"(?:\n        [^\n]*|\n    \})*", wrapper,
            )
            box = (bg / "BoxService.kt").read_text()
            calls = re.findall(r"Libbox\.\w*PowerReportDraft\(\)", box)
            self.assertEqual(len(calls), 2)
            for name in ("ProxyService", "VPNService"):
                self.assertIn("PlatformInterfaceWrapper", (bg / f"{name}.kt").read_text())
            seam = root / "Seam.kt"
            seam.write_text(
                "import io.nekohasekai.libbox.*\n"
                "interface PlatformInterfaceWrapper : PlatformInterface {\n"
                + "\n".join(overrides) + "\n}\n"
                "class ProxyService : PlatformInterfaceWrapper\n"
                "class VPNService : PlatformInterfaceWrapper\n"
                "fun main() {\n"
                + "\n".join(calls) + "\n"
                "check(Libbox.calls == 2)\n"
                "for (service in listOf(ProxyService(), VPNService())) {\n"
                "check(!service.usePlatformAutoRedirect())\n"
                "try {\n"
                "service.createAutoRedirect(byteArrayOf(), object : AutoRedirectHandler {})\n"
                'error("Unsupported auto-redirect unexpectedly succeeded")\n'
                "} catch (expected: UnsupportedOperationException) {\n"
                'check(expected.message == "Platform auto-redirect is not supported by this build")\n'
                "}\n}\n}\n"
            )
            compiler = [str(java_home / "bin/java"), "-Xmx512m", "-cp",
                        str(KOTLIN_HOME / "lib/*"), "org.jetbrains.kotlin.cli.jvm.K2JVMCompiler"]
            version = subprocess.run([*compiler, "-version"], text=True, capture_output=True,
                                     check=True)
            self.assertIn("kotlinc-jvm " + prepare.MANIFEST["toolchain"]["kotlin"],
                          version.stdout + version.stderr)
            result = subprocess.run(
                [*compiler, "-no-stdlib", "-no-reflect", "-jvm-target", "17",
                 "-classpath", os.pathsep.join((str(classes),
                                               str(KOTLIN_HOME / "lib/kotlin-stdlib.jar"))),
                 "-d", str(root / "seam.jar"), str(seam)],
                text=True, capture_output=True,
            )
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
            subprocess.run(
                [str(java_home / "bin/java"), "-cp",
                 os.pathsep.join((str(root / "seam.jar"), str(classes),
                                  str(KOTLIN_HOME / "lib/kotlin-stdlib.jar"))), "SeamKt"],
                check=True,
            )
            print("Pinned Kotlin ABI seam compiles; both services reject unsupported auto-redirect")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--core-source", required=True, type=Path)
    parser.add_argument("--app-source", required=True, type=Path)
    parser.add_argument("--kotlin-home", type=Path,
                        help="Optional Kotlin compiler distribution; requires JAVA_HOME (JDK 17)")
    args, remaining = parser.parse_known_args()
    CORE_SOURCE = args.core_source.resolve()
    APP_SOURCE = args.app_source.resolve()
    KOTLIN_HOME = args.kotlin_home.resolve() if args.kotlin_home else None
    unittest.main(argv=[__file__, *remaining])
