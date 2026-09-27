#!/usr/bin/env python3
"""Real Gradle synthetic Maven integration; no Android build or APK claim."""
import hashlib
import functools
import http.server
import io
import json
import os
from pathlib import Path
import struct
import subprocess
import tempfile
import tarfile
import threading
import unittest
import zipfile
from unittest.mock import patch

import runtime_provenance

HERE = Path(__file__).resolve().parent


class RuntimeSafety(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix="runtime-safety-")
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.capture = self.root / "capture"
        (self.capture / "files").mkdir(parents=True)
        self.output = self.root / "public.tar.gz"
        self.outside = self.root / "sentinel"
        self.outside.mkdir()
        (self.outside / "keep").write_bytes(b"untouched")

    def evidence(self, data, kind=None):
        digest = hashlib.sha256(data).hexdigest()
        entry = {"file": f"files/{digest}", "sha256": digest, "name": "fixture"}
        (self.capture / entry["file"]).write_bytes(data)
        config = {"components": ["fixture"], "edges": ["fixture"], "artifacts": [entry]}
        record = {"schema": 1, "mode": "build", "assemble_task": ":app:assembleOtherRelease",
                  "configurations": {"otherReleaseRuntimeClasspath": config,
                                     "coreLibraryDesugaring": config},
                  "supplements": [], "local_aars": [], "supplemental_missing": []}
        if kind:
            entry["kind"] = kind
        (self.capture / "graph.json").write_text(json.dumps(record))
        return record, entry

    def zipped(self, members):
        stream = io.BytesIO()
        with zipfile.ZipFile(stream, "w", zipfile.ZIP_DEFLATED) as archive:
            for name, data in members:
                archive.writestr(name, data)
        return stream.getvalue()

    def rejected(self, message=""):
        with self.assertRaisesRegex(ValueError, message):
            runtime_provenance.archive(self.capture, self.output)
        self.assertFalse(self.output.exists())
        self.assertEqual((self.outside / "keep").read_bytes(), b"untouched")

    def test_files_ancestor_rejected_before_read(self):
        _, entry = self.evidence(b"outside evidence")
        file = self.capture / entry["file"]
        file.rename(self.outside / file.name)
        file.parent.rmdir()
        file.parent.symlink_to(self.outside, target_is_directory=True)
        original = Path.open
        def guarded(path, *args, **kwargs):
            self.assertFalse(path == file, "attempted outside evidence read")
            return original(path, *args, **kwargs)
        with patch.object(Path, "open", guarded):
            self.rejected("symlink")

    def test_notice_ancestor_rejected_without_outside_write(self):
        self.evidence(self.zipped([("LICENSE", b"license")]))
        (self.capture / "notices").symlink_to(self.outside, target_is_directory=True)
        self.rejected("symlink")
        self.assertEqual(sorted(p.name for p in self.outside.iterdir()), ["keep"])

    def test_root_and_output_ancestors_rejected(self):
        self.evidence(b"ordinary")
        original = self.capture
        link = self.root / "linked"
        link.symlink_to(original, target_is_directory=True)
        self.capture = link
        self.rejected("symlink")
        self.capture = original
        self.output = link / "public.tar.gz"
        self.rejected("symlink")
        self.output = self.root / "public.tar.gz"
        self.output.symlink_to(self.outside / "keep")
        with self.assertRaisesRegex(ValueError, "symlink"):
            runtime_provenance.archive(self.capture, self.output)
        self.assertEqual((self.outside / "keep").read_bytes(), b"untouched")

    def test_raw_metadata_and_source_credentials_fail_closed(self):
        for data in (b'<project><url>https://example.invalid/?token=fixture-secret</url></project>',
                     b'{"origin":"https://user:fixture-secret@example.invalid/source"}',
                     self.zipped([("Example.java",
                                   b'// https://example.invalid/?api_key=fixture-secret')])):
            with self.subTest(data_type=data[:8]):
                self.evidence(data)
                with self.assertRaises(ValueError) as raised:
                    runtime_provenance.archive(self.capture, self.output)
                self.assertNotIn("fixture-secret", str(raised.exception))
                self.assertFalse(self.output.exists())

    def test_credential_url_encodings_and_chunk_boundary(self):
        for url in (b"https://example.invalid/?accessToken=fixture-secret",
                    b"https://example.invalid/?api%5fkey=fixture-secret",
                    b"https:\\/\\/example.invalid/?page=1&amp;client_secret=fixture-secret",
                    b"https\\u003a//example.invalid/?token=fixture-secret",
                    "https://example.invalid/?password=fixture-secret".encode("utf-16-le")):
            with self.subTest(encoding=url[:12]):
                self.evidence(b" " * 65520 + url)
                self.rejected("credential")

    def test_graph_credential_rejected(self):
        record, _ = self.evidence(b"ordinary")
        record["untrusted"] = "https://example.invalid/?secret=fixture-secret"
        (self.capture / "graph.json").write_text(json.dumps(record))
        self.rejected("credential")

    def test_prepare_does_not_follow_symlinks_or_remove_unowned_files(self):
        self.evidence(b"ordinary")
        (self.capture / "keep").write_bytes(b"owned by someone else")
        runtime_provenance.prepare_capture(self.capture)
        self.assertEqual((self.capture / "keep").read_bytes(), b"owned by someone else")
        (self.capture / "graph.json").symlink_to(self.outside / "keep")
        with self.assertRaisesRegex(ValueError, "symlink"):
            runtime_provenance.prepare_capture(self.capture)
        self.assertEqual((self.outside / "keep").read_bytes(), b"untouched")

    def test_safe_source_bytes_and_hashes_unchanged(self):
        data = self.zipped([("Example.java", b'String token = "public"; // https://example.invalid/?page=2'),
                            ("LICENSE", b"ordinary license")])
        _, entry = self.evidence(data)
        runtime_provenance.archive(self.capture, self.output)
        with tarfile.open(self.output) as archive:
            self.assertEqual(archive.extractfile(entry["file"]).read(), data)
            index = json.load(archive.extractfile("index.json"))
            self.assertEqual(index["files"][entry["file"]], hashlib.sha256(data).hexdigest())

    def test_compression_bomb_aggregate_rejected_before_publication(self):
        self.evidence(self.zipped([(f"{i}/LICENSE", b"x" * 1024) for i in range(16)]))
        with patch.dict(os.environ, {"RUNTIME_PROVENANCE_LIMITS": '{"archive_bytes":8192}'}):
            self.rejected("limit")
        self.assertFalse((self.capture / "notices").exists())

    def test_member_count_and_capture_work_limits(self):
        for limits in ('{"archive_members":2}', '{"capture_bytes":2048}',
                       '{"notice_bytes":2048}', '{"member_bytes":512}',
                       '{"capture_members":2}'):
            with self.subTest(limits=limits):
                self.evidence(self.zipped([(f"{i}/LICENSE", bytes([65+i]) * 1024)
                                          for i in range(4)]))
                with patch.dict(os.environ, {"RUNTIME_PROVENANCE_LIMITS": limits}):
                    self.rejected("limit")

    def test_limits_across_archives_and_no_partial_output(self):
        record, _ = self.evidence(self.zipped([("LICENSE", b"a" * 1024)]))
        data = self.zipped([("NOTICE", b"b" * 1024)])
        digest = hashlib.sha256(data).hexdigest()
        (self.capture / "files" / digest).write_bytes(data)
        record["supplements"].append({"file": f"files/{digest}", "sha256": digest})
        (self.capture / "graph.json").write_text(json.dumps(record))
        with patch.dict(os.environ, {"RUNTIME_PROVENANCE_LIMITS": '{"notice_bytes":1536}'}):
            self.rejected("limit")
        self.assertFalse(list(self.root.glob(".runtime-*")))
        self.assertFalse((self.capture / "index.json").exists())

    def test_actual_stream_work_is_bounded(self):
        for limits in ('{"capture_bytes":65536}', '{"member_bytes":65536}'):
            with self.subTest(limits=limits), patch.dict(
                    os.environ, {"RUNTIME_PROVENANCE_LIMITS": limits}):
                stream = io.BytesIO(b"x" * (256 * 1024))
                with self.assertRaisesRegex(ValueError, "limit"):
                    runtime_provenance.scan(stream, runtime_provenance.Budget(),
                                            archive=True, collect=True)
                self.assertEqual(stream.tell(), 128 * 1024)

    def test_existing_output_is_not_overwritten(self):
        self.evidence(b"ordinary")
        self.output.write_bytes(b"prior evidence")
        with self.assertRaisesRegex(ValueError, "already exists"):
            runtime_provenance.archive(self.capture, self.output)
        self.assertEqual(self.output.read_bytes(), b"prior evidence")

    def nested_sources(self):
        return self.zipped([("sources.jar", self.zipped([
            ("Example.java", b"// https://example.invalid/?token=INDEPENDENT_SYNTHETIC_CANARY")
        ]))])

    def pending(self, record):
        runtime_provenance.prepare_capture(self.capture)
        (self.capture / "graph.pending.json").write_text(json.dumps(record))

    def optional(self, data):
        record, _ = self.evidence(b"safe runtime")
        digest = hashlib.sha256(data).hexdigest()
        entry = {"file": f"files/{digest}", "sha256": digest, "kind": "sources"}
        (self.capture / entry["file"]).write_bytes(data)
        record["supplements"].append(entry)
        return record, entry

    def test_nested_credentials_required(self):
        record, _ = self.evidence(self.nested_sources())
        self.pending(record)
        with self.assertRaisesRegex(ValueError, "credential-bearing URL") as raised:
            runtime_provenance.sanitize_capture(self.capture)
        self.assertNotIn("INDEPENDENT_SYNTHETIC_CANARY", str(raised.exception))
        self.assertFalse((self.capture / "graph.json").exists())
        self.assertFalse(self.output.exists())

    def test_nested_credentials_optional(self):
        record, entry = self.optional(self.nested_sources())
        self.pending(record)
        runtime_provenance.sanitize_capture(self.capture)
        sanitized = json.loads((self.capture / "graph.json").read_text())
        self.assertEqual(sanitized["supplements"], [])
        self.assertEqual(sanitized["supplemental_missing"], [{
            "component": None, "kind": "sources", "sha256": entry["sha256"],
            "reason": "credential-bearing URL"}])
        runtime_provenance.archive(self.capture, self.output)
        with tarfile.open(self.output) as bundle:
            self.assertNotIn(entry["file"], bundle.getnames())

    def assert_preflight_rejects(self, data, limits, message, expected_objects=0):
        self.output.unlink(missing_ok=True)
        _, entry = self.evidence(data)
        created = []
        original = zipfile.ZipInfo.__init__
        def counted(instance, *args, **kwargs):
            created.append(1)
            original(instance, *args, **kwargs)
        with patch.dict(os.environ, {"RUNTIME_PROVENANCE_LIMITS": json.dumps(limits)}), \
                patch.object(zipfile.ZipInfo, "__init__", counted):
            with self.assertRaisesRegex(ValueError, message):
                runtime_provenance.archive(self.capture, self.output)
        self.assertEqual(len(created), expected_objects)
        self.assertFalse(self.output.exists())
        self.assertEqual(hashlib.sha256(data).hexdigest(), entry["sha256"])

    def test_directory_preallocation_exact_review(self):
        data = self.zipped([(str(i), b"") for i in range(5000)])
        self.assertEqual(len(data), 427802)
        self.assert_preflight_rejects(data, {"archive_members": 2}, "archive_members")

    def test_directory_count_mismatch(self):
        data = self.zipped([(str(i), b"") for i in range(5000)])
        spoofed = bytearray(data)
        struct.pack_into("<HH", spoofed, len(spoofed) - 22 + 8, 1, 1)
        self.assert_preflight_rejects(bytes(spoofed), {"archive_members": 2}, "ZIP|limit")
        for count in (0, 2):
            data = bytearray(self.zipped([("one", b"")]))
            struct.pack_into("<HH", data, len(data) - 22 + 8, count, count)
            self.assert_preflight_rejects(bytes(data), {}, "ZIP")

    def test_directory_bytes_before_allocation(self):
        data = self.zipped([("long/" * 1000, b"")])
        self.assert_preflight_rejects(data, {"archive_directory_bytes": 128},
                                     "archive_directory_bytes")
        self.assert_preflight_rejects(data, {"capture_directory_bytes": 128},
                                     "capture_directory_bytes")

    def test_unsupported_and_malformed_zip(self):
        normal = self.zipped([("one", b"")])
        mutations = []
        for offset, fmt, value in ((4, "<H", 1), (6, "<H", 1), (8, "<H", 0xffff),
                                   (12, "<I", 0xffffffff), (16, "<I", 0xffffffff),
                                   (20, "<H", 1)):
            data = bytearray(normal)
            struct.pack_into(fmt, data, len(data) - 22 + offset, value)
            mutations.append(bytes(data))
        data = bytearray(normal)
        central = data.index(b"PK\x01\x02")
        struct.pack_into("<H", data, central + 28, 0xffff)
        mutations.extend((bytes(data), normal[:-22], b"PK\x03\x04malformed"))
        buffer = io.BytesIO()
        with zipfile.ZipFile(buffer, "w") as archive:
            info = zipfile.ZipInfo("zip64")
            info.extra = struct.pack("<HHQQ", 1, 16, 0, 0)
            archive.writestr(info, b"")
        mutations.append(buffer.getvalue())
        mutations.append(normal[:-22] + b"PK\x06\x07" + bytes(16) + normal[-22:])
        for data in mutations:
            with self.subTest(case=len(data)):
                self.assert_preflight_rejects(data, {}, "ZIP")

    def test_nested_preflight_and_shared_limits(self):
        jar = self.zipped([("one", b""), ("two", b""), ("three", b"")])
        data = self.zipped([("classes.jar", jar)])
        self.assert_preflight_rejects(data, {"archive_members": 2}, "archive_members", 1)
        jar = self.zipped([("long/" * 1000, b"")])
        data = self.zipped([("classes.jar", jar)])
        self.assert_preflight_rejects(data, {"archive_directory_bytes": 128},
                                     "archive_directory_bytes", 1)
        jar = self.zipped([("Example.java", b"x" * 1024)])
        data = self.zipped([("one.jar", jar), ("two.jar", jar)])
        for limits, message in (({"capture_members": 3}, "capture_members"),
                                ({"member_bytes": 512}, "member_bytes"),
                                ({"archive_bytes": 512}, "archive_bytes"),
                                ({"capture_bytes": len(data) + 2 * len(jar) + 1024},
                                 "capture_bytes"),
                                ({"capture_directory_bytes": 200},
                                 "capture_directory_bytes")):
            with self.subTest(limits=limits):
                self.evidence(data)
                with patch.dict(os.environ, {"RUNTIME_PROVENANCE_LIMITS": json.dumps(limits)}):
                    self.rejected(message)
        data = self.zipped([("one.jar", self.zipped([("LICENSE", b"a" * 1024)])),
                            ("two.jar", self.zipped([("NOTICE", b"b" * 1024)]))])
        self.evidence(data)
        with patch.dict(os.environ, {"RUNTIME_PROVENANCE_LIMITS": '{"notice_bytes":1536}'}):
            self.rejected("notice_bytes")

    def test_nested_depth_and_optional_uninspectable(self):
        data = self.zipped([("Example.java", b"ordinary source")])
        for _ in range(3):
            data = self.zipped([("nested.jar", data)])
        _, entry = self.evidence(data)
        with patch.dict(os.environ, {"RUNTIME_PROVENANCE_LIMITS": '{"archive_depth":4}'}):
            _, _, unsafe = runtime_provenance.inspect(
                self.capture / entry["file"], runtime_provenance.Budget())
            self.assertIsNone(unsafe)
        self.evidence(data)
        with patch.dict(os.environ, {"RUNTIME_PROVENANCE_LIMITS": '{"archive_depth":3}'}):
            self.rejected("archive_depth")
        deep = data
        for _ in range(5):
            deep = self.zipped([("nested.jar", deep)])
        self.evidence(deep)
        self.rejected("archive_depth")
        for data in (data, self.zipped([("sources.jar", b"PK\x03\x04broken")])):
            record, entry = self.optional(data)
            self.pending(record)
            with patch.dict(os.environ, {"RUNTIME_PROVENANCE_LIMITS": '{"archive_depth":3}'}):
                runtime_provenance.sanitize_capture(self.capture)
            sanitized = json.loads((self.capture / "graph.json").read_text())
            self.assertEqual(sanitized["supplements"], [])
            self.assertEqual(sanitized["supplemental_missing"][0]["sha256"], entry["sha256"])
            self.assertRegex(sanitized["supplemental_missing"][0]["reason"], "ZIP|archive_depth")

    def test_normal_zip_comments_empty_and_data_descriptors(self):
        class Unseekable(io.BytesIO):
            def seek(self, *args):
                raise OSError("unseekable fixture")
        stream = Unseekable()
        with zipfile.ZipFile(stream, "w", zipfile.ZIP_DEFLATED) as archive:
            archive.comment = b"ordinary archive comment"
            archive.writestr("Example.java", b"class Example {}")
        for data in (stream.getvalue(), self.zipped([])):
            _, entry = self.evidence(data)
            digest, _, unsafe = runtime_provenance.inspect(
                self.capture / entry["file"], runtime_provenance.Budget())
            self.assertEqual(digest, entry["sha256"])
            self.assertIsNone(unsafe)

    def test_safe_aar_classes_and_source_jars_unchanged(self):
        classes = self.zipped([("example/Example.class", b"\xca\xfe\xba\xbe"),
                               ("META-INF/LICENSE", b"nested license")])
        sources = self.zipped([("example/Example.java",
                               b"// https://example.invalid/?page=2\nclass Example {}")])
        data = self.zipped([("AndroidManifest.xml", b"<manifest/>"),
                            ("classes.jar", classes), ("libs/sources.jar", sources)])
        record, entry = self.evidence(data)
        self.pending(record)
        runtime_provenance.sanitize_capture(self.capture)
        runtime_provenance.archive(self.capture, self.output)
        with tarfile.open(self.output) as bundle:
            self.assertEqual(bundle.extractfile(entry["file"]).read(), data)
            index = json.load(bundle.extractfile("index.json"))
            self.assertEqual(index["files"][entry["file"]], hashlib.sha256(data).hexdigest())
            self.assertEqual(len(index["notices"]), 1)
            self.assertEqual(index["notices"][0]["member"], "classes.jar!/META-INF/LICENSE")


class RuntimeCapture(unittest.TestCase):
    @unittest.skipUnless(os.environ.get("GRADLE"), "Set GRADLE for the real Gradle fixture")
    def test_same_resolution_and_missing_policy(self):
        with tempfile.TemporaryDirectory(prefix="runtime-fixture-") as temporary:
            root = Path(temporary)
            (root / "settings.gradle").write_text("rootProject.name='fixture'\ninclude ':app'\n")
            app = root / "app"
            app.mkdir()
            for name, version, dependency in (("leaf", "1", ""), ("leaf", "2", ""),
                                             ("parent", "1", "<dependencies><dependency>"
                                              "<groupId>example</groupId><artifactId>leaf</artifactId>"
                                              "<version>1</version></dependency></dependencies>")):
                module = root / "repo/example" / name / version
                module.mkdir(parents=True)
                (module / f"{name}-{version}.pom").write_text(
                    f"<project><modelVersion>4.0.0</modelVersion><groupId>example</groupId>"
                    f"<artifactId>{name}</artifactId><version>{version}</version>{dependency}</project>")
                with zipfile.ZipFile(module / f"{name}-{version}.jar", "w") as jar:
                    jar.writestr("LICENSE", "Synthetic fixture license\n")
                if name == "parent":
                    with zipfile.ZipFile(module / f"{name}-{version}-sources.jar", "w") as jar:
                        jar.writestr("Example.java", "// Synthetic source\n")
                if name == "leaf" and version == "2":
                    pom = module / f"{name}-{version}.pom"
                    pom.write_text(pom.read_text().replace("<project>", "<project>"
                                   "<!-- do_not_remove: published-with-gradle-metadata -->"
                                   "<url>https://example.invalid/?secret=fixture-pom-secret</url>"))
                    with zipfile.ZipFile(module / f"{name}-{version}-sources.jar", "w") as jar:
                        jar.writestr("Example.java",
                                     "// https://example.invalid/?token=fixture-source-secret")
                    artifact = module / "leaf-2.jar"
                    (module / "leaf-2.module").write_text(json.dumps({
                        "formatVersion": "1.1",
                        "component": {"group": "example", "module": "leaf", "version": "2"},
                        "variants": [{"name": "runtime", "attributes": {
                            "org.gradle.usage": "java-runtime",
                            "fixture.origin": "https://user:password@example.invalid/source?token=fixture-module-secret"},
                                      "files": [{"name": artifact.name, "url": artifact.name,
                                                 "size": artifact.stat().st_size,
                                                 "sha256": hashlib.sha256(artifact.read_bytes()).hexdigest()}]}]
                    }))
            (app / "libs").mkdir()
            (app / "libs/libbox.aar").write_bytes(b"synthetic local AAR")
            server = http.server.ThreadingHTTPServer(("127.0.0.1", 0),
                functools.partial(http.server.SimpleHTTPRequestHandler, directory=str(root / "repo")))
            self.addCleanup(server.server_close)
            self.addCleanup(server.shutdown)
            threading.Thread(target=server.serve_forever, daemon=True).start()
            (app / "build.gradle").write_text("""
repositories { maven { url = 'FIXTURE_URL'; allowInsecureProtocol = true } }
configurations { otherReleaseRuntimeClasspath; coreLibraryDesugaring }
dependencies {
    otherReleaseRuntimeClasspath 'example:parent:1'
    otherReleaseRuntimeClasspath 'example:leaf:2'
    otherReleaseRuntimeClasspath files('libs/libbox.aar')
    coreLibraryDesugaring 'example:leaf:2'
}
tasks.register('assembleOtherRelease') {
    doLast {
        configurations.coreLibraryDesugaring.files
        file('assembled.txt').text = configurations.otherReleaseRuntimeClasspath.files
            .collect { it.name }.sort().join('\\n')
    }
}
""".replace("FIXTURE_URL", f"http://127.0.0.1:{server.server_port}"))
            command = [os.environ["GRADLE"], "--no-daemon", "--console=plain",
                       "-g", str(root / "cache"), "-I", str(HERE / "runtime.init.gradle"),
                       "-PprovenanceFixture=true", ":app:captureOtherReleaseProvenance"]
            run = subprocess.run(command, cwd=root, text=True, capture_output=True, timeout=180)
            self.assertEqual(run.returncode, 0, run.stdout + run.stderr)
            output = app / "build/runtime-provenance"
            record = json.loads((output / "graph.json").read_text())
            self.assertEqual(record["mode"], "fixture")
            runtime = record["configurations"]["otherReleaseRuntimeClasspath"]
            self.assertIn("example:leaf:2", [c["id"] for c in runtime["components"]])
            self.assertNotIn("example:leaf:1", [c["id"] for c in runtime["components"]])
            self.assertTrue(any(e["selected"] == "example:leaf:2" and
                                e["requested"] == "example:leaf:1" for e in runtime["edges"]))
            self.assertEqual(sorted(a["name"] for a in runtime["artifacts"]),
                             (app / "assembled.txt").read_text().splitlines())
            for artifact in runtime["artifacts"]:
                data = (output / artifact["file"]).read_bytes()
                self.assertEqual(hashlib.sha256(data).hexdigest(), artifact["sha256"])
                self.assertIn("attributes", artifact)
            self.assertIn("coreLibraryDesugaring", record["configurations"])
            self.assertTrue(record["supplemental_missing"])
            self.assertTrue(any(s["kind"] == "sources" for s in record["supplements"]))
            self.assertTrue(any(s["kind"] == "pom" for s in record["supplements"]))
            for kind in ("pom", "module", "sources"):
                omitted = [s for s in record["supplemental_missing"]
                           if s.get("kind") == kind and s.get("sha256")]
                self.assertEqual(len(omitted), 1, kind)
                original = root / "repo/example/leaf/2" / (
                    "leaf-2-sources.jar" if kind == "sources" else f"leaf-2.{kind}")
                self.assertEqual(omitted[0]["sha256"],
                                 hashlib.sha256(original.read_bytes()).hexdigest())
                self.assertEqual(omitted[0]["reason"], "credential-bearing URL")
            self.assertNotIn(str(root), (output / "graph.json").read_text())
            self.assertNotIn("password", (output / "graph.json").read_text())
            self.assertNotIn("token=secret", (output / "graph.json").read_text())
            with self.assertRaisesRegex(ValueError, "Fixture"):
                runtime_provenance.archive(output, root / "fixture.tar.gz")
            # Exercise the archive validator with explicitly synthetic data, not a build claim.
            record["mode"] = "build"
            (output / "graph.json").write_text(json.dumps(record))
            runtime_provenance.archive(output, root / "fixture.tar.gz")
            with tarfile.open(root / "fixture.tar.gz") as bundle:
                self.assertTrue(any(n.startswith("notices/") for n in bundle.getnames()))
                self.assertIn("index.json", bundle.getnames())
                self.assertFalse(any("cache" in n for n in bundle.getnames()))
                for member in bundle.getmembers():
                    data = bundle.extractfile(member).read()
                    for secret in (b"fixture-pom-secret", b"fixture-source-secret",
                                   b"fixture-module-secret", b"password"):
                        self.assertNotIn(secret, data)
            (output / runtime["artifacts"][0]["file"]).write_bytes(b"tampered")
            with self.assertRaisesRegex(ValueError, "changed"):
                runtime_provenance.archive(output, root / "bad.tar.gz")
            build = app / "build.gradle"
            original = build.read_text()
            build.write_text(original.replace("configurations.coreLibraryDesugaring.files", ""))
            run = subprocess.run(command, cwd=root, text=True, capture_output=True)
            self.assertNotEqual(run.returncode, 0)
            self.assertIn("not consumed by assemble", run.stdout + run.stderr)
            self.assertFalse((output / "graph.json").exists())
            build.write_text(original)
            # Missing configuration must fail, not produce an empty success graph.
            build.write_text(build.read_text().replace("otherReleaseRuntimeClasspath", "wrongRuntime"))
            run = subprocess.run(command, cwd=root, text=True, capture_output=True)
            self.assertNotEqual(run.returncode, 0)
            self.assertFalse((output / "graph.json").exists())

    def test_missing_capture_fails_closed(self):
        with tempfile.TemporaryDirectory() as temporary:
            with self.assertRaisesRegex(ValueError, "graph missing"):
                runtime_provenance.archive(Path(temporary), Path(temporary) / "output.tar.gz")


if __name__ == "__main__":
    unittest.main()
