#!/usr/bin/env python3
"""Schema-2 publication boundary; retained binaries are optional local evidence."""
import hashlib
import io
import json
import os
from pathlib import Path
import struct
import subprocess
import tarfile
import tempfile
import unittest
import zipfile
from unittest.mock import patch

import runtime_provenance as runtime


class MetadataOnly(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        (self.root / "files").mkdir()

    def record(self, data):
        artifact = dict(component="local:libbox", type="so",
                        sha256=hashlib.sha256(data).hexdigest(), size=len(data))
        config = dict(components=[dict(id="project::app", variants=[])],
                      edges=[], artifacts=[artifact])
        return dict(schema=2, mode="build", gradle="9.7.0",
                    assemble_task=":app:assembleOtherRelease",
                    configurations=dict(otherReleaseRuntimeClasspath=config,
                                        coreLibraryDesugaring=config),
                    local_aars=[artifact], supplements=[], supplemental_missing=[])

    def publish(self, record):
        (self.root / "graph.pending.json").write_text(json.dumps(record))
        runtime.sanitize_capture(self.root)
        output = self.root / "bundle.tar.gz"
        runtime.archive(self.root, output)
        result = runtime.verify_archive(output, runtime.sha(output))
        self.assertEqual(result["schema"], 2)
        with tarfile.open(output) as archive:
            return {m.name: archive.extractfile(m).read() for m in archive}

    def supplement(self, record, data, kind):
        digest = hashlib.sha256(data).hexdigest()
        (self.root / "files" / digest).write_bytes(data)
        record["supplements"].append(dict(component="example:source:1", kind=kind,
            sha256=digest, size=len(data), file="files/" + digest))
        return digest

    def zipped(self, entries):
        stream = io.BytesIO()
        with zipfile.ZipFile(stream, "w", zipfile.ZIP_DEFLATED) as archive:
            for name, data in entries:
                archive.writestr(name, data)
        return stream.getvalue()

    def test_binary_hash_only_no_read_or_publication(self):
        data = b"\x7fELF\x00https://example.invalid/?token=BINARY_CANARY"
        record = self.record(data)
        members = self.publish(record)
        self.assertEqual(set(members), {"graph.json", "index.json"})
        self.assertNotIn(b"BINARY_CANARY", b"".join(members.values()))
        self.assertIn(hashlib.sha256(data).hexdigest().encode(), members["graph.json"])

    @unittest.skipUnless(os.environ.get("RETAINED_NATIVE") and os.environ.get("RETAINED_AAR"),
                         "Set RETAINED_NATIVE and RETAINED_AAR for actual retained-byte probes")
    def test_actual_retained_binary_hashes(self):
        expected = [
            ("RETAINED_NATIVE", "51cc6c5e92f99fdae83be45bd37405e93b03f90f2de53d799fd210214e585a4d", 82125832),
            ("RETAINED_AAR", "2ad334a323b28046e89b738c77d184cb3dcca32a551ab048851b2fda23a3ba26", 1148656),
        ]
        for variable, digest, size in expected:
            data = Path(os.environ[variable]).read_bytes()
            self.assertEqual((hashlib.sha256(data).hexdigest(), len(data)), (digest, size))
            record = self.record(data)
            if variable == "RETAINED_AAR":
                record["local_aars"][0]["type"] = "aar"
            members = self.publish(record)
            self.assertEqual(set(members), {"graph.json", "index.json"})
            (self.root / "graph.json").unlink()
            (self.root / "bundle.tar.gz").unlink()

    def test_metadata_credentials_and_unknown_fields_rejected(self):
        for field, value in [("origin", "https://example.invalid/?token=PRIVATE_CANARY"),
                             ("unknown", "not allowed")]:
            record = self.record(b"binary")
            record[field] = value
            with self.assertRaises(ValueError):
                self.publish(record)
            self.assertFalse((self.root / "graph.json").exists())

    def test_sources_exact_or_omitted_never_rewritten(self):
        record = self.record(b"binary")
        safe = self.zipped([("Example.java", b"class Example {}"), ("LICENSE", b"license")])
        digest = self.supplement(record, safe, "sources")
        for data, kind in [
            (self.zipped([("Example.class", b"\xca\xfe\xba\xbe")]), "sources"),
            (self.zipped([("Example.java", b"// https://x.invalid/?token=PRIVATE_CANARY")]), "sources"),
            (b"-----BEGIN PRIVATE KEY-----\nPRIVATE_CANARY", "pom"),
            (b"https://x.invalid/?token=PRIVATE_CANARY", "module"),
        ]:
            self.supplement(record, data, kind)
        members = self.publish(record)
        self.assertEqual(members["files/" + digest], safe)
        self.assertEqual(len(json.loads(members["graph.json"])["supplemental_missing"]), 4)
        self.assertNotIn(b"PRIVATE_CANARY", b"".join(members.values()))
        self.assertEqual(len([p for p in members if p.startswith("files/")]), 1)

    def test_source_archive_traversal_and_nested_binary_omitted(self):
        record = self.record(b"binary")
        for data in [self.zipped([("../LICENSE", b"notice")]),
                     self.zipped([("nested.jar", self.zipped([("native.so", b"\x7fELF")]))])]:
            self.supplement(record, data, "sources")
        members = self.publish(record)
        self.assertFalse(any(p.startswith("files/") for p in members))
        self.assertEqual(len(json.loads(members["graph.json"])["supplemental_missing"]), 2)

    def assert_omitted(self, data):
        record = self.record(b"binary inventory only")
        digest = self.supplement(record, data, "sources")
        members = self.publish(record)
        (self.root / "graph.json").unlink()
        (self.root / "bundle.tar.gz").unlink()
        self.assertEqual(set(members), {"graph.json", "index.json"})
        graph = json.loads(members["graph.json"])
        self.assertEqual(graph["supplements"], [])
        self.assertEqual(graph["supplemental_missing"], [dict(
            component="example:source:1", kind="sources", sha256=digest,
            reason="rejected_public_material")])

    def inserted(self, data, position, payload, *, local_shift=0, extra=False, compressed=False):
        data = bytearray(data)
        central = data.index(b"PK\x01\x02")
        end = data.rindex(b"PK\x05\x06")
        struct.pack_into("<I", data, end + 16, central + len(payload))
        if local_shift:
            struct.pack_into("<I", data, central + 42, local_shift)
        if extra:
            struct.pack_into("<H", data, 28, len(payload))
        if compressed:
            size = struct.unpack_from("<I", data, central + 20)[0] + len(payload)
            struct.pack_into("<I", data, central + 20, size)
            struct.pack_into("<I", data, 18, size)
        return bytes(data[:position] + payload + data[position:])

    def test_directory_payload_omitted(self):
        for payload in (b"\x7fELFbinary", b"https://x.invalid/?token=DIRECTORY_CANARY"):
            self.assert_omitted(self.zipped([("assets/", payload)]))

    @unittest.skipUnless(os.environ.get("RETAINED_NATIVE") and os.environ.get("RETAINED_AAR"),
                         "Set RETAINED_NATIVE and RETAINED_AAR for exact directory payload probes")
    def test_actual_retained_directory_payloads_omitted(self):
        for variable, digest, size in [
            ("RETAINED_NATIVE", "51cc6c5e92f99fdae83be45bd37405e93b03f90f2de53d799fd210214e585a4d", 82125832),
            ("RETAINED_AAR", "2ad334a323b28046e89b738c77d184cb3dcca32a551ab048851b2fda23a3ba26", 1148656),
        ]:
            data = Path(os.environ[variable]).read_bytes()
            self.assertEqual((hashlib.sha256(data).hexdigest(), len(data)), (digest, size))
            with self.subTest(artifact=variable, size=size):
                self.assert_omitted(self.zipped([("assets/", data)]))

    def test_source_prefix_gaps_trailer_and_local_extra_omitted(self):
        safe = self.zipped([("Example.java", b"class Example {}")])
        central = safe.index(b"PK\x01\x02")
        payload = b"\x7fELF\x00https://x.invalid/?token=LOCAL_EXTRA_CANARY"
        unknown = struct.pack("<HH", 0xbeef, len(payload)) + payload
        for name, data in [
            ("prefix", self.inserted(safe, 0, payload, local_shift=len(payload))),
            ("gap", self.inserted(safe, central, payload)),
            ("trailer", safe + payload),
            ("local-extra", self.inserted(safe, 30 + len("Example.java"), unknown, extra=True)),
            ("compressed-tail", self.inserted(safe, central, payload, compressed=True)),
        ]:
            with self.subTest(container=name):
                self.assert_omitted(data)

    def test_source_local_central_mismatches_omitted(self):
        safe = self.zipped([("Example.java", b"class Example {}")])
        for offset, fmt, value in [(6, "<H", 1), (8, "<H", 0), (10, "<H", 123),
                                   (14, "<I", 0), (18, "<I", 0), (22, "<I", 0)]:
            with self.subTest(offset=offset):
                changed = bytearray(safe)
                struct.pack_into(fmt, changed, offset, value)
                self.assert_omitted(bytes(changed))

    def test_source_notice_allocation_bounded_before_read(self):
        cap = runtime.DEFAULT_LIMITS["notice_member_bytes"]
        temporary_file = tempfile.TemporaryFile
        for name, payload, declared, nested in [
            ("LICENSE", b"x" * (4 * cap), 0, False),
            ("Example.java", b"x" * (4 * cap), 0, False),
            ("LICENSE", b"x" * (4 * cap), 0, True),
            ("Example.java", b"x" * (4 * cap), 0, True),
            ("LICENSE", b"safe notice", 12, False),
            ("LICENSE", b"safe notice", 11, False),
            ("LICENSE", b"x" * (cap + 1), cap + 1, False),
            ("LICENSE", b"x" * cap, cap, False),
            ("LICENSE", b"x" * cap, cap, True),
        ]:
            data = bytearray(self.zipped([(name, payload)]))
            struct.pack_into("<I", data, 22, declared)
            struct.pack_into("<I", data, data.index(b"PK\x01\x02") + 24, declared)
            if len(payload) == 4 * cap and name == "LICENSE":
                self.assertEqual(len(data), 4192)
            if nested:
                data = self.zipped([("nested.jar", data)])
            reads, opened = [], []

            def tracked_file():
                stream = temporary_file()
                opened.append(stream)
                read = stream.read

                def tracked_read(size=-1):
                    reads.append((size, stream.tell(), os.fstat(stream.fileno()).st_size))
                    return read(size)

                stream.read = tracked_read
                return stream

            with self.subTest(name=name, actual=len(payload), declared=declared, nested=nested):
                with patch.object(tempfile, "TemporaryFile", tracked_file):
                    if declared != len(payload) or len(payload) > cap:
                        with self.assertRaises(ValueError):
                            runtime.inspect_zip(io.BytesIO(data), runtime.Budget(),
                                                expected=True, public=True)
                    else:
                        notices, problem = runtime.inspect_zip(
                            io.BytesIO(data), runtime.Budget(), expected=True, public=True)
                        self.assertIsNone(problem)
                        self.assertEqual(notices, [(
                            ("nested.jar!/" if nested else "") + name,
                            hashlib.sha256(payload).hexdigest(), payload)])
                self.assertTrue(all(stream.closed for stream in opened))
                # zipfile's EOF searches use read() after a bounded seek, not at byte zero.
                self.assertTrue(all(0 <= size <= cap + 1 or
                                    (size == -1 and position > 0 and length - position <= 65558)
                                    for size, position, length in reads),
                                f"unbounded/over-cap temporary reads (request, offset, disk bytes): {reads}")

    def test_empty_directory_payload_must_be_valid_and_exhausted(self):
        safe = self.zipped([("assets/", b"")])
        central = safe.index(b"PK\x01\x02")
        self.assert_omitted(self.inserted(safe, central, b"HIDDEN", compressed=True))
        changed = bytearray(safe)
        changed[30 + len("assets/")] ^= 0xff
        self.assert_omitted(bytes(changed))

    def test_ordinary_sources_timestamps_descriptors_and_leaves_byte_exact(self):
        class Unseekable(io.BytesIO):
            def seek(self, *args):
                raise OSError("unseekable fixture")
        leaves = {"example/Example.java": b"package example;\nclass Example {}\n",
                  "META-INF/LICENSE": b"ordinary license\n"}
        for compression in (zipfile.ZIP_STORED, zipfile.ZIP_DEFLATED):
            for descriptors in (False, True):
                stream = Unseekable() if descriptors else io.BytesIO()
                with zipfile.ZipFile(stream, "w", compression) as archive:
                    archive.comment = b"ordinary comment"
                    archive.writestr("example/", b"")
                    for name, contents in leaves.items():
                        info = zipfile.ZipInfo(name)
                        info.compress_type = compression
                        info.extra = struct.pack("<HH", 0xcafe, 0) + struct.pack("<HHBI", 0x5455, 5, 1, 123)
                        archive.writestr(info, contents)
                data = stream.getvalue()
                record = self.record(b"binary")
                digest = self.supplement(record, data, "sources")
                members = self.publish(record)
                self.assertTrue(members["files/" + digest] == data)
                with zipfile.ZipFile(io.BytesIO(members["files/" + digest])) as archive:
                    self.assertEqual({name: archive.read(name) for name in leaves}, leaves)
                (self.root / "graph.json").unlink()
                (self.root / "bundle.tar.gz").unlink()

    def test_source_preflight_budgets_before_zipinfo_allocation(self):
        data = self.zipped([(f"{i}.java", b"source") for i in range(3)])
        with patch.dict(os.environ, {"RUNTIME_PROVENANCE_LIMITS": '{"archive_members":2}'}), \
                patch.object(zipfile.ZipInfo, "__init__", side_effect=AssertionError("allocated")):
            with self.assertRaises(runtime.EvidenceLimit):
                runtime.inspect_zip(io.BytesIO(data), runtime.Budget(), expected=True, public=True)

    def test_timestamp_extra_shapes_and_mismatches(self):
        valid_ntfs = struct.pack("<HHIHHQQQ", 0x000a, 32, 0, 1, 24, 123, 456, 789)
        for extra in (struct.pack("<HH", 0xbeef, 0),
                      struct.pack("<HHB", 0x5455, 1, 8),
                      struct.pack("<HHBI", 0x5455, 5, 0, 123),
                      valid_ntfs[:4] + b"x" + valid_ntfs[5:],
                      valid_ntfs + valid_ntfs):
            stream = io.BytesIO()
            with zipfile.ZipFile(stream, "w") as archive:
                info = zipfile.ZipInfo("Example.java")
                info.extra = extra
                archive.writestr(info, b"class Example {}")
            with self.subTest(extra=extra.hex()):
                self.assert_omitted(stream.getvalue())
        stream = io.BytesIO()
        with zipfile.ZipFile(stream, "w") as archive:
            info = zipfile.ZipInfo("Example.java")
            info.extra = valid_ntfs
            archive.writestr(info, b"class Example {}")
        data = stream.getvalue()
        runtime.inspect_zip(io.BytesIO(data), runtime.Budget(), expected=True, public=True)
        changed = bytearray(data)
        changed[30 + len("Example.java") + 12] ^= 1
        self.assert_omitted(bytes(changed))

    def test_unsigned_descriptor_and_java_timestamp_layout(self):
        class Unseekable(io.BytesIO):
            def seek(self, *args):
                raise OSError("unseekable fixture")
        stream = Unseekable()
        with zipfile.ZipFile(stream, "w", zipfile.ZIP_DEFLATED) as archive:
            archive.writestr("Example.java", b"class Example {}")
        data = bytearray(stream.getvalue())
        descriptor = data.index(b"PK\x07\x08")
        central = data.index(b"PK\x01\x02")
        struct.pack_into("<I", data, len(data) - 6, central - 4)
        del data[descriptor:descriptor + 4]
        runtime.inspect_zip(io.BytesIO(data), runtime.Budget(), expected=True, public=True)
        data[descriptor] ^= 1
        self.assert_omitted(bytes(data))
        stream = io.BytesIO()
        with zipfile.ZipFile(stream, "w") as archive:
            info = zipfile.ZipInfo("Example.java")
            info.extra = struct.pack("<HHBI", 0x5455, 5, 1, 123)
            archive.writestr(info, b"class Example {}")
        data = bytearray(stream.getvalue())
        central = data.index(b"PK\x01\x02")
        # Java writes all available timestamps locally, but only mtime centrally.
        data[30 + len("Example.java") + 4] = 7
        data[central + 46 + len("Example.java") + 4] = 7
        struct.pack_into("<H", data, 30 + len("Example.java") + 2, 13)
        struct.pack_into("<H", data, 28, 17)
        struct.pack_into("<I", data, len(data) - 6, central + 8)
        position = 30 + len("Example.java") + 9
        data[position:position] = struct.pack("<II", 456, 789)
        runtime.inspect_zip(io.BytesIO(data), runtime.Budget(), expected=True, public=True)

    @unittest.skipUnless(os.environ.get("JAVA_HOME"), "Set JAVA_HOME for actual Java sources JAR")
    def test_actual_java_sources_jar(self):
        sources = self.root / "java-sources"
        sources.mkdir()
        contents = b"// ordinary public source\nclass Example {}\n"
        (sources / "Example.java").write_bytes(contents)
        jar = self.root / "ordinary-sources.jar"
        subprocess.run([str(Path(os.environ["JAVA_HOME"]) / "bin/jar"),
                        "--create", "--file", str(jar), "-C", str(sources), "."],
                       check=True, capture_output=True)
        data = jar.read_bytes()
        record = self.record(b"binary")
        digest = self.supplement(record, data, "sources")
        members = self.publish(record)
        self.assertTrue(members["files/" + digest] == data)
        with zipfile.ZipFile(io.BytesIO(members["files/" + digest])) as archive:
            self.assertEqual(archive.read("Example.java"), contents)

    def test_nested_source_limits_and_archive_metadata_canary(self):
        record = self.record(b"binary")
        inner = self.zipped([("Example.java", b"source")])
        for _ in range(9):
            inner = self.zipped([("nested.jar", inner)])
        self.supplement(record, inner, "sources")
        stream = io.BytesIO(self.zipped([("Example.java", b"source")]))
        with zipfile.ZipFile(stream, "a") as archive:
            archive.comment = b"https://x.invalid/?token=PRIVATE_CANARY"
        self.supplement(record, stream.getvalue(), "sources")
        members = self.publish(record)
        self.assertEqual(set(members), {"graph.json", "index.json"})

    def test_verifier_rejects_extra_binary_even_with_updated_index(self):
        members = self.publish(self.record(b"binary"))
        data = b"\x7fELFextra"
        name = "files/" + hashlib.sha256(data).hexdigest()
        members[name] = data
        index = json.loads(members["index.json"])
        index["files"][name] = hashlib.sha256(data).hexdigest()
        members["index.json"] = (json.dumps(index, indent=2) + "\n").encode()
        output = self.root / "tampered.tar.gz"
        with tarfile.open(output, "w:gz") as archive:
            for name, data in members.items():
                item = tarfile.TarInfo(name)
                item.size = len(data)
                archive.addfile(item, io.BytesIO(data))
        with self.assertRaisesRegex(ValueError, "membership"):
            runtime.verify_archive(output, runtime.sha(output))


if __name__ == "__main__":
    unittest.main()
