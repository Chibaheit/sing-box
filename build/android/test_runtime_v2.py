#!/usr/bin/env python3
"""Schema-2 publication boundary; retained binaries are optional local evidence."""
import hashlib
import io
import json
import os
from pathlib import Path
import tarfile
import tempfile
import unittest
import zipfile

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
