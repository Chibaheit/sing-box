#!/usr/bin/env python3
"""Real Gradle synthetic Maven integration; no Android build or APK claim."""
import hashlib
import functools
import http.server
import json
import os
from pathlib import Path
import subprocess
import tempfile
import tarfile
import threading
import unittest
import zipfile

import runtime_provenance

HERE = Path(__file__).resolve().parent


class RuntimeCapture(unittest.TestCase):
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
                                   "<!-- do_not_remove: published-with-gradle-metadata -->"))
                    artifact = module / "leaf-2.jar"
                    (module / "leaf-2.module").write_text(json.dumps({
                        "formatVersion": "1.1",
                        "component": {"group": "example", "module": "leaf", "version": "2"},
                        "variants": [{"name": "runtime", "attributes": {
                            "org.gradle.usage": "java-runtime",
                            "fixture.origin": "https://user:password@example.invalid/source?token=secret"},
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
            run = subprocess.run(command, cwd=root, text=True, capture_output=True)
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
            self.assertTrue(any(s["kind"] == "module" for s in record["supplements"]))
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
