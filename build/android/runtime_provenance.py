#!/usr/bin/env python3
"""Validate and archive only explicitly captured public dependency evidence."""
import hashlib
import json
from pathlib import Path
import tarfile
import zipfile

from prepare import require


def archive(capture, output):
    graph = capture / "graph.json"
    require(graph.is_file() and not graph.is_symlink(), "Same-build runtime graph missing")
    record = json.loads(graph.read_text())
    require(record["schema"] == 1 and record["mode"] == "build",
            "Fixture graph is not build evidence")
    require(record["assemble_task"] == ":app:assembleOtherRelease", "Wrong captured variant")
    configurations = record["configurations"]
    require("otherReleaseRuntimeClasspath" in configurations and
            any("corelibrarydesugaring" in name.lower() for name in configurations),
            "Runtime/desugaring graph missing")
    require(all(config["components"] and config["edges"] and config["artifacts"]
                for config in configurations.values()), "Empty runtime resolution")
    entries = [entry for config in configurations.values() for entry in config["artifacts"]]
    entries += record["supplements"] + record["local_aars"]
    allowed = {"graph.json": graph}
    notices = []
    missing_notices = []
    for entry in entries:
        digest = entry["sha256"]
        require(len(digest) == 64 and all(c in "0123456789abcdef" for c in digest),
                "Invalid evidence digest")
        name = f"files/{digest}"
        require(entry["file"] == name, "Non-allowlisted evidence path")
        path = capture / name
        require(path.is_file() and not path.is_symlink() and
                hashlib.sha256(path.read_bytes()).hexdigest() == digest,
                "Captured artifact missing or changed")
        allowed[name] = path
        if zipfile.is_zipfile(path):
            found_notice = False
            with zipfile.ZipFile(path) as source:
                for member in source.infolist():
                    basename = Path(member.filename).name.upper()
                    if (not member.is_dir() and member.file_size <= 1024 * 1024 and
                            basename.split(".")[0] in {"LICENSE", "NOTICE", "COPYING", "COPYRIGHT"}):
                        data = source.read(member)
                        notice_hash = hashlib.sha256(data).hexdigest()
                        destination = capture / "notices" / notice_hash
                        destination.parent.mkdir(exist_ok=True)
                        destination.write_bytes(data)
                        allowed[f"notices/{notice_hash}"] = destination
                        notices.append({"artifact": digest, "member": member.filename,
                                        "sha256": notice_hash})
                        found_notice = True
            if not found_notice:
                missing_notices.append({"artifact": digest, "reason": "no allowlisted embedded notice found"})
    index = capture / "index.json"
    index.write_text(json.dumps({
        "schema": 1, "notices": notices, "missing_notices": missing_notices,
        "notice_policy": "Embedded notices only; absence is not proof no notice obligation exists",
        "files": {name: hashlib.sha256(path.read_bytes()).hexdigest()
                  for name, path in sorted(allowed.items())},
    }, indent=2) + "\n")
    allowed["index.json"] = index
    with tarfile.open(output, "w:gz") as bundle:
        for name, path in sorted(allowed.items()):
            info = bundle.gettarinfo(str(path), arcname=name)
            info.uid = info.gid = 0
            info.uname = info.gname = ""
            with path.open("rb") as stream:
                bundle.addfile(info, stream)
    return {"archive": output.name, "sha256": hashlib.sha256(output.read_bytes()).hexdigest(),
            "missing": record["supplemental_missing"], "certified": False}
