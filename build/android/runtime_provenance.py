#!/usr/bin/env python3
"""Validate and archive explicitly captured evidence in a trusted, idle workspace."""
import hashlib
import html
import io
import json
import os
from pathlib import Path
import re
import struct
import sys
import tarfile
import tempfile
from urllib.parse import unquote, urlsplit
import zipfile
import zlib

from prepare import require


DEFAULT_LIMITS = {
    "archive_members": 100000, "capture_members": 500000,
    "member_bytes": 128 * 1024**2, "archive_bytes": 512 * 1024**2,
    "capture_bytes": 2 * 1024**3, "evidence_bytes": 2 * 1024**3,
    "notice_member_bytes": 1024**2, "notice_bytes": 32 * 1024**2,
    "graph_bytes": 32 * 1024**2,
    "archive_depth": 8, "archive_directory_bytes": 16 * 1024**2,
    "capture_directory_bytes": 64 * 1024**2,
}
URL = re.compile(r"(?<![a-z0-9+.-])[a-z][a-z0-9+.-]*://[^\s<>\"'`\\]+", re.I | re.ASCII)
SECRET_KEY = re.compile(
    r"(?:^|[_ -])(?:secret|token|password|passwd|pwd|credential|credentials|auth|authorization|"
    r"signature|sig|key|apikey|accesskey|privatekey|accesstoken|authtoken)(?:$|[_ -])", re.I)


def safe_path(path, root=None):
    path = Path(os.path.abspath(path))
    require(not any(part == ".." for part in Path(path).parts), "Unsafe evidence path")
    for ancestor in reversed((path, *path.parents)):
        require(not ancestor.is_symlink(), "Evidence path has symlink ancestor")
    if root is not None:
        require(path.is_relative_to(root), "Evidence path escapes capture")
    return path


def prepare_capture(capture):
    capture = safe_path(capture)
    for name in ("files", "notices", "index.json", "graph.json", "graph.pending.json"):
        safe_path(capture / name, capture)
    # Only the two graph files are owned outputs; never recursively clean a tree.
    for name in ("graph.json", "graph.pending.json"):
        path = capture / name
        if path.exists():
            require(path.is_file(), "Invalid graph output")
            path.unlink()


class Budget:
    def __init__(self):
        overrides = json.loads(os.environ.get("RUNTIME_PROVENANCE_LIMITS", "{}"))
        require(isinstance(overrides, dict) and overrides.keys() <= DEFAULT_LIMITS.keys(),
                "Invalid runtime limits")
        self.limits = DEFAULT_LIMITS | overrides
        require(all(type(n) is int and n > 0 for n in self.limits.values()), "Invalid runtime limits")
        self.used = {}

    def check(self, key, count):
        if count > self.limits[key]:
            raise EvidenceLimit("Runtime evidence limit exceeded: " + key)

    def add(self, key, count):
        self.used[key] = self.used.get(key, 0) + count
        self.check(key, self.used[key])


class UnsafeEvidence(ValueError):
    pass


class EvidenceLimit(ValueError):
    pass


def check_urls(text):
    text = re.sub(r"\\u00([0-9a-fA-F]{2})",
                  lambda match: chr(int(match[1], 16)), text)
    text = html.unescape(text.replace("\\/", "/").replace("\x00", ""))
    for match in URL.finditer(text):
        url = match.group()
        require(len(url) < 65536, "Runtime evidence URL scan limit exceeded")
        try:
            parsed = urlsplit(url)
        except ValueError:
            raise UnsafeEvidence("unparseable evidence URL") from None
        if "@" in parsed.netloc:
            raise UnsafeEvidence("credential-bearing URL")
        for field in re.split(r"[&;]", parsed.query + "&" + parsed.fragment):
            key = unquote(field.split("=", 1)[0]).replace("+", " ")
            key = re.sub(r"([a-z])([A-Z])", r"\1_\2", key)
            if SECRET_KEY.search(key):
                raise UnsafeEvidence("credential-bearing URL")
    return text


def scan(stream, budget, *, archive=False, collect=False, sink=None):
    digest = hashlib.sha256()
    tail = ""
    data = bytearray() if collect else None
    count = 0
    unsafe = None
    while chunk := stream.read(65536):
        count += len(chunk)
        if archive:
            budget.check("member_bytes", count)
        budget.add("capture_bytes", len(chunk))
        digest.update(chunk)
        text = tail + chunk.decode("latin1")
        try:
            text = check_urls(text)
        except UnsafeEvidence as error:
            unsafe = error
        tail = text[-65536:]
        if collect:
            data.extend(chunk)
        if sink is not None:
            sink.write(chunk)
    return digest.hexdigest(), data, unsafe, count


def zip_preflight(stream, budget, depth, expected=False):
    def valid(condition):
        if not condition:
            raise UnsafeEvidence("Invalid or unsupported ZIP evidence")

    stream.seek(0, os.SEEK_END)
    length = stream.tell()
    stream.seek(0)
    magic = stream.read(4)
    tail_start = max(0, length - 65557)
    stream.seek(tail_start)
    tail = stream.read(65557)
    end = tail.rfind(b"PK\x05\x06")
    if end < 0:
        valid(not expected and magic not in (b"PK\x03\x04", b"PK\x05\x06",
                                            b"PK\x07\x08", b"PK\x06\x06"))
        return None
    valid(len(tail) - end >= 22)
    _, disk, directory_disk, disk_count, count, size, offset, comment = struct.unpack_from(
        "<4s4H2IH", tail, end)
    eocd = tail_start + end
    valid(end + 22 + comment == len(tail))
    valid(disk == directory_disk == 0 and disk_count == count)
    valid(count != 0xffff and size != 0xffffffff and offset != 0xffffffff)
    valid(offset + size == eocd and count * 46 <= size)
    if eocd >= 20:
        stream.seek(eocd - 20)
        valid(stream.read(4) != b"PK\x06\x07")
    budget.check("archive_depth", depth)
    budget.check("archive_members", count)
    budget.check("capture_members", budget.used.get("capture_members", 0) + count)
    budget.check("archive_directory_bytes", size)
    budget.add("capture_directory_bytes", size)
    # Count actual records without allocating ZipInfo objects or trusting the EOCD count.
    position = offset
    actual = 0
    while position < eocd:
        valid(eocd - position >= 46)
        stream.seek(position)
        header = stream.read(46)
        valid(len(header) == 46 and header[:4] == b"PK\x01\x02")
        compressed, uncompressed = struct.unpack_from("<II", header, 20)
        name, extra, note, start_disk = struct.unpack_from("<4H", header, 28)
        local = struct.unpack_from("<I", header, 42)[0]
        valid(start_disk == 0 and 0xffffffff not in (compressed, uncompressed, local))
        valid(local < offset)
        following = position + 46 + name + extra + note
        valid(following <= eocd)
        stream.seek(position + 46 + name)
        remaining = extra
        while remaining:
            valid(remaining >= 4)
            field, field_size = struct.unpack("<HH", stream.read(4))
            valid(field != 1 and field_size <= remaining - 4)
            stream.seek(field_size, os.SEEK_CUR)
            remaining -= 4 + field_size
        actual += 1
        budget.check("archive_members", actual)
        budget.add("capture_members", 1)
        position = following
    valid(actual == count)
    return actual


def inspect_zip(stream, budget, depth=1, prefix="", expected=False):
    count = zip_preflight(stream, budget, depth, expected)
    notices = []
    unsafe = None
    if count is not None:
        stream.seek(0)
        with zipfile.ZipFile(stream) as source:
            members = source.infolist()
            require(len(members) == count, "Invalid ZIP directory count")
            budget.check("archive_members", len(members))
            budget.check("archive_bytes", sum(m.file_size for m in members))
            budget.check("capture_bytes", budget.used.get("capture_bytes", 0) +
                         sum(m.file_size for m in members))
            actual = 0
            for member in members:
                budget.check("member_bytes", member.file_size)
                try:
                    check_urls(member.filename)
                except UnsafeEvidence as problem:
                    unsafe = unsafe or problem
                if member.is_dir():
                    continue
                notice = Path(member.filename).name.upper().split(".")[0] in {
                    "LICENSE", "NOTICE", "COPYING", "COPYRIGHT"}
                if notice:
                    budget.check("notice_member_bytes", member.file_size)
                    budget.add("notice_bytes", member.file_size)
                with tempfile.TemporaryFile() as nested, source.open(member) as member_stream:
                    member_hash, data, problem, count = scan(
                        member_stream, budget, archive=True, collect=notice, sink=nested)
                    require(count == member.file_size, "Invalid archive member size")
                    embedded, nested_problem = inspect_zip(
                        nested, budget, depth + 1, prefix + member.filename + "!/",
                        Path(member.filename).suffix.lower() in {".zip", ".jar", ".aar"})
                    notices.extend(embedded)
                    unsafe = unsafe or nested_problem
                actual += count
                budget.check("archive_bytes", actual)
                unsafe = unsafe or problem
                if notice:
                    notices.append((prefix + member.filename, member_hash, bytes(data)))
    return notices, unsafe


def inspect(path, budget):
    budget.add("evidence_bytes", path.stat().st_size)
    with path.open("rb") as stream:
        digest, _, unsafe, _ = scan(stream, budget)
        try:
            notices, problem = inspect_zip(stream, budget)
            unsafe = unsafe or problem
        except (UnsafeEvidence, EvidenceLimit) as problem:
            notices, unsafe = [], unsafe or UnsafeEvidence(str(problem))
        except (zipfile.BadZipFile, NotImplementedError, RuntimeError, EOFError, zlib.error):
            notices, unsafe = [], UnsafeEvidence("Invalid or unsupported ZIP evidence")
    return digest, notices, unsafe


def load_capture(capture, budget, graph_name="graph.json"):
    capture = safe_path(capture)
    for name in ("files", "notices", "index.json"):
        safe_path(capture / name, capture)
    graph = safe_path(capture / graph_name, capture)
    require(graph.is_file(), "Same-build runtime graph missing")
    budget.check("graph_bytes", graph.stat().st_size)
    data = graph.read_bytes()
    check_urls(data.decode("utf-8"))
    return capture, graph, json.loads(data)


def evidence_path(capture, entry):
    digest = entry["sha256"]
    require(isinstance(digest, str) and re.fullmatch("[0-9a-f]{64}", digest),
            "Invalid evidence digest")
    require(entry["file"] == f"files/{digest}", "Non-allowlisted evidence path")
    path = safe_path(capture / entry["file"], capture)
    require(path.is_file(), "Captured artifact missing or changed")
    return path


def validate_entries(capture, record, budget, omit_optional=False):
    required = [entry for config in record["configurations"].values()
                for entry in config["artifacts"]] + record["local_aars"]
    checked = {}
    kept = []
    allowed = {}
    notices = []
    missing_notices = []
    for optional, entry in [(False, e) for e in required] + [
            (True, e) for e in record["supplements"]]:
        path = evidence_path(capture, entry)
        digest = entry["sha256"]
        if digest not in checked:
            checked[digest] = inspect(path, budget)
        actual, embedded, unsafe = checked[digest]
        require(actual == digest, "Captured artifact missing or changed")
        if unsafe:
            if optional and omit_optional:
                record["supplemental_missing"].append({
                    "component": entry.get("component"), "kind": entry.get("kind"),
                    "sha256": digest, "reason": str(unsafe)})
                continue
            raise ValueError("Required/public evidence rejected: " + str(unsafe))
        if optional:
            kept.append(entry)
        if entry["file"] in allowed:
            continue
        allowed[entry["file"]] = path
        for member, notice_hash, data in embedded:
            notices.append({"artifact": digest, "member": member, "sha256": notice_hash})
            allowed[f"notices/{notice_hash}"] = data
        if zipfile.is_zipfile(path) and not embedded:
            missing_notices.append({"artifact": digest, "reason": "no allowlisted embedded notice found"})
    if omit_optional:
        record["supplements"] = kept
    return allowed, notices, missing_notices


def sanitize_capture(capture):
    budget = Budget()
    capture, _, record = load_capture(capture, budget, "graph.pending.json")
    validate_entries(capture, record, budget, omit_optional=True)
    graph = safe_path(capture / "graph.json", capture)
    require(not graph.exists(), "Graph output already exists")
    with graph.open("x") as stream:
        stream.write(json.dumps(record, indent=2) + "\n")
    (capture / "graph.pending.json").unlink()


def sha(path):
    with path.open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


def archive(capture, output):
    output = safe_path(output)
    require(not output.exists(), "Runtime archive output already exists")
    budget = Budget()
    capture, graph, record = load_capture(capture, budget)
    require(record["schema"] == 1 and record["mode"] == "build",
            "Fixture graph is not build evidence")
    require(record["assemble_task"] == ":app:assembleOtherRelease", "Wrong captured variant")
    configurations = record["configurations"]
    require("otherReleaseRuntimeClasspath" in configurations and
            any("corelibrarydesugaring" in name.lower() for name in configurations),
            "Runtime/desugaring graph missing")
    require(all(config["components"] and config["edges"] and config["artifacts"]
                for config in configurations.values()), "Empty runtime resolution")
    allowed, notices, missing_notices = validate_entries(capture, record, budget)
    allowed["graph.json"] = graph
    index = {
        "schema": 1, "notices": notices, "missing_notices": missing_notices,
        "notice_policy": "Embedded notices only; absence is not proof no notice obligation exists",
        "files": {name: sha(value) if isinstance(value, Path) else hashlib.sha256(value).hexdigest()
                  for name, value in sorted(allowed.items())},
    }
    allowed["index.json"] = (json.dumps(index, indent=2) + "\n").encode()
    # Publish only after all evidence passes. Cleanup is restricted to our own temp file.
    with tempfile.NamedTemporaryFile(dir=output.parent, prefix=".runtime-", delete=False) as stream:
        temporary = Path(stream.name)
    try:
        with tarfile.open(temporary, "w:gz") as bundle:
            for name, value in sorted(allowed.items()):
                info = tarfile.TarInfo(name)
                info.mode = 0o644
                info.size = value.stat().st_size if isinstance(value, Path) else len(value)
                with value.open("rb") if isinstance(value, Path) else io.BytesIO(value) as stream:
                    bundle.addfile(info, stream)
        os.link(temporary, output)
    finally:
        temporary.unlink()
    return {"archive": output.name, "sha256": sha(output),
            "missing": record["supplemental_missing"], "certified": False}


if __name__ == "__main__":
    try:
        require(len(sys.argv) == 3 and sys.argv[1] in ("--prepare", "--sanitize"),
                "Invalid runtime validator invocation")
        if sys.argv[1] == "--prepare":
            prepare_capture(Path(sys.argv[2]))
        else:
            sanitize_capture(Path(sys.argv[2]))
    except (ValueError, OSError, KeyError, TypeError, zipfile.BadZipFile, RuntimeError):
        # Malformed inputs and OS/ZIP exceptions may contain private paths or evidence.
        sys.exit("Runtime evidence validation failed; no public graph published")
