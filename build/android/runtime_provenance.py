#!/usr/bin/env python3
"""Validate and archive explicitly captured evidence in a trusted, idle workspace."""
import hashlib
import codecs
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
DIAGNOSTIC_MAX_INTEGER = 2**63 - 1
DIAGNOSTIC_PHASES = {
    "invocation", "prepare", "limits", "graph_read", "graph_scan", "graph_decode",
    "entry", "raw_scan", "zip_inspection", "publication",
}
DIAGNOSTIC_REASONS = {
    "invalid_input", "io_error", "unexpected_error", "invalid_zip",
    "credential_url", "unparseable_url", "budget_exceeded",
}
DIAGNOSTIC_FIELDS = {"capture", "graph", "required_artifacts", "supplements"}


def diagnostic_record(context, error):
    if isinstance(error, EvidenceRejected):
        error = error.problem
    reason = (error.reason if isinstance(error, (UnsafeEvidence, EvidenceLimit)) else
              "io_error" if isinstance(error, OSError) else
              "invalid_input" if isinstance(error, (ValueError, KeyError, TypeError)) else
              "unexpected_error")
    phase = getattr(error, "phase", None) or context.get("phase")
    record = {
        "schema": 1,
        "phase": phase if phase in DIAGNOSTIC_PHASES else "invocation",
        "reason": reason if reason in DIAGNOSTIC_REASONS else "unexpected_error",
        "field": context.get("field") if context.get("field") in DIAGNOSTIC_FIELDS else "capture",
    }
    index = context.get("index")
    if type(index) is int and index >= 0:
        record["index"] = min(index, DIAGNOSTIC_MAX_INTEGER)
    digest = context.get("sha256")
    if isinstance(digest, str) and re.fullmatch("[0-9a-f]{64}", digest):
        record["sha256"] = digest
    if isinstance(error, EvidenceLimit) and error.key in DEFAULT_LIMITS:
        record.update(budget=error.key, count=min(error.count, DIAGNOSTIC_MAX_INTEGER),
                      limit=min(error.limit, DIAGNOSTIC_MAX_INTEGER))
    return record


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
    def __init__(self, diagnostic=None):
        self.diagnostic = diagnostic if diagnostic is not None else {}
        self.diagnostic.update(phase="limits", field="capture")
        overrides = json.loads(os.environ.get("RUNTIME_PROVENANCE_LIMITS", "{}"))
        require(isinstance(overrides, dict) and overrides.keys() <= DEFAULT_LIMITS.keys(),
                "Invalid runtime limits")
        self.limits = DEFAULT_LIMITS | overrides
        require(all(type(n) is int and n > 0 for n in self.limits.values()), "Invalid runtime limits")
        self.used = {}

    def check(self, key, count):
        if count > self.limits[key]:
            raise EvidenceLimit(key, count, self.limits[key], self.diagnostic.get("phase"))

    def add(self, key, count):
        self.used[key] = self.used.get(key, 0) + count
        self.check(key, self.used[key])


class UnsafeEvidence(ValueError):
    def __init__(self, message, reason, phase=None):
        super().__init__(message)
        self.reason = reason
        self.phase = phase


class EvidenceLimit(ValueError):
    reason = "budget_exceeded"

    def __init__(self, key, count, limit, phase):
        super().__init__("Runtime evidence limit exceeded: " + key)
        self.key, self.count, self.limit, self.phase = key, count, limit, phase


class EvidenceRejected(ValueError):
    def __init__(self, problem):
        super().__init__("Required/public evidence rejected: " + str(problem))
        self.problem = problem


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
            raise UnsafeEvidence("unparseable evidence URL", "unparseable_url") from None
        if "@" in parsed.netloc:
            raise UnsafeEvidence("credential-bearing URL", "credential_url")
        for field in re.split(r"[&;]", parsed.query + "&" + parsed.fragment):
            key = unquote(field.split("=", 1)[0]).replace("+", " ")
            key = re.sub(r"([a-z])([A-Z])", r"\1_\2", key)
            if SECRET_KEY.search(key):
                raise UnsafeEvidence("credential-bearing URL", "credential_url")
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
            raise UnsafeEvidence("Invalid or unsupported ZIP evidence", "invalid_zip")

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


def inspect_zip(stream, budget, depth=1, prefix="", expected=False, public=False):
    count = zip_preflight(stream, budget, depth, expected)
    notices = []
    unsafe = None
    if count is not None:
        stream.seek(0)
        with zipfile.ZipFile(stream) as source:
            if public:
                public_text(io.BytesIO(source.comment), "metadata.txt")
            members = source.infolist()
            require(len(members) == count, "Invalid ZIP directory count")
            budget.check("archive_members", len(members))
            budget.check("archive_bytes", sum(m.file_size for m in members))
            budget.check("capture_bytes", budget.used.get("capture_bytes", 0) +
                         sum(m.file_size for m in members))
            actual = 0
            for member in members:
                if public:
                    require(member.orig_filename == member.filename and
                            not any(ord(c) < 32 for c in member.filename),
                            "Invalid source member name")
                    require(not member.filename.startswith("/") and "\\" not in member.filename and
                            all(p not in ("", ".", "..") for p in member.filename.rstrip("/").split("/")),
                            "Unsafe source member path")
                    require((member.external_attr >> 16) & 0o170000 != 0o120000,
                            "Source archive symlink")
                    public_text(io.BytesIO(member.comment), "metadata.txt")
                    require(Path(member.filename).suffix.lower() not in
                            {".aar", ".class", ".so", ".a", ".o", ".dex", ".exe", ".dll"},
                            "Compiled source member")
                    extra = member.extra
                    while extra:
                        require(len(extra) >= 4, "Invalid source extra field")
                        tag, length = struct.unpack_from("<HH", extra)
                        require(length <= len(extra) - 4 and
                                ((tag == 0xcafe and length == 0) or
                                 (tag == 0x5455 and length in (1, 5, 9, 13)) or
                                 (tag == 0x000a and length == 32)),
                                "Non-allowlisted source extra field")
                        extra = extra[4 + length:]
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
                    if public:
                        member_hash = hashlib.sha256()
                        count = 0
                        while chunk := member_stream.read(65536):
                            count += len(chunk)
                            budget.check("member_bytes", count)
                            budget.add("capture_bytes", len(chunk))
                            member_hash.update(chunk)
                            nested.write(chunk)
                        member_hash = member_hash.hexdigest()
                        nested.seek(0)
                        data = nested.read() if notice else None
                        problem = None
                    else:
                        member_hash, data, problem, count = scan(
                            member_stream, budget, archive=True, collect=notice, sink=nested)
                    require(count == member.file_size, "Invalid archive member size")
                    embedded, nested_problem = inspect_zip(
                        nested, budget, depth + 1, prefix + member.filename + "!/",
                        Path(member.filename).suffix.lower() in {".zip", ".jar", ".aar"}, public)
                    if public:
                        nested.seek(0)
                        if not zipfile.is_zipfile(nested):
                            public_text(nested, member.filename)
                    notices.extend(embedded)
                    unsafe = unsafe or nested_problem
                actual += count
                budget.check("archive_bytes", actual)
                unsafe = unsafe or problem
                if notice:
                    notices.append((prefix + member.filename, member_hash, bytes(data)))
    return notices, unsafe


def inspect(path, budget):
    budget.diagnostic["phase"] = "raw_scan"
    budget.add("evidence_bytes", path.stat().st_size)
    with path.open("rb") as stream:
        digest, _, unsafe, _ = scan(stream, budget)
        if unsafe:
            unsafe.phase = "raw_scan"
        budget.diagnostic["phase"] = "zip_inspection"
        try:
            notices, problem = inspect_zip(stream, budget)
            unsafe = unsafe or problem
        except (UnsafeEvidence, EvidenceLimit) as problem:
            notices, unsafe = [], unsafe or problem
        except (zipfile.BadZipFile, NotImplementedError, RuntimeError, EOFError, zlib.error):
            notices, unsafe = [], UnsafeEvidence("Invalid or unsupported ZIP evidence", "invalid_zip")
        if unsafe and unsafe.phase is None:
            unsafe.phase = "zip_inspection"
    return digest, notices, unsafe


def load_capture(capture, budget, graph_name="graph.json"):
    budget.diagnostic.update(phase="graph_read", field="graph")
    capture = safe_path(capture)
    for name in ("files", "notices", "index.json"):
        safe_path(capture / name, capture)
    graph = safe_path(capture / graph_name, capture)
    require(graph.is_file(), "Same-build runtime graph missing")
    budget.check("graph_bytes", graph.stat().st_size)
    data = graph.read_bytes()
    budget.diagnostic["phase"] = "graph_scan"
    check_urls(data.decode("utf-8"))
    budget.diagnostic["phase"] = "graph_decode"
    def unique(items):
        result = {}
        for key, value in items:
            require(key not in result, "Duplicate metadata key")
            result[key] = value
        return result
    return capture, graph, json.loads(data, object_pairs_hook=unique)


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
    for optional, index, entry in [(False, i, e) for i, e in enumerate(required)] + [
            (True, i, e) for i, e in enumerate(record["supplements"])]:
        budget.diagnostic.update(phase="entry",
                                 field="supplements" if optional else "required_artifacts",
                                 index=index)
        budget.diagnostic.pop("sha256", None)
        if isinstance(entry, dict):
            digest = entry.get("sha256")
            if isinstance(digest, str) and re.fullmatch("[0-9a-f]{64}", digest):
                budget.diagnostic["sha256"] = digest
        path = evidence_path(capture, entry)
        digest = entry["sha256"]
        if digest not in checked:
            checked[digest] = inspect(path, budget)
        actual, embedded, unsafe = checked[digest]
        budget.diagnostic["phase"] = "entry"
        require(actual == digest, "Captured artifact missing or changed")
        if unsafe:
            if optional and omit_optional:
                record["supplemental_missing"].append({
                    "component": entry.get("component"), "kind": entry.get("kind"),
                    "sha256": digest, "reason": str(unsafe)})
                continue
            raise EvidenceRejected(unsafe)
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


def sanitize_legacy_capture(capture, diagnostic=None):
    budget = Budget(diagnostic)
    capture, _, record = load_capture(capture, budget, "graph.pending.json")
    validate_entries(capture, record, budget, omit_optional=True)
    budget.diagnostic.clear()
    budget.diagnostic.update(phase="publication", field="graph")
    graph = safe_path(capture / "graph.json", capture)
    require(not graph.exists(), "Graph output already exists")
    with graph.open("x") as stream:
        stream.write(json.dumps(record, indent=2) + "\n")
    (capture / "graph.pending.json").unlink()


def sha(path):
    with path.open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


def archive_legacy(capture, output):
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


MATERIAL_ROLES = {"sources", "pom", "module", "notice"}
TEXT_SUFFIXES = {
    ".java", ".kt", ".kts", ".scala", ".groovy", ".c", ".h", ".cc", ".cpp", ".hpp",
    ".rs", ".go", ".py", ".sh", ".xml", ".json", ".properties", ".txt", ".md",
    ".html", ".css", ".js", ".proto", ".aidl", ".mf", ".gradle", ".yaml", ".yml",
}


def public_text(stream, name):
    require(Path(name).suffix.lower() in TEXT_SUFFIXES or
            Path(name).name.upper().split(".")[0] in {"LICENSE", "NOTICE", "COPYING", "COPYRIGHT"},
            "Non-allowlisted source member")
    stream.seek(0)
    decoder = codecs.getincrementaldecoder("utf-8")()
    tail = ""
    while chunk := stream.read(65536):
        text = tail + decoder.decode(chunk)
        require(not any(ord(c) < 32 and c not in "\n\r\t" for c in text),
                "Non-text public material")
        require(not re.search(r"-----BEGIN (?:[A-Z ]*PRIVATE KEY|OPENSSH PRIVATE KEY)-----", text),
                "Private key material")
        check_urls(text)
        tail = text[-65536:]
    decoder.decode(b"", final=True)


def fields(value, required, optional=()):
    require(isinstance(value, dict) and set(required) <= value.keys() <=
            set(required) | set(optional), "Unknown or missing schema fields")


def label(value):
    require(isinstance(value, str) and 0 < len(value) <= 512 and
            re.fullmatch(r"[A-Za-z0-9_.:+ /()\[\]-]+", value) and
            ".." not in value.split("/"), "Invalid public label")
    check_urls(value)


def component(value):
    require(isinstance(value, str), "Invalid component")
    if value in {"local:libbox", "local:libbox-legacy"}:
        return
    if value.startswith("project:"):
        require(re.fullmatch(r"project::(?:[A-Za-z0-9_-]+(?::[A-Za-z0-9_-]+)*)?", value),
                "Invalid project identity")
        return
    require(re.fullmatch(r"[A-Za-z0-9_.+-]+:[A-Za-z0-9_.+-]+:[A-Za-z0-9_.+-]+", value)
            and all(p not in ("", ".", "..") for part in value.split(":")
                    for p in part.split(".")), "Invalid Maven coordinate")


def attributes(value):
    require(isinstance(value, dict), "Invalid attributes")
    for key, item in value.items():
        label(key)
        require(not SECRET_KEY.search(key), "Private metadata key")
        label(item)


def variant(value, capabilities=False):
    fields(value, ("name", "attributes", "capabilities") if capabilities else ("name", "attributes"))
    label(value["name"])
    attributes(value["attributes"])
    if capabilities:
        require(isinstance(value["capabilities"], list), "Invalid capabilities")
        for item in value["capabilities"]:
            component(item)


def inventory_entry(entry, material=False):
    fields(entry, ("component", "sha256", "size", "kind", "file") if material else
           ("component", "sha256", "size", "type"), () if material else ("attributes",))
    component(entry["component"])
    require(isinstance(entry["sha256"], str) and re.fullmatch("[0-9a-f]{64}", entry["sha256"]),
            "Invalid original digest")
    require(type(entry["size"]) is int and 0 <= entry["size"] <= DIAGNOSTIC_MAX_INTEGER,
            "Invalid original size")
    if material:
        require(entry["kind"] in MATERIAL_ROLES, "Unknown published material role")
        require(entry["file"] == "files/" + entry["sha256"], "Invalid material path")
    else:
        require(entry["type"] in {"aar", "jar", "so", "a", "dex"}, "Invalid input artifact type")
        if "attributes" in entry:
            attributes(entry["attributes"])


def validate_schema(record):
    fields(record, ("schema", "mode", "gradle", "assemble_task", "configurations",
                    "local_aars", "supplements", "supplemental_missing"))
    require(type(record["schema"]) is int and record["schema"] == 2,
            "Legacy schema requires separate historical verification")
    require(record["mode"] in {"build", "fixture"} and
            record["assemble_task"] == ":app:assembleOtherRelease", "Wrong captured variant")
    label(record["gradle"])
    configs = record["configurations"]
    require(isinstance(configs, dict) and "otherReleaseRuntimeClasspath" in configs and
            any("corelibrarydesugaring" in n.lower() for n in configs),
            "Runtime/desugaring graph missing")
    for name, config in configs.items():
        label(name)
        require(name == "otherReleaseRuntimeClasspath" or
                "corelibrarydesugaring" in name.lower(), "Unknown configuration")
        fields(config, ("components", "edges", "artifacts"))
        require(all(isinstance(config[k], list) for k in config) and
                config["components"] and config["artifacts"], "Empty runtime resolution")
        ids = set()
        for item in config["components"]:
            fields(item, ("id", "variants"))
            component(item["id"])
            ids.add(item["id"])
            require(isinstance(item["variants"], list), "Invalid variants")
            for selected in item["variants"]:
                variant(selected, True)
        for edge in config["edges"]:
            fields(edge, ("from", "requested", "selected", "constraint", "variant"))
            require(edge["from"] in ids and edge["selected"] in ids, "Unknown edge component")
            component(edge["requested"])
            require(type(edge["constraint"]) is bool, "Invalid constraint")
            variant(edge["variant"])
        for entry in config["artifacts"]:
            inventory_entry(entry)
            require(entry["component"] in ids or entry["component"].startswith("local:"),
                    "Unknown artifact component")
    for key in ("local_aars", "supplements", "supplemental_missing"):
        require(isinstance(record[key], list), "Invalid inventory")
    for entry in record["local_aars"]:
        inventory_entry(entry)
        require(entry["component"] in {"local:libbox", "local:libbox-legacy"},
                "Unknown local artifact")
    require(any(e["component"] == "local:libbox" for e in record["local_aars"]),
            "Required local libbox missing")
    for entry in record["supplements"]:
        inventory_entry(entry, True)
    for entry in record["supplemental_missing"]:
        fields(entry, ("component", "kind", "reason"), ("sha256",))
        component(entry["component"])
        require(entry["kind"] in MATERIAL_ROLES, "Unknown omitted role")
        require(entry["reason"] in {"unavailable", "rejected_public_material"},
                "Unknown omission reason")
        if "sha256" in entry:
            require(re.fullmatch("[0-9a-f]{64}", entry["sha256"]), "Invalid omitted digest")


def published_materials(capture, record, budget, omit=False):
    validate_schema(record)
    allowed, notices, kept = {}, [], []
    for index, entry in enumerate(record["supplements"]):
        budget.diagnostic.update(phase="entry", field="supplements", index=index,
                                 sha256=entry["sha256"])
        path = evidence_path(capture, entry)
        budget.check("evidence_bytes", entry["size"])
        require(path.stat().st_size == entry["size"] and sha(path) == entry["sha256"],
                "Public material missing or changed")
        try:
            budget.add("evidence_bytes", entry["size"])
            with path.open("rb") as stream:
                if entry["kind"] == "sources":
                    embedded, problem = inspect_zip(stream, budget, expected=True, public=True)
                    if problem:
                        raise problem
                else:
                    budget.add("capture_bytes", entry["size"])
                    public_text(stream, "NOTICE" if entry["kind"] == "notice" else "metadata.xml")
                    embedded = []
        except (ValueError, zipfile.BadZipFile, NotImplementedError, RuntimeError, EOFError, zlib.error):
            if not omit:
                raise ValueError("Rejected public material") from None
            record["supplemental_missing"].append(dict(
                component=entry["component"], kind=entry["kind"], sha256=entry["sha256"],
                reason="rejected_public_material"))
            continue
        kept.append(entry)
        allowed[entry["file"]] = path
        for member, digest, data in embedded:
            notices.append(dict(artifact=entry["sha256"], member=member, sha256=digest))
            allowed["notices/" + digest] = data
    if omit:
        record["supplements"] = kept
    return allowed, notices


def sanitize_capture(capture, diagnostic=None):
    budget = Budget(diagnostic)
    capture, pending, record = load_capture(capture, budget, "graph.pending.json")
    published_materials(capture, record, budget, omit=True)
    budget.diagnostic.clear()
    budget.diagnostic.update(phase="publication", field="graph")
    graph = safe_path(capture / "graph.json", capture)
    with graph.open("x") as stream:
        stream.write(json.dumps(record, indent=2) + "\n")
    pending.unlink()


def archive(capture, output):
    output = safe_path(output)
    require(not output.exists(), "Runtime archive output already exists")
    budget = Budget()
    capture, graph, record = load_capture(capture, budget)
    require(record.get("schema") == 2, "Legacy schema requires separate historical verification")
    require(record["mode"] == "build", "Fixture graph is not build evidence")
    allowed, notices = published_materials(capture, record, budget)
    allowed["graph.json"] = graph
    index = dict(schema=2, notices=notices,
                 files={name: sha(value) if isinstance(value, Path) else
                        hashlib.sha256(value).hexdigest() for name, value in sorted(allowed.items())})
    allowed["index.json"] = (json.dumps(index, indent=2) + "\n").encode()
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
    return dict(archive=output.name, sha256=sha(output),
                missing=record["supplemental_missing"], certified=False)


def verify_archive(path, expected_sha):
    """Revalidate historical schema 1 separately; never upgrade its evidence claims."""
    require(sha(path) == expected_sha, "Runtime archive hash mismatch")
    with tempfile.TemporaryDirectory(prefix="verify-runtime-") as temporary:
        root = Path(temporary)
        capture = root / "capture"
        capture.mkdir()
        members = {}
        total = 0
        with tarfile.open(path, "r:gz") as bundle:
            for item in bundle:
                require(item.isfile() and item.name not in members and
                        (item.name in {"graph.json", "index.json"} or
                         re.fullmatch(r"(files|notices)/[0-9a-f]{64}", item.name)),
                        "Invalid runtime archive member")
                total += item.size
                require(total <= DEFAULT_LIMITS["evidence_bytes"] + DEFAULT_LIMITS["graph_bytes"] * 2
                        and len(members) < DEFAULT_LIMITS["capture_members"], "Runtime tar limit")
                with bundle.extractfile(item) as stream:
                    members[item.name] = stream.read(item.size + 1)
                require(len(members[item.name]) == item.size, "Truncated runtime member")
        require({"graph.json", "index.json"} <= members.keys(), "Runtime index missing")
        for name, data in members.items():
            target = capture / name
            target.parent.mkdir(exist_ok=True)
            target.write_bytes(data)
        record = json.loads(members["graph.json"])
        require(type(record.get("schema")) is int and record["schema"] in (1, 2),
                "Unknown runtime schema")
        regenerated = root / "verified.tar.gz"
        writer = archive_legacy if record["schema"] == 1 else archive
        writer(capture, regenerated)
        with tarfile.open(regenerated, "r:gz") as bundle:
            actual = {item.name: bundle.extractfile(item).read() for item in bundle}
        require(actual == members, "Runtime index/material membership mismatch")
        return dict(schema=record["schema"], members=len(members), certified=False)


def main(argv):
    diagnostic = {"phase": "invocation", "field": "capture"}
    try:
        require(len(argv) == 3 and argv[1] in ("--prepare", "--sanitize"),
                "Invalid runtime validator invocation")
        if argv[1] == "--prepare":
            diagnostic["phase"] = "prepare"
            prepare_capture(Path(argv[2]))
        else:
            sanitize_capture(Path(argv[2]), diagnostic)
    except Exception as error:
        # Never expose exception text, including for unforeseen interpreter/library failures.
        print(json.dumps(diagnostic_record(diagnostic, error), separators=(",", ":")), file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
