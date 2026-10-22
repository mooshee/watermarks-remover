"""Bounded, read-only WebAssembly core-v1 framing/custom-metadata inspection.

Author: Daniel Hallman

References: WebAssembly binary modules/values/name appendix and the WebAssembly
tool-conventions ProducersSection and Linking target_features specifications.
Code, data, functional symbol strings and instructions are never scanned as prose,
executed, normalized or rewritten. This is not a semantic Wasm validator.
"""

from __future__ import annotations

import base64
import hashlib
import re
from typing import Any

MAX_BYTES = 256 << 20
MAX_SECTIONS = 4096
MAX_METADATA_BYTES = 16 << 20
MAX_STRING = 4096
MAX_ENTRIES = 262144
SECTION_ORDER = {
    1: 1,
    2: 2,
    3: 3,
    4: 4,
    5: 5,
    13: 6,
    6: 7,
    7: 8,
    8: 9,
    9: 10,
    12: 11,
    10: 12,
    11: 13,
}
KNOWN_FEATURES = {
    "atomics",
    "bulk-memory",
    "bulk-memory-opt",
    "call-indirect-overlong",
    "exception-handling",
    "extended-const",
    "gc",
    "memory64",
    "multimemory",
    "multivalue",
    "mutable-globals",
    "nontrapping-fptoint",
    "reference-types",
    "relaxed-simd",
    "sign-ext",
    "simd128",
    "tail-call",
    "wide-arithmetic",
}
PROVENANCE_NAME = re.compile(
    r"(?:^|[._ -])(?:c2pa|jumbf|synthid|ai|ai_metadata|ai_provenance|openai|chatgpt|anthropic)(?:$|[._ -])",
    re.I,
)
PROVENANCE_TEXT = re.compile(
    r"c2pa|content credentials|synthid|ai[- ]generated|generated (?:by|with) (?:openai|chatgpt|claude|gemini)",
    re.I,
)
PRODUCER_GENERATOR = re.compile(
    r"(?:^|[\s._/()@:-])(?:openai|chatgpt|anthropic|claude|gemini)(?:$|[\s._/()@:-])",
    re.I,
)


def is_wasm(data: bytes) -> bool:
    return data[:4] == b"\0asm"


def _require(condition: bool, reason: str) -> None:
    if not condition:
        raise ValueError(f"WASM inspection rejected: {reason}")


class _Reader:
    def __init__(self, data: memoryview, budget: list[int]):
        self.data, self.cursor, self.budget = data, 0, budget

    def take(self, size: int) -> memoryview:
        _require(0 <= size <= len(self.data) - self.cursor, "truncated payload")
        start = self.cursor
        self.cursor += size
        return self.data[start : self.cursor]

    def byte(self) -> int:
        return self.take(1)[0]

    def u32(self) -> int:
        value = 0
        for index in range(5):
            byte = self.byte()
            _require(index != 4 or byte & 0xF0 == 0, "overflow or overlong ULEB128")
            value |= (byte & 0x7F) << (7 * index)
            if not byte & 0x80:
                return value
        raise ValueError("WASM inspection rejected: overlong ULEB128")

    def count(self) -> int:
        count = self.u32()
        self.budget[0] += count
        _require(self.budget[0] <= MAX_ENTRIES, "metadata/vector entry work bound exceeded")
        return count

    def name(self) -> str:
        size = self.u32()
        _require(size <= MAX_STRING, "metadata string outside bound")
        try:
            return bytes(self.take(size)).decode("utf-8")
        except UnicodeDecodeError as exc:
            raise ValueError("WASM inspection rejected: invalid metadata UTF-8") from exc

    def end(self) -> None:
        _require(self.cursor == len(self.data), "unparsed metadata trailing bytes")


def _names(reader: _Reader, indirect: bool = False) -> None:
    previous = -1
    for _ in range(reader.count()):
        index = reader.u32()
        _require(index > previous, "duplicate or unordered name index")
        previous = index
        if indirect:
            _names(reader)
        else:
            # Functional compiler/linker symbols: validate UTF-8 and bounds only.
            reader.name()


def _name_section(reader: _Reader, findings: set[str]) -> None:
    previous, subsections = -1, 0
    while reader.cursor < len(reader.data):
        subsections += 1
        _require(subsections <= MAX_SECTIONS, "name subsection work bound exceeded")
        kind, size = reader.byte(), reader.u32()
        _require(kind > previous, "duplicate or unordered name subsection")
        previous = kind
        body = _Reader(reader.take(size), reader.budget)
        if kind == 0:
            body.name()
        elif kind in (1, 4, 5, 6, 7, 8, 9, 11):
            _names(body)
        elif kind in (2, 3, 10):
            _names(body, indirect=True)
        else:
            findings.add("unsupported_name_subsection")
            continue
        body.end()


def _producers(reader: _Reader, findings: set[str]) -> int:
    fields, entries = set(), 0
    for _ in range(reader.count()):
        field = reader.name()
        _require(field not in fields, "duplicate producer field")
        fields.add(field)
        if field not in {"language", "processed-by", "sdk"}:
            findings.add("unsupported_producer_field")
        names = set()
        for _ in range(reader.count()):
            name, version = reader.name(), reader.name()
            _require(bool(name) and name not in names, "empty or duplicate producer name")
            names.add(name)
            entries += 1
            # This is compiler provenance metadata, not arbitrary program strings.
            if any(
                pattern.search(value)
                for pattern in (PROVENANCE_TEXT, PRODUCER_GENERATOR)
                for value in (name, version)
            ):
                findings.add("explicit_provenance_producer_metadata")
                if re.search(r"c2pa|jumbf|content credentials", name + version, re.I):
                    findings.add("explicit_c2pa_metadata")
    reader.end()
    return entries


def _features(reader: _Reader, findings: set[str]) -> int:
    names = set()
    count = reader.count()
    for _ in range(count):
        prefix, name = reader.byte(), reader.name()
        _require(prefix in (ord("+"), ord("-")), "invalid target feature prefix")
        _require(name and name not in names, "empty or duplicate target feature")
        names.add(name)
        if name not in KNOWN_FEATURES:
            findings.add("unsupported_target_feature")
    reader.end()
    return count


def inspect_wasm(data: bytes) -> dict[str, Any]:
    _require(8 <= len(data) <= MAX_BYTES, "artifact size outside bound")
    _require(is_wasm(data) and data[4:8] == b"\x01\0\0\0", "only core module version1 is supported")
    budget = [0]
    reader = _Reader(memoryview(data), budget)
    reader.take(8)
    seen: set[int] = set()
    custom_names: list[str] = []
    known_custom: set[str] = set()
    findings: set[str] = set()
    sections = last_order = metadata_bytes = producer_entries = feature_entries = 0
    functions = code_functions = data_count = data_segments = None
    while reader.cursor < len(reader.data):
        sections += 1
        _require(sections <= MAX_SECTIONS, "section count outside bound")
        kind, size = reader.byte(), reader.u32()
        _require(kind < 128, "section id outside supported one-byte range")
        payload = reader.take(size)
        section = _Reader(payload, budget)
        if kind == 0:
            metadata_bytes += size
            _require(metadata_bytes <= MAX_METADATA_BYTES, "custom metadata bytes outside bound")
            name = section.name()
            custom_names.append(name)
            if name in {"name", "producers", "target_features"}:
                _require(name not in known_custom, "duplicate known custom section")
                known_custom.add(name)
            if name == "name":
                _name_section(section, findings)
            elif name == "producers":
                producer_entries += _producers(section, findings)
            elif name == "target_features":
                feature_entries += _features(section, findings)
            else:
                findings.add("unsupported_custom_metadata")
                if PROVENANCE_NAME.search(name):
                    findings.add("explicit_provenance_custom_section")
                    if re.search(r"c2pa|jumbf|content credentials", name, re.I):
                        findings.add("explicit_c2pa_metadata")
            continue
        _require(kind not in seen, "duplicate standard section")
        seen.add(kind)
        _require(size > 0, "empty standard section payload")
        order = SECTION_ORDER.get(kind)
        if order is None:
            findings.add("unsupported_standard_section")
            continue
        _require(order > last_order, "standard sections out of order")
        last_order = order
        if kind == 3:
            functions = section.count()
            for _ in range(functions):
                section.u32()
            section.end()
        elif kind == 10:
            code_functions = section.count()
            for _ in range(code_functions):
                body_size = section.u32()
                _require(body_size > 0, "empty function body")
                # Function instruction bytes remain entirely opaque.
                section.take(body_size)
            section.end()
        elif kind in (8, 12):
            count = section.u32()
            section.end()
            if kind == 12:
                data_count = count
        elif kind == 11:
            data_segments = section.count()
            # Initializer expressions/data bytes need semantic parsing; never scan them.
        else:
            # Count framing only; imports/types/globals/exports/instructions remain opaque.
            section.count()
    _require(seen, "module has no standard sections; magic-only inspection is unsupported")
    _require((functions or 0) == (code_functions or 0), "function/code count mismatch")
    if data_count is not None:
        _require(
            data_count == (data_segments or 0), "data-count metadata differs from data section"
        )
    digest = hashlib.sha256(data).hexdigest()
    return {
        "format": "wasm",
        "module_version": 1,
        "sections": sections,
        "standard_sections": len(seen),
        "custom_sections": custom_names,
        "custom_metadata_bytes": metadata_bytes,
        "producer_entries_preserved": producer_entries,
        "target_features_preserved": feature_entries,
        "bounded_vector_entries": budget[0],
        "findings": sorted(findings),
        "has_c2pa": "explicit_c2pa_metadata" in findings,
        "has_ai_metadata": any("explicit_provenance" in finding for finding in findings),
        "changed": False,
        "input_sha256": digest,
        "output_sha256": digest,
        "release_ready": not findings,
        "review_required": bool(findings),
        "limits": {
            "artifact_bytes": MAX_BYTES,
            "sections": MAX_SECTIONS,
            "custom_metadata_bytes": MAX_METADATA_BYTES,
            "metadata_string_bytes": MAX_STRING,
            "vector_entries": MAX_ENTRIES,
        },
        "limitations": "Bounded core-v1 module/section and function-body framing plus known name/producers/target_features custom-metadata inspection only. Code, data, functional names and instruction payloads are preserved without prose/Unicode scans, execution or rewrites. Standard-section contents are not semantically validated. Unknown metadata requires review. Not Wasm validation, signature trust, malware analysis, universal watermark absence or authorship proof. No bytes are changed.",
    }


def clean_wasm(data: bytes, options: dict[str, Any]) -> dict[str, Any]:
    incompatible = (
        "strategy",
        "style",
        "nfkc",
        "aggressive_homoglyphs",
        "normalize_spaces",
        "remove_pixel",
        "remove_audio_watermark",
        "strip_all_metadata",
        "detect_before",
        "detect_after",
    )
    _require(
        not any(options.get(key) for key in incompatible),
        "executable transformations are forbidden",
    )
    inspected = inspect_wasm(data)
    unresolved = bool(inspected["findings"])
    status = "requires_review" if unresolved else "inspected_no_change"
    result = {
        "ok": True,
        "kind": "executable",
        "status": status,
        "report": {
            "mode": "deterministic_only",
            "status": status,
            "changed": False,
            "release_ready": not unresolved,
            "review_required": unresolved,
            "input_sha256": inspected["input_sha256"],
            "output_sha256": inspected["output_sha256"],
            "actions": [],
            "before": inspected,
            "after": inspected,
            "limitations": inspected["limitations"],
        },
    }
    if not unresolved:
        result["cleaned"] = base64.b64encode(data).decode("ascii")
    return result
