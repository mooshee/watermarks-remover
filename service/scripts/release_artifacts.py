"""Deterministic, byte-preserving inspection for reviewed release artifacts.

Author: Daniel Hallman

Never normalize source, remove source characters, format code or call a model.
Unclassified Unicode is returned for a narrow, reviewed source fix. Only actual
HTML metadata elements are edited, without serializing the rest of the document.
"""

from __future__ import annotations

import base64
import hashlib
import re
from html.parser import HTMLParser
from pathlib import Path
from typing import Any
from xml.parsers import expat

from common import looks_binary
from container_meta import AI_META_NAME_RE, inspect_html, inspect_markdown
from format_dispatch import TEXT_EXTS
from text_unicode import inspect_text

RELEASE_TEXT_EXTS = TEXT_EXTS - {".txt", ".text", ".rst", ".adoc", ".asciidoc", ".org", ".tex"}
RELEASE_CONTAINER_EXTS = {".html", ".htm", ".md", ".markdown", ".mdx"}
KNOWN_RELEASE_NAMES = {"_headers", "_redirects", "LICENSE"}
KNOWN_RELEASE_EXTS = {".xml", ".sha256"}
MAX_KNOWN_TEXT_BYTES = 4 << 20
MAX_CHECKSUM_BYTES = 64 << 10
MAX_CHECKSUM_LINES = 1024
MAX_XML_DEPTH = 128
MAX_XML_ELEMENTS = 100_000
MAX_XML_ATTRIBUTES = 128
MAX_XML_METADATA_CHARS = 4096
_CHECKSUM_LINE = re.compile(r"[0-9a-fA-F]{64} [ *]([A-Za-z0-9][A-Za-z0-9._-]{0,254})")
_XML_C2PA_FIELDS = {"c2pa", "jumbf", "contentcredentials", "content-credentials"}
_XML_AI_FIELDS = {
    "ai-generated",
    "ai_generated",
    "ai-provenance",
    "ai_provenance",
    "synthid",
    "aigc",
}
_XML_GENERATOR_FIELDS = {"generator", "generated-by", "generatedby", "creator-tool", "creatortool"}
_XML_AI_GENERATOR = re.compile(
    r"\b(?:openai|anthropic|chatgpt|claude|gemini|synthid|aigc)\b|\bai[-_ ]generated\b", re.I
)
_FONT_AWESOME_NAMES = {"fontawesome"} | {
    f"font awesome {version} {variant}"
    for version in (4, 5, 6)
    for variant in ("free", "pro", "brands")
}


def automatic_release_mode(name: str) -> bool:
    return known_release_text(name) or Path(name).suffix.lower() in RELEASE_TEXT_EXTS | {
        ".html",
        ".htm",
    }


def known_release_text(name: str) -> bool:
    path = Path(name)
    return path.name in KNOWN_RELEASE_NAMES or path.suffix.lower() in KNOWN_RELEASE_EXTS


def _xml_structure(text: str) -> dict[str, Any]:
    """Non-building XML parser: declarations/entities are rejected before expansion."""
    if expat.version_info < (2, 6, 0):
        raise ValueError("XML inspection requires Expat 2.6.0 or newer")
    parser = expat.ParserCreate(encoding="UTF-8", namespace_separator="}")
    parser.SetParamEntityParsing(expat.XML_PARAM_ENTITY_PARSING_NEVER)
    parser.UseForeignDTD(False)
    depth = elements = deepest = namespaces = 0
    findings: set[str] = set()
    captures: list[dict[str, Any]] = []

    def metadata_name(name: str) -> str:
        namespace_uri, _, local = name.rpartition("}")
        local = local.lower()
        namespace_tokens = re.split(r"[/#:.]", namespace_uri.lower())
        if local in _XML_C2PA_FIELDS or "c2pa" in namespace_tokens:
            findings.add("explicit_xml_c2pa_metadata")
        elif local in _XML_AI_FIELDS:
            findings.add("explicit_xml_ai_provenance")
        elif local == "provenance":
            findings.add("explicit_xml_provenance_metadata")
        return local

    def generator_value(value: str) -> None:
        if len(value) > MAX_XML_METADATA_CHARS:
            raise ValueError("XML metadata field exceeds inspection bound")
        if _XML_AI_GENERATOR.search(value):
            findings.add("explicit_xml_ai_generator")

    def forbidden(*args: Any) -> None:
        raise ValueError("XML inspection rejects DOCTYPE and entity declarations/references")

    def declaration(version: str, encoding: str | None, standalone: int) -> None:
        if version != "1.0" or (encoding is not None and encoding.lower() not in {"utf-8", "utf8"}):
            raise ValueError("XML inspection supports only XML 1.0 with UTF-8 encoding")

    def start(name: str, attributes: dict[str, str]) -> None:
        nonlocal depth, elements, deepest, namespaces
        depth += 1
        elements += 1
        deepest = max(deepest, depth)
        if (
            depth > MAX_XML_DEPTH
            or elements > MAX_XML_ELEMENTS
            or len(attributes) + namespaces > MAX_XML_ATTRIBUTES
        ):
            raise ValueError("XML structural inspection limits exceeded")
        namespaces = 0
        local = metadata_name(name)
        local_attributes: dict[str, list[str]] = {}
        for key, value in attributes.items():
            field = metadata_name(key)
            local_attributes.setdefault(field, []).append(value)
            if field in _XML_GENERATOR_FIELDS:
                generator_value(value)
        capture = local in _XML_GENERATOR_FIELDS
        if local in {"meta", "metadata"}:
            for selector in local_attributes.get("name", []) + local_attributes.get("property", []):
                if metadata_name(selector) in _XML_GENERATOR_FIELDS:
                    for value in local_attributes.get("content", []) + local_attributes.get(
                        "value", []
                    ):
                        generator_value(value)
                    capture = True
        if capture:
            captures.append({"depth": depth, "parts": [], "size": 0})

    def namespace(prefix: str | None, uri: str | None) -> None:
        nonlocal namespaces
        namespaces += 1
        if namespaces > MAX_XML_ATTRIBUTES:
            raise ValueError("XML structural inspection limits exceeded")

    def end(name: str) -> None:
        nonlocal depth
        if captures and captures[-1]["depth"] == depth:
            generator_value("".join(captures.pop()["parts"]))
        depth -= 1

    def characters(value: str) -> None:
        for capture in captures:
            capture["size"] += len(value)
            if capture["size"] > MAX_XML_METADATA_CHARS:
                raise ValueError("XML metadata field exceeds inspection bound")
            capture["parts"].append(value)

    def processing_instruction(target: str, value: str) -> None:
        if metadata_name(target) in _XML_GENERATOR_FIELDS:
            generator_value(value)

    parser.StartDoctypeDeclHandler = forbidden
    parser.EntityDeclHandler = forbidden
    parser.ExternalEntityRefHandler = forbidden
    parser.XmlDeclHandler = declaration
    parser.StartElementHandler = start
    parser.EndElementHandler = end
    parser.StartNamespaceDeclHandler = namespace
    parser.CharacterDataHandler = characters
    parser.ProcessingInstructionHandler = processing_instruction
    try:
        parser.Parse(text, True)
    except expat.ExpatError as exc:
        raise ValueError("XML inspection requires well-formed XML") from exc
    return {
        "format": "xml",
        "validation": "well-formed XML 1.0; no DTD or declared entities",
        "elements": elements,
        "maximum_depth": deepest,
        "metadata_findings": sorted(findings),
        "has_c2pa": "explicit_xml_c2pa_metadata" in findings,
        "has_ai_metadata": bool(
            findings & {"explicit_xml_ai_provenance", "explicit_xml_ai_generator"}
        ),
        "review_required": bool(findings),
        "limits": {
            "depth": MAX_XML_DEPTH,
            "elements": MAX_XML_ELEMENTS,
            "attributes_per_element": MAX_XML_ATTRIBUTES,
            "metadata_field_characters": MAX_XML_METADATA_CHARS,
        },
    }


def _known_text_structure(text: str, name: str) -> dict[str, Any]:
    if any((ord(ch) < 32 and ch not in "\t\r\n") or ord(ch) == 127 for ch in text):
        raise ValueError("known release text rejects binary/control characters")
    suffix = Path(name).suffix.lower()
    if suffix == ".xml":
        return _xml_structure(text)
    if suffix == ".sha256":
        lines = text.split("\n")
        if lines[-1] == "":
            lines.pop()
        if not 0 < len(lines) <= MAX_CHECKSUM_LINES:
            raise ValueError("SHA-256 manifest line count outside bound")
        filenames: set[str] = set()
        for index, line in enumerate(lines):
            if line.endswith("\r") and index == len(lines) - 1 and not text.endswith("\n"):
                raise ValueError("SHA-256 manifest requires LF or CRLF line endings")
            match = _CHECKSUM_LINE.fullmatch(line.removesuffix("\r"))
            if match is None or match[1] in filenames:
                raise ValueError(
                    "SHA-256 manifest requires exact hex checksum lines with unique safe basenames"
                )
            filenames.add(match[1])
        return {
            "format": "sha256",
            "validation": "checksum-line syntax and safe basenames only",
            "entries": len(lines),
            "target_hashes_verified": False,
        }
    return {
        "format": "known_text",
        "name": Path(name).name,
        "validation": "UTF-8 text only; configuration/license semantics are not validated",
    }


def _release_text(data: bytes, name: str) -> tuple[str, dict[str, Any] | None]:
    known = known_release_text(name)
    limit = MAX_CHECKSUM_BYTES if Path(name).suffix.lower() == ".sha256" else MAX_KNOWN_TEXT_BYTES
    if known and len(data) > limit:
        raise ValueError("known release text size outside bound")
    if looks_binary(data):
        raise ValueError("refusing binary bytes in a deterministic text artifact")
    try:
        text = data.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise ValueError("deterministic artifact inspection requires valid UTF-8") from exc
    structure = _known_text_structure(text, name) if known else None
    if structure is not None:
        structure["artifact_byte_limit"] = limit
        structure["inspection_only"] = True
    return text, structure


def _unresolved(report: dict[str, Any]) -> bool:
    return bool(
        report["applicable_unicode"]["suspicious_total"]
        or report["has_c2pa"]
        or report["has_ai_metadata"]
        or report.get("format_inspection", {}).get("review_required", False)
    )


def inspect_known_release_text(data: bytes, name: str) -> dict[str, Any]:
    if not known_release_text(name):
        raise ValueError("unsupported release text name/format")
    text, structure = _release_text(data, name)
    report = _inspection(text, name, structure)
    unresolved = _unresolved(report)
    digest = hashlib.sha256(data).hexdigest()
    return {
        **report,
        "format_inspection": structure,
        "mode": "deterministic_only",
        "suspicious_total": report["applicable_unicode"]["suspicious_total"],
        "status": "requires_review" if unresolved else "inspected_no_change",
        "changed": False,
        "release_ready": not unresolved,
        "review_required": unresolved,
        "input_sha256": digest,
        "output_sha256": digest,
        "limitations": "Bounded format syntax, contextual metadata and raw source Unicode inspection only; no schema/configuration/license validation, checksum target verification, external resources, universal watermark or authorship claim. Original bytes are preserved.",
    }


class _HTMLSpans(HTMLParser):
    """Locate real metadata tags and style bodies; never parse raw JS as HTML."""

    def __init__(self, text: str):
        super().__init__(convert_charrefs=False)
        self.text = text
        self.lines = [0]
        self.lines.extend(m.end() for m in re.finditer("\n", text))
        self.metadata: list[tuple[int, int]] = []
        self.css: list[tuple[int, str]] = []
        self.actions: list[str] = []
        self.in_style = False

    def source_offset(self) -> int:
        line, column = self.getpos()
        return self.lines[line - 1] + column

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        if tag == "style":
            self.in_style = True
        if tag != "meta":
            return
        values = dict(attrs)
        key = values.get("name") or values.get("property") or values.get("http-equiv") or ""
        value = values.get("content") or ""
        # Preserve ordinary CMS generator metadata. Unknown provenance-like
        # constructs stay unresolved rather than broad regex deletion in code.
        if key.lower() == "generator" and not re.search(
            r"openai|anthropic|claude|gemini|synthid|chatgpt", value, re.I
        ):
            return
        if AI_META_NAME_RE.search(key):
            start = self.source_offset()
            self.metadata.append((start, start + len(self.get_starttag_text())))
            self.actions.append("remove AI/provenance HTML meta element")

    handle_startendtag = handle_starttag

    def handle_endtag(self, tag: str) -> None:
        if tag == "style":
            self.in_style = False

    def handle_data(self, data: str) -> None:
        if self.in_style:
            self.css.append((self.source_offset(), data))


def _css_blocks(css: str) -> tuple[str, list[tuple[int, int]]]:
    """Mask comments and locate balanced blocks outside strings, keeping offsets.

    Ambiguous or malformed CSS gets no functional classification. This is a
    conservative classifier, not a CSS parser or a source-transforming tool.
    """
    masked = list(css)
    blocks: list[tuple[int, int]] = []
    stack: list[int] = []
    quote = ""
    i = 0
    while i < len(css):
        ch = css[i]
        if quote:
            if ch in "\r\n":
                # CSS bad-string tokens end at an unescaped newline. Recover
                # there without classifying the malformed declaration, so it
                # cannot swallow unrelated valid rules later in the sheet.
                quote = ""
            elif ch == "\\":
                i += 2
                continue
            elif ch == quote:
                quote = ""
        elif ch in "\"'":
            quote = ch
        elif css.startswith("/*", i):
            end = css.find("*/", i + 2)
            if end == -1:
                return css, []
            masked[i : end + 2] = " " * (end + 2 - i)
            i = end + 2
            continue
        elif ch == "{":
            stack.append(i + 1)
        elif ch == "}":
            if not stack:
                return css, []
            blocks.append((stack.pop(), i))
        i += 1
    return (css, []) if quote or stack else ("".join(masked), blocks)


def _css_declarations(body: str) -> list[tuple[str, str, int]]:
    declarations: list[tuple[str, str, int]] = []
    quote = ""
    start = 0
    i = 0
    while i <= len(body):
        ch = body[i] if i < len(body) else ";"
        if quote:
            if ch == "\\":
                i += 2
                continue
            if ch == quote:
                quote = ""
        elif ch in "\"'":
            quote = ch
        elif ch == ";":
            declaration = body[start:i]
            if declaration.strip():
                key, colon, value = declaration.partition(":")
                if not colon or not re.fullmatch(r"[a-zA-Z-]+", key.strip()):
                    return []
                declarations.append((key.strip().lower(), value, start + len(key) + 1))
            start = i + 1
        i += 1
    return declarations


def _functional_glyph_offsets(css: str, start: int) -> set[int]:
    offsets: set[int] = set()
    masked, blocks = _css_blocks(css)
    for begin, end in blocks:
        body = masked[begin:end]
        # Nested blocks and CSS escapes have more grammar than this classifier
        # supports; leave their glyphs unresolved rather than guess.
        if "{" in body or "}" in body or "\\" in body:
            continue
        declarations = _css_declarations(body)
        fonts = [(value, offset) for key, value, offset in declarations if key == "font-family"]
        content = [(value, offset) for key, value, offset in declarations if key == "content"]
        if (
            len(fonts) != 1
            or len(content) != 1
            or any(key in {"font", "all"} for key, _, _ in declarations)
        ):
            continue
        font = _css_value(fonts[0][0])
        if (
            len(font) < 2
            or font[0] not in "\"'"
            or font[-1] != font[0]
            or font[1:-1].lower() not in _FONT_AWESOME_NAMES
        ):
            continue
        value, offset = content[0]
        icon = _css_value(value)
        if (
            len(icon) == 3
            and icon[0] in "\"'"
            and icon[-1] == icon[0]
            and icon[1] in "\uf078\uf0c9"
        ):
            offsets.add(start + begin + offset + len(value) - len(value.lstrip()) + 1)
    return offsets


def _css_value(value: str) -> str:
    """Read a CSS value with optional priority in linear time, without regex."""
    stripped = value.strip()
    if stripped.lower().endswith("!important"):
        stripped = stripped[:-10].rstrip()
    return stripped


def _inspection(text: str, name: str, structure: dict[str, Any] | None = None) -> dict[str, Any]:
    suffix = Path(name).suffix.lower()
    spans = _HTMLSpans(text) if suffix in {".html", ".htm"} else None
    if spans is not None:
        spans.feed(text)
        spans.close()
    css = spans.css if spans else [(0, text)] if suffix == ".css" else []
    preserved = set().union(*(_functional_glyph_offsets(body, offset) for offset, body in css))
    unicode_report = inspect_text(text).to_dict()
    # Re-inspect a masked copy to count ALL occurrences, not the ten diagnostic
    # sample offsets returned for each code point by inspect_text.
    classified = "".join(" " if i in preserved else ch for i, ch in enumerate(text))
    applicable_unicode = inspect_text(classified).to_dict()
    has_c2pa = has_ai = False
    metadata_findings: list[str] = []
    if suffix in {".html", ".htm"}:
        has_c2pa, has_ai, metadata_findings, _ = inspect_html(text)
    elif suffix in {".md", ".markdown", ".mdx"}:
        has_c2pa, has_ai, metadata_findings, _ = inspect_markdown(text)
    if structure is not None:
        has_c2pa |= structure.get("has_c2pa", False)
        has_ai |= structure.get("has_ai_metadata", False)
        metadata_findings.extend(structure.get("metadata_findings", []))
    return {
        **({"format_inspection": structure} if structure is not None else {}),
        "unicode": unicode_report,
        "applicable_unicode": applicable_unicode,
        "has_c2pa": has_c2pa,
        "has_ai_metadata": has_ai,
        "metadata_findings": metadata_findings,
        "preserved_functional_unicode": [
            {
                "offset": i,
                "codepoint": f"U+{ord(text[i]):04X}",
                "reason": "Font Awesome CSS content declaration with explicit font family",
            }
            for i in sorted(preserved)
        ],
    }


def clean_release_artifact(data: bytes, name: str, options: dict[str, Any]) -> dict[str, Any]:
    from elf_metadata import clean_elf, is_elf
    from macho_metadata import clean_macho, is_macho
    from wasm_metadata import clean_wasm, is_wasm

    if is_wasm(data):
        return clean_wasm(data, options)
    if is_elf(data):
        return clean_elf(data, options)
    if is_macho(data):
        return clean_macho(data, options)
    suffix = Path(name).suffix.lower()
    if suffix not in TEXT_EXTS | RELEASE_CONTAINER_EXTS and not known_release_text(name):
        raise ValueError(
            "deterministic_only requires a supported source, configuration, text, HTML or Markdown filename"
        )
    text, structure = _release_text(data, name)
    incompatible = {
        "strategy",
        "style",
        "nfkc",
        "aggressive_homoglyphs",
        "normalize_spaces",
        "remove_pixel",
        "remove_audio_watermark",
        "detect_before",
        "detect_after",
    }
    if structure is not None:
        incompatible.add("strip_all_metadata")
    if any(options.get(key) for key in incompatible):
        raise ValueError(
            "deterministic_only cannot rewrite, normalize, run detectors or transform content"
        )
    before = _inspection(text, name, structure)
    cleaned = text
    actions: list[str] = []
    if suffix in {".html", ".htm"}:
        spans = _HTMLSpans(text)
        spans.feed(text)
        spans.close()
        for start, end in reversed(spans.metadata):
            cleaned = cleaned[:start] + cleaned[end:]
        actions = spans.actions
    after = _inspection(cleaned, name, structure)
    unresolved = _unresolved(after)
    output = cleaned.encode("utf-8")
    changed = output != data
    status = "requires_review" if unresolved else "cleaned" if changed else "inspected_no_change"
    kind = "container" if suffix in RELEASE_CONTAINER_EXTS else "text"
    result = {
        "ok": True,
        "kind": kind,
        "status": status,
        "report": {
            "mode": "deterministic_only",
            "status": status,
            "changed": changed,
            "release_ready": not unresolved,
            "review_required": changed or unresolved,
            "input_sha256": hashlib.sha256(data).hexdigest(),
            "output_sha256": hashlib.sha256(output).hexdigest(),
            "actions": actions,
            "before": before,
            "after": after,
            "limitations": "Deterministic metadata/Unicode inspection only; no authorship or universal watermark claim. Any changed bytes require diff, affected tests and review before publication.",
        },
    }
    if not (structure is not None and unresolved):
        result["cleaned"] = base64.b64encode(output).decode("ascii")
    if structure is not None:
        result["report"]["limitations"] = (
            "Bounded format syntax, contextual metadata and raw source Unicode inspection only; no schema/configuration/license validation, checksum target verification, external resources, universal watermark or authorship claim. Original bytes are preserved."
        )
    return result
