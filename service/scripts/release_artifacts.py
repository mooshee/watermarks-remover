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

from common import looks_binary
from container_meta import AI_META_NAME_RE, inspect_html, inspect_markdown
from format_dispatch import TEXT_EXTS
from text_unicode import inspect_text

RELEASE_TEXT_EXTS = TEXT_EXTS - {".txt", ".text", ".rst", ".adoc", ".asciidoc", ".org", ".tex"}
RELEASE_CONTAINER_EXTS = {".html", ".htm", ".md", ".markdown", ".mdx"}
_FONT_AWESOME_NAMES = {"fontawesome"} | {
    f"font awesome {version} {variant}"
    for version in (4, 5, 6)
    for variant in ("free", "pro", "brands")
}


def automatic_release_mode(name: str) -> bool:
    return Path(name).suffix.lower() in RELEASE_TEXT_EXTS | {".html", ".htm"}


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


def _inspection(text: str, name: str) -> dict[str, Any]:
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
    return {
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

    if is_elf(data):
        return clean_elf(data, options)
    if is_macho(data):
        return clean_macho(data, options)
    suffix = Path(name).suffix.lower()
    if suffix not in TEXT_EXTS | RELEASE_CONTAINER_EXTS:
        raise ValueError(
            "deterministic_only requires a supported source, configuration, text, HTML or Markdown filename"
        )
    if looks_binary(data):
        raise ValueError("refusing binary bytes in a deterministic text artifact")
    try:
        text = data.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise ValueError("deterministic artifact inspection requires valid UTF-8") from exc
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
    if any(options.get(key) for key in incompatible):
        raise ValueError(
            "deterministic_only cannot rewrite, normalize, run detectors or transform content"
        )
    before = _inspection(text, name)
    cleaned = text
    actions: list[str] = []
    if suffix in {".html", ".htm"}:
        spans = _HTMLSpans(text)
        spans.feed(text)
        spans.close()
        for start, end in reversed(spans.metadata):
            cleaned = cleaned[:start] + cleaned[end:]
        actions = spans.actions
    after = _inspection(cleaned, name)
    unresolved = bool(
        after["applicable_unicode"]["suspicious_total"]
        or after["has_c2pa"]
        or after["has_ai_metadata"]
    )
    output = cleaned.encode("utf-8")
    changed = output != data
    status = "requires_review" if unresolved else "cleaned" if changed else "inspected_no_change"
    kind = "container" if suffix in RELEASE_CONTAINER_EXTS else "text"
    return {
        "ok": True,
        "kind": kind,
        "status": status,
        "cleaned": base64.b64encode(output).decode("ascii"),
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
