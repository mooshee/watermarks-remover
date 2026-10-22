"""Bounded, read-only ELF64 little-endian AMD64 executable metadata inspection.

Author: Daniel Hallman

System V ELF ABI headers/sections/program headers and Linux GNU note layouts.
No executable is loaded, rewritten, disassembled or decoded as prose.
"""

from __future__ import annotations

import base64
import hashlib
import re
import struct
from typing import Any

MAX_BYTES = 256 << 20
MAX_HEADERS = 4096
MAX_METADATA_BYTES = 16 << 20
MAX_NOTES = 4096
MAX_STRING = 4096
MAX_TABLE_ENTRIES = 1 << 20
U64 = (1 << 64) - 1
GNU_EH_FRAME, GNU_STACK, GNU_RELRO, GNU_PROPERTY = range(0x6474E550, 0x6474E554)
PROGRAM_TYPES = {0, 1, 2, 3, 4, 6, 7, GNU_EH_FRAME, GNU_STACK, GNU_RELRO, GNU_PROPERTY}
SECTION_TYPES = {
    1,
    2,
    3,
    4,
    5,
    6,
    7,
    8,
    9,
    11,
    14,
    15,
    16,
    18,
    19,
    0x6FFFFFF6,
    0x6FFFFFFD,
    0x6FFFFFFE,
    0x6FFFFFFF,
}
FUNCTIONAL_SECTIONS = {
    ".interp",
    ".dynsym",
    ".dynstr",
    ".hash",
    ".gnu.hash",
    ".gnu.version",
    ".gnu.version_d",
    ".gnu.version_r",
    ".symtab",
    ".strtab",
    ".shstrtab",
    ".text",
    ".init",
    ".fini",
    ".plt",
    ".plt.got",
    ".plt.sec",
    ".iplt",
    ".rodata",
    ".data",
    ".data.rel.ro",
    ".bss",
    ".tbss",
    ".tdata",
    ".init_array",
    ".fini_array",
    ".preinit_array",
    ".dynamic",
    ".got",
    ".got.plt",
    ".gcc_except_table",
    ".eh_frame",
    ".eh_frame_hdr",
    ".relro_padding",
    ".comment",
    ".gnu_debuglink",
    ".gnu_debugaltlink",
}
PROVENANCE_NAME = re.compile(
    r"(?:^|[._ -])(?:c2pa|jumbf|synthid|ai|ai_metadata|ai_provenance|openai|chatgpt|anthropic)(?:$|[._ -])",
    re.I,
)
PROVENANCE_TEXT = re.compile(
    r"c2pa|content credentials|synthid|ai[- ]generated|generated (?:by|with) (?:openai|chatgpt|claude|gemini)",
    re.I,
)
C2PA_METADATA = re.compile(r"c2pa|jumbf|content credentials", re.I)
FUNCTIONAL_PREFIXES = (".text.", ".rodata.", ".data.", ".bss.")


def is_elf(data: bytes) -> bool:
    return data[:4] == b"\x7fELF"


def _require(condition: bool, reason: str) -> None:
    if not condition:
        raise ValueError(f"ELF inspection rejected: {reason}")


def _range(offset: int, size: int, length: int, reason: str) -> None:
    _require(0 <= offset <= length and 0 <= size <= length - offset, reason)


def _unpack(data: memoryview, fmt: str, offset: int) -> tuple[int, ...]:
    _range(offset, struct.calcsize("<" + fmt), len(data), "truncated structure")
    return struct.unpack_from("<" + fmt, data, offset)


def _aligned(value: int) -> bool:
    return value in (0, 1) or (value <= 1 << 30 and value & (value - 1) == 0)


def _disjoint(ranges: list[tuple[int, int]], reason: str) -> None:
    previous = 0
    for start, end in sorted((a, b) for a, b in ranges if b > a):
        _require(start >= previous, reason)
        previous = end


def _string(table: memoryview, offset: int) -> str:
    _range(offset, 1, len(table), "string offset outside string table")
    raw = bytes(table[offset : min(len(table), offset + MAX_STRING)])
    end = raw.find(b"\0")
    _require(end >= 0, "unterminated or oversized metadata string")
    _require(all(32 <= ch < 127 for ch in raw[:end]), "non-ASCII/control metadata name")
    return raw[:end].decode("ascii")


def _provenance(value: str, context: str, findings: set[str]) -> None:
    findings.add(f"explicit_provenance_{context}")
    if C2PA_METADATA.search(value):
        findings.add("explicit_c2pa_metadata")


def _string_range(table: memoryview, offset: int) -> None:
    """Validate functional symbol/linker strings without decoding/scanning text."""
    _range(offset, 1, len(table), "functional string offset outside string table")
    _require(
        b"\0" in bytes(table[offset : min(len(table), offset + MAX_STRING)]),
        "unterminated or oversized functional string",
    )


def _properties(desc: memoryview, findings: set[str]) -> None:
    cursor, previous, count = 0, -1, 0
    while cursor < len(desc):
        count += 1
        _require(count <= MAX_NOTES, "GNU property count outside bound")
        kind, size = _unpack(desc, "II", cursor)
        _require(kind > previous, "duplicate or unordered GNU properties")
        previous = kind
        start, end = cursor + 8, cursor + 8 + size
        padded = (end + 7) & ~7
        _range(start, padded - start, len(desc), "truncated GNU property")
        _require(not any(desc[end:padded]), "nonzero GNU property padding")
        expected = {1: 8, 2: 0, 0xC0000002: 4, 0xC0008002: 4, 0xC0010002: 4}
        if kind in expected:
            _require(size == expected[kind], "invalid GNU property size")
        else:
            findings.add("unsupported_gnu_property")
        cursor = padded
    _require(cursor > 0, "empty GNU property descriptor")


def _notes(
    image: memoryview,
    offset: int,
    size: int,
    alignment: int,
    findings: set[str],
    records: set[tuple[int, int]],
) -> None:
    _require(alignment in (4, 8) and offset % alignment == 0, "unsupported note alignment")
    _require(0 < size <= MAX_METADATA_BYTES, "note bytes outside bound")
    _range(offset, size, len(image), "note range outside artifact")
    data, cursor = image[offset : offset + size], 0
    while cursor < size:
        _require(len(records) < MAX_NOTES, "note count outside bound")
        namesz, descsz, kind = _unpack(data, "III", cursor)
        _require(1 < namesz <= MAX_STRING, "empty or oversized note owner")
        begin = cursor + 12
        name_end = begin + namesz
        desc_begin = (name_end + alignment - 1) & ~(alignment - 1)
        desc_end = desc_begin + descsz
        end = (desc_end + alignment - 1) & ~(alignment - 1)
        _range(begin, end - begin, size, "truncated note owner/descriptor/padding")
        owner_bytes = bytes(data[begin:name_end])
        _require(
            owner_bytes[-1:] == b"\0" and b"\0" not in owner_bytes[:-1],
            "invalid note owner terminator",
        )
        owner = _string(data[begin:name_end], 0)
        _require(
            not any(data[name_end:desc_begin]) and not any(data[desc_end:end]),
            "nonzero note padding",
        )
        desc = data[desc_begin:desc_end]
        if PROVENANCE_NAME.search(owner):
            _provenance(owner, "note_owner", findings)
        elif owner == "GNU" and kind == 1:
            _require(descsz == 16 and _unpack(desc, "I", 0)[0] <= 4, "invalid GNU ABI-tag note")
        elif owner == "GNU" and kind == 3:
            _require(1 <= descsz <= 64, "unsupported GNU build-id length")
        elif owner == "GNU" and kind == 5:
            _require(alignment == 8, "GNU property note requires eight-byte alignment")
            _properties(desc, findings)
        else:
            findings.add("unsupported_note_metadata")
            # Only unknown textual note metadata is eligible for marker detection;
            # GNU build IDs/properties and arbitrary executable bytes remain opaque.
            if descsz <= MAX_STRING and all(ch in (9, 10, 13) or 32 <= ch < 127 for ch in desc):
                text = bytes(desc).decode("ascii")
                if PROVENANCE_TEXT.search(text):
                    _provenance(text, "note_descriptor", findings)
        records.add((offset + cursor, offset + end))
        cursor = end


def inspect_elf(data: bytes) -> dict[str, Any]:
    _require(64 <= len(data) <= MAX_BYTES, "artifact size outside bound")
    _require(is_elf(data), "unsupported executable format")
    _require(data[4] == 2, "only ELF64 class is supported")
    _require(data[5] == 1, "only little-endian ELF is supported")
    _require(data[6] == 1, "unsupported identification version")
    _require(data[7] in (0, 3) and data[8] == 0, "unsupported OS/ABI version")
    _require(not any(data[9:16]), "nonzero identification padding")
    image = memoryview(data)
    (
        kind,
        machine,
        version,
        entry,
        phoff,
        shoff,
        flags,
        ehsize,
        phsize,
        phnum,
        shsize,
        shnum,
        names,
    ) = _unpack(image, "HHIQQQIHHHHHH", 16)
    _require(machine == 62, "only AMD64 machine is supported")
    _require(kind in (2, 3), "only ET_EXEC/ET_DYN executables are supported")
    _require(version == 1 and flags == 0, "unsupported header version/flags")
    _require(ehsize == 64 and phsize == 56 and shsize == 64, "unsupported header sizes")
    _require(
        0 < phnum <= MAX_HEADERS and 1 < shnum <= MAX_HEADERS,
        "program/section count outside bound; extended or absent tables unsupported",
    )
    _require(0 < names < shnum, "section-name table index outside table")
    _require(
        phoff >= 64 and shoff >= 64 and phoff % 8 == shoff % 8 == 0,
        "invalid header table offset/alignment",
    )
    _range(phoff, phnum * 56, len(image), "program table outside artifact")
    _range(shoff, shnum * 64, len(image), "section table outside artifact")
    occupied = [(0, 64), (phoff, phoff + phnum * 56), (shoff, shoff + shnum * 64)]
    findings: set[str] = set()
    programs, loads, singletons, note_ranges = [], [], set(), []
    for index in range(phnum):
        record = _unpack(image, "IIQQQQQQ", phoff + index * 56)
        ptype, perms, offset, addr, _, filesz, memsz, align = record
        _require(perms & ~7 == 0 and _aligned(align), "unsupported segment flags/alignment")
        _range(offset, filesz, len(image), "segment outside artifact")
        _range(addr, memsz, U64 + 1, "segment address overflow")
        if ptype not in PROGRAM_TYPES:
            findings.add("unsupported_program_header")
        if ptype in {2, 3, 6, 7, GNU_STACK, GNU_EH_FRAME, GNU_RELRO, GNU_PROPERTY}:
            _require(ptype not in singletons, "duplicate singleton program header")
            singletons.add(ptype)
        if ptype == 1:
            _require(filesz <= memsz, "load segment file size exceeds memory size")
            _require(
                align <= 1 or offset % align == addr % align,
                "load segment address/offset alignment differs",
            )
            loads.append(record)
        elif ptype == 3:
            _require(not loads and 1 < filesz <= MAX_STRING, "invalid interpreter placement/size")
            raw = image[offset : offset + filesz]
            _require(len(_string(raw, 0)) + 1 == filesz, "interpreter contains trailing bytes")
        elif ptype in (4, GNU_PROPERTY):
            note_ranges.append((offset, filesz, align))
        elif ptype == 6:
            _require(
                not loads and offset == phoff and filesz == memsz == phnum * 56,
                "invalid program-header segment",
            )
        programs.append(record)
    _require(
        loads and [p[3] for p in loads] == sorted(p[3] for p in loads),
        "missing or unordered load segments",
    )
    _disjoint([(p[2], p[2] + p[5]) for p in loads], "overlapping load file ranges")
    _disjoint([(p[3], p[3] + p[6]) for p in loads], "overlapping load memory ranges")
    _require(
        any(p[2] == 0 and p[5] >= phoff + phnum * 56 for p in loads),
        "ELF/program headers are not load-mapped",
    )
    _require(
        entry > 0 and any(p[1] & 1 and p[3] <= entry < p[3] + p[5] for p in loads),
        "entry point is not file-backed executable code",
    )
    sections = [_unpack(image, "IIQQQQIIQQ", shoff + i * 64) for i in range(shnum)]
    _require(not any(sections[0]), "unsupported nonzero null section/extended numbering")
    strsec = sections[names]
    _require(
        strsec[1] == 3 and 0 < strsec[5] <= MAX_METADATA_BYTES, "invalid section-name string table"
    )
    _range(strsec[4], strsec[5], len(image), "section-name strings outside artifact")
    name_table = image[strsec[4] : strsec[4] + strsec[5]]
    _require(name_table[0] == name_table[-1] == 0, "invalid section-name string boundaries")
    note_records: set[tuple[int, int]] = set()
    metadata_bytes, comment_strings = 0, 0
    for section in sections[1:]:
        nameoff, stype, sflags, addr, offset, size, link, info, align, entsize = section
        name = _string(name_table, nameoff)
        _require(name and stype != 0, "unsupported unnamed/null section")
        _require(
            _aligned(align) and (align <= 1 or addr % align == 0),
            "invalid section address alignment",
        )
        # GNU_RETAIN is linker ownership metadata; preserve it like SHF_ALLOC.
        _require(sflags & ~0x2007F7 == 0, f"unsupported section flags/compression (0x{sflags:x})")
        _require(
            link < shnum and (not sflags & 0x40 or info < shnum), "section link/info outside table"
        )
        _require(not entsize or size % entsize == 0, "partial fixed-size section entry")
        _range(addr, size, U64 + 1, "section address overflow")
        if stype != 8:
            _range(offset, size, len(image), "section outside artifact")
            _require(align <= 1 or offset % align == 0, "invalid section file alignment")
            occupied.append((offset, offset + size))
        if sflags & 2:
            # TLS NOBITS has its own memory template and can overlap other sections.
            _require(
                any(
                    p[3] <= addr
                    and size <= p[3] + p[6] - addr
                    and (
                        stype == 8
                        or (
                            offset - p[2] == addr - p[3]
                            and p[2] <= offset
                            and size <= p[2] + p[5] - offset
                        )
                    )
                    for p in loads
                ),
                "allocated section is not contained in a load segment",
            )
        else:
            _require(addr == 0, "nonallocated section has memory address")
        if stype not in SECTION_TYPES:
            findings.add("unsupported_section_type")
        explicit = bool(PROVENANCE_NAME.search(name)) and not name.startswith(FUNCTIONAL_PREFIXES)
        if explicit:
            _provenance(name, "section_name", findings)
        elif (
            stype != 7
            and name not in FUNCTIONAL_SECTIONS
            and not name.startswith(
                (".text.", ".rodata.", ".data.", ".bss.", ".debug_", ".rela.", ".rel.", ".relr.")
            )
        ):
            findings.add("unsupported_section_metadata")
        _require(not name.startswith(".note") or stype == 7, "note section has wrong type")
        if stype in (2, 11):
            _require(
                entsize == 24 and sections[link][1] == 3 and info <= size // 24,
                "invalid symbol table/string-table linkage",
            )
        if stype in (4, 9, 19, 6, 14, 15, 16):
            expected = {4: 24, 9: 16, 19: 8, 6: 16, 14: 8, 15: 8, 16: 8}
            _require(
                entsize in (0, 8) if stype in (14, 15, 16) else entsize == expected[stype],
                f"invalid structured section entry size (type={stype}, size={entsize})",
            )
            _require(size % expected[stype] == 0, "partial structured section entry")
        if stype == 3:
            _require(
                size > 0 and image[offset] == image[offset + size - 1] == 0,
                "invalid string-table boundaries",
            )
        if stype == 7 or name == ".comment":
            metadata_bytes += size
            _require(metadata_bytes <= MAX_METADATA_BYTES, "metadata bytes outside bound")
        if stype == 7:
            _notes(image, offset, size, align, findings, note_records)
        elif name == ".comment":
            _require(stype == 1 and not sflags & 2 and size > 0, "invalid compiler comment section")
            raw = bytes(image[offset : offset + size])
            _require(raw[-1] == 0, "unterminated compiler comment")
            values = raw.split(b"\0", MAX_NOTES + 1)
            _require(len(values) <= MAX_NOTES + 1, "compiler comment string count outside bound")
            for value in values:
                _require(len(value) <= MAX_STRING, "compiler comment string outside bound")
                try:
                    text = value.decode("utf-8")
                except UnicodeDecodeError as exc:
                    raise ValueError(
                        "ELF inspection rejected: invalid compiler comment UTF-8"
                    ) from exc
                if PROVENANCE_TEXT.search(text):
                    _provenance(text, "compiler_comment", findings)
                comment_strings += bool(value)
    table_entries = 0
    for section in sections[1:]:
        _, stype, _, _, offset, size, link, _, _, entsize = section
        if stype not in (2, 6, 11):
            continue
        table_entries += size // entsize
        _require(table_entries <= MAX_TABLE_ENTRIES, "symbol/dynamic entry count outside bound")
        linked = sections[link]
        _require(linked[1] == 3, "symbol/dynamic metadata lacks string table")
        _range(linked[4], linked[5], len(image), "linked strings outside artifact")
        strings = image[linked[4] : linked[4] + linked[5]]
        terminated = False
        for cursor in range(offset, offset + size, entsize):
            if stype in (2, 11):
                nameoff, _, _, shindex, _, _ = _unpack(image, "IBBHQQ", cursor)
                _require(
                    shindex < shnum or shindex in (0xFFF1, 0xFFF2),
                    "symbol section index outside table; extended indices unsupported",
                )
                _string_range(strings, nameoff)
            else:
                tag, value = _unpack(image, "qQ", cursor)
                if terminated:
                    _require(tag == value == 0, "nonzero metadata after dynamic terminator")
                elif tag == 0:
                    _require(value == 0, "nonzero dynamic terminator")
                    terminated = True
                elif tag in (1, 14, 15, 29):
                    _string_range(strings, value)
        _require(stype != 6 or terminated, "dynamic metadata lacks terminator")
    _disjoint(occupied, "overlapping sections/header tables")
    previous = 0
    for start, end in sorted((a, b) for a, b in occupied if b > a):
        _require(
            not any(image[previous:start]), "uninspected nonzero bytes outside sections/tables"
        )
        previous = end
    _require(not any(image[previous:]), "uninspected nonzero bytes after sections/tables")
    section_notes = set(note_records)
    _require(
        sum(size for _, size, _ in note_ranges) <= MAX_METADATA_BYTES,
        "program note inspection bytes outside bound",
    )
    for offset, size, alignment in note_ranges:
        records: set[tuple[int, int]] = set()
        _notes(image, offset, size, alignment, findings, records)
        _require(records <= section_notes, "program note lacks matching section metadata")
    for ptype, _, offset, _, _, size, _, _ in programs:
        if ptype in (2, 3, GNU_EH_FRAME):
            expected = {2: ".dynamic", 3: ".interp", GNU_EH_FRAME: ".eh_frame_hdr"}[ptype]
            _require(
                any(
                    _string(name_table, s[0]) == expected and s[4:6] == (offset, size)
                    for s in sections[1:]
                ),
                "program metadata lacks matching section",
            )
    digest = hashlib.sha256(data).hexdigest()
    return {
        "format": "elf",
        "bits": 64,
        "byte_order": "little",
        "machine": "amd64",
        "elf_type": "ET_EXEC" if kind == 2 else "ET_DYN",
        "program_headers": phnum,
        "sections": shnum,
        "notes": len(note_records),
        "compiler_comment_strings_preserved": comment_strings,
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
            "program_headers": MAX_HEADERS,
            "sections": MAX_HEADERS,
            "metadata_bytes": MAX_METADATA_BYTES,
            "notes": MAX_NOTES,
            "metadata_string_bytes": MAX_STRING,
            "symbol_dynamic_entries": MAX_TABLE_ENTRIES,
        },
        "limitations": "Bounded ELF64 little-endian AMD64 executable header/table/segment/section and GNU note/compiler-comment metadata inspection only. Complete section/name tables required. Functional code, data, symbols, linker paths and debug payloads are preserved without semantic or Unicode inspection. Unknown metadata requires review. Not executable validation, signature trust, malware analysis, external-resource inspection, universal watermark absence or authorship proof. No bytes are changed.",
    }


def clean_elf(data: bytes, options: dict[str, Any]) -> dict[str, Any]:
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
    inspected = inspect_elf(data)
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
