"""Bounded, read-only Mach-O executable metadata inspection.

Author: Daniel Hallman

Format references: Apple's mach-o/loader.h, mach-o/fat.h and kern/cs_blobs.h.
No executable is loaded, rewritten, disassembled, decoded as text or trusted.
"""

from __future__ import annotations

import base64
import hashlib
import struct
from typing import Any

MAX_BYTES = 256 << 20
MAX_COMMANDS = 4096
MAX_COMMAND_BYTES = 16 << 20
MAX_ARCHITECTURES = 32
MAX_SECTIONS = 4096
MAX_SIGNATURE_BYTES = 32 << 20
THIN = {
    b"\xfe\xed\xfa\xce": (">", False),
    b"\xce\xfa\xed\xfe": ("<", False),
    b"\xfe\xed\xfa\xcf": (">", True),
    b"\xcf\xfa\xed\xfe": ("<", True),
}
FAT = {
    b"\xca\xfe\xba\xbe": (">", False),
    b"\xbe\xba\xfe\xca": ("<", False),
    b"\xca\xfe\xba\xbf": (">", True),
    b"\xbf\xba\xfe\xca": ("<", True),
}
LINKEDIT = {0x1D, 0x1E, 0x26, 0x29, 0x2E, 0x80000033, 0x80000034}
DYLIB = {0xC, 0xD, 0x80000018, 0x8000001F, 0x20, 0x80000023}
STRINGS = {0xE, 0xF, 0x8000001C, 0x27}
ZERO_FILL = {1, 0xC, 0x12}
# Apple's mach-o/loader.h: explicit supported layouts, not the entire low byte.
# S_DTRACE_DOF (0x0f) carries metadata that needs a dedicated parser.
SECTION_TYPES = {
    0x00,  # S_REGULAR
    0x01,  # S_ZEROFILL
    0x02,  # S_CSTRING_LITERALS
    0x03,  # S_4BYTE_LITERALS
    0x04,  # S_8BYTE_LITERALS
    0x05,  # S_LITERAL_POINTERS
    0x06,  # S_NON_LAZY_SYMBOL_POINTERS
    0x07,  # S_LAZY_SYMBOL_POINTERS
    0x08,  # S_SYMBOL_STUBS
    0x09,  # S_MOD_INIT_FUNC_POINTERS
    0x0A,  # S_MOD_TERM_FUNC_POINTERS
    0x0B,  # S_COALESCED
    0x0C,  # S_GB_ZEROFILL
    0x0D,  # S_INTERPOSING
    0x0E,  # S_16BYTE_LITERALS
    0x10,  # S_LAZY_DYLIB_SYMBOL_POINTERS
    0x11,  # S_THREAD_LOCAL_REGULAR
    0x12,  # S_THREAD_LOCAL_ZEROFILL
    0x13,  # S_THREAD_LOCAL_VARIABLES
    0x14,  # S_THREAD_LOCAL_VARIABLE_POINTERS
    0x15,  # S_THREAD_LOCAL_INIT_FUNCTION_POINTERS
    0x16,  # S_INIT_FUNC_OFFSETS
}
SECTION_ATTRIBUTES = (
    0x80000000  # S_ATTR_PURE_INSTRUCTIONS
    | 0x40000000  # S_ATTR_NO_TOC
    | 0x20000000  # S_ATTR_STRIP_STATIC_SYMS
    | 0x10000000  # S_ATTR_NO_DEAD_STRIP
    | 0x08000000  # S_ATTR_LIVE_SUPPORT
    | 0x04000000  # S_ATTR_SELF_MODIFYING_CODE
    | 0x02000000  # S_ATTR_DEBUG
    | 0x00000400  # S_ATTR_SOME_INSTRUCTIONS
    | 0x00000200  # S_ATTR_EXT_RELOC
    | 0x00000100  # S_ATTR_LOC_RELOC
)
FUNCTIONAL_SECTIONS = {
    "__text",
    "__stubs",
    "__stub_helper",
    "__gcc_except_tab",
    "__const",
    "__cstring",
    "__ustring",
    "__unwind_info",
    "__eh_frame",
    "__mod_init_func",
    "__mod_term_func",
    "__got",
    "__auth_got",
    "__auth_ptr",
    "__la_symbol_ptr",
    "__nl_symbol_ptr",
    "__data",
    "__thread_vars",
    "__thread_data",
    "__thread_bss",
    "__thread_ptrs",
    "__thread_init",
    "__bss",
    "__common",
    "__objc_methname",
    "__objc_methtype",
    "__objc_classname",
    "__objc_classlist",
    "__objc_nlclslist",
    "__objc_catlist",
    "__objc_nlcatlist",
    "__objc_protolist",
    "__objc_imageinfo",
    "__objc_const",
    "__objc_selrefs",
    "__objc_protorefs",
    "__objc_classrefs",
    "__objc_superrefs",
    "__objc_ivar",
    "__objc_data",
}
FUNCTIONAL_SEGMENTS = {
    "__PAGEZERO",
    "__TEXT",
    "__DATA",
    "__DATA_CONST",
    "__DATA_DIRTY",
    "__AUTH",
    "__AUTH_CONST",
    "__LINKEDIT",
}


def is_macho(data: bytes) -> bool:
    return data[:4] in THIN or data[:4] in FAT


def _require(condition: bool, reason: str) -> None:
    if not condition:
        raise ValueError(f"Mach-O inspection rejected: {reason}")


def _range(offset: int, size: int, length: int, reason: str) -> None:
    _require(0 <= offset <= length and 0 <= size <= length - offset, reason)


def _unpack(data: memoryview, endian: str, fmt: str, offset: int) -> tuple[Any, ...]:
    _range(offset, struct.calcsize(endian + fmt), len(data), "truncated structure")
    return struct.unpack_from(endian + fmt, data, offset)


def _disjoint(ranges: list[tuple[int, int]], reason: str) -> None:
    previous = 0
    for start, end in sorted((a, b) for a, b in ranges if b > a):
        _require(start >= previous, reason)
        previous = end


def _zero_gaps(data: memoryview, ranges: list[tuple[int, int]], reason: str) -> None:
    """Unknown bytes outside parsed metadata/mapped payloads cannot certify clean."""
    _disjoint(ranges, reason)
    previous = 0
    for start, end in sorted((a, b) for a, b in ranges if b > a):
        _range(start, end - start, len(data), reason)
        _require(not any(data[previous:start]), reason)
        previous = end
    _require(not any(data[previous:]), reason)


def _name(raw: bytes) -> str:
    name, _, padding = raw.partition(b"\0")
    _require(not padding.strip(b"\0") and all(32 <= b < 127 for b in name), "invalid metadata name")
    return name.decode("ascii")


def _string(data: memoryview, start: int, end: int) -> int:
    _range(start, 1, end, "string offset outside its metadata")
    raw = bytes(data[start : min(end, start + 4096)])
    nul = raw.find(b"\0")
    _require(nul >= 0, "unterminated or oversized metadata string")
    try:
        text = raw[:nul].decode("utf-8")
    except UnicodeDecodeError as exc:
        raise ValueError("Mach-O inspection rejected: invalid metadata string") from exc
    _require(not any(ord(c) < 32 or ord(c) == 127 for c in text), "control byte in metadata string")
    return start + nul + 1


def _code_directory(blob: memoryview, image: memoryview, signature_offset: int) -> dict[str, Any]:
    fields = _unpack(blob, ">", "9I4BI", 0)
    (
        _,
        length,
        version,
        flags,
        hash_offset,
        identifier,
        special,
        slots,
        limit,
        hash_size,
        hash_type,
        _,
        page_exp,
        _,
    ) = fields
    sizes = [
        (0x20000, 44),
        (0x20100, 48),
        (0x20200, 52),
        (0x20300, 64),
        (0x20400, 88),
        (0x20500, 96),
        (0x20600, 108),
    ]
    _require(version in {first for first, _ in sizes}, "unsupported CodeDirectory version")
    minimum = max(size for first, size in sizes if version >= first)
    _require(length == len(blob) and length >= minimum, "truncated CodeDirectory version")
    _require(
        special <= 64 and slots <= 262144 and page_exp <= 30, "CodeDirectory work bound exceeded"
    )
    _require(special == 0, "external/special CodeDirectory metadata is unsupported")
    _require(fields[-1] == 0, "nonzero CodeDirectory reserved field")
    hashes = {1: (20, "sha1"), 2: (32, "sha256"), 3: (20, "sha256"), 4: (48, "sha384")}
    _require(
        hash_type in hashes and hash_size == hashes[hash_type][0], "unsupported CodeDirectory hash"
    )
    _require(hash_offset >= minimum + special * hash_size, "special hash slots underflow metadata")
    _range(hash_offset, slots * hash_size, length, "code hash slots outside CodeDirectory")
    metadata_end = hash_offset - special * hash_size
    _require(minimum <= identifier < metadata_end, "identifier outside CodeDirectory metadata")
    occupied = [
        (0, minimum),
        (identifier, _string(blob, identifier, metadata_end)),
        (metadata_end, hash_offset + slots * hash_size),
    ]
    if version >= 0x20100:
        _require(_unpack(blob, ">", "I", 44)[0] == 0, "scatter CodeDirectory is unsupported")
    if version >= 0x20200:
        team = _unpack(blob, ">", "I", 48)[0]
        if team:
            _require(minimum <= team < metadata_end, "team identifier outside metadata")
            occupied.append((team, _string(blob, team, metadata_end)))
    if version >= 0x20300:
        _require(_unpack(blob, ">", "I", 52)[0] == 0, "nonzero CodeDirectory reserved field")
        wide_limit = _unpack(blob, ">", "Q", 56)[0]
        if limit == 0xFFFFFFFF:
            limit = wide_limit
        else:
            _require(wide_limit in (0, limit), "conflicting CodeDirectory limits")
    _require(
        0 < limit == signature_offset <= len(image),
        "CodeDirectory does not cover all pre-signature bytes",
    )
    if version >= 0x20400:
        base, size, _ = _unpack(blob, ">", "QQQ", 64)
        _range(base, size, limit, "CodeDirectory executable range outside signed bytes")
    if version >= 0x20500:
        _require(_unpack(blob, ">", "I", 92)[0] == 0, "pre-encrypted hashes are unsupported")
    if version >= 0x20600:
        _require(not any(blob[96:108]), "linked CodeDirectory metadata is unsupported")
    _zero_gaps(blob, occupied, "unparsed or overlapping CodeDirectory metadata")
    page = 1 << page_exp if page_exp else limit
    _require(slots == (limit + page - 1) // page, "CodeDirectory page count differs")
    for slot in range(slots):
        begin = slot * page
        digest = hashlib.new(
            hashes[hash_type][1], image[begin : min(begin + page, limit)]
        ).digest()[:hash_size]
        _require(
            bytes(blob[hash_offset + slot * hash_size : hash_offset + (slot + 1) * hash_size])
            == digest,
            "CodeDirectory page hash differs",
        )
    return {
        "code_pages_verified": True,
        "code_slots": slots,
        "ad_hoc": bool(flags & 2),
        "hash_algorithm": hashes[hash_type][1],
        "special_slots_bounds_checked": special,
    }


def _signature(image: memoryview, offset: int, size: int) -> dict[str, Any]:
    _require(12 <= size <= MAX_SIGNATURE_BYTES, "signature size outside bound")
    _range(offset, size, len(image), "signature outside slice")
    blob = image[offset : offset + size]
    magic, length, count = _unpack(blob, ">", "III", 0)
    _require(
        magic == 0xFADE0CC0 and 12 <= length <= size and 1 <= count <= 64,
        "invalid signature SuperBlob",
    )
    _require(
        size - length <= 4096 and not any(blob[length:]), "nonzero or excessive signature padding"
    )
    table_end = 12 + count * 8
    _require(table_end <= length, "truncated signature indices")
    ranges, types, directories = [], set(), []
    for index in range(count):
        kind, start = _unpack(blob, ">", "II", 12 + 8 * index)
        _require(kind not in types and table_end <= start <= length - 8, "invalid signature index")
        types.add(kind)
        child_magic, child_size = _unpack(blob, ">", "II", start)
        _require(child_size >= 8, "short signature child")
        _range(start, child_size, length, "signature child outside SuperBlob")
        ranges.append((start, start + child_size))
        # CMS, entitlements, requirements and launch constraints need their own parser.
        # Never certify an opaque child solely because it carries an Apple magic.
        _require(kind == 0 or 0x1000 <= kind < 0x1005, "unsupported signature child metadata")
        _require(child_magic == 0xFADE0C02, "signature slot is not a CodeDirectory")
        directories.append(_code_directory(blob[start : start + child_size], image, offset))
    _disjoint(ranges, "overlapping signature children")
    _zero_gaps(blob[:length], [(0, table_end), *ranges], "unparsed signature metadata padding")
    _require(0 in types, "signature lacks primary CodeDirectory")
    return {"present": True, "directories": directories, "cryptographic_trust_verified": False}


def _thin(image: memoryview) -> dict[str, Any]:
    _require(bytes(image[:4]) in THIN, "slice is not thin Mach-O")
    endian, wide = THIN[bytes(image[:4])]
    header = 32 if wide else 28
    _, cpu, subtype, filetype, count, command_size, _ = _unpack(image, endian, "7I", 0)
    _require(filetype == 2, "only executable Mach-O filetype is supported")
    if wide:
        _require(_unpack(image, endian, "I", 28)[0] == 0, "nonzero reserved header")
    _require(
        0 < count <= MAX_COMMANDS and 8 * count <= command_size <= MAX_COMMAND_BYTES,
        "load-command bounds exceeded",
    )
    _range(header, command_size, len(image), "truncated load-command table")
    command_end, cursor = header + command_size, header
    segments, sections, links, findings, entries = [], [], [], [], []
    singletons = set()
    symbol_count, dynamic_symbols, signatures = None, None, []
    string_count = 0
    for _ in range(count):
        cmd, size = _unpack(image, endian, "II", cursor)
        _require(size >= 8 and size % (8 if wide else 4) == 0, "unaligned load command")
        _range(cursor, size, command_end, "load command crosses table")
        body = image[cursor : cursor + size]
        if cmd not in DYLIB | STRINGS | {1, 0x19}:
            family = (
                0x22
                if cmd in (0x22, 0x80000022)
                else 0x24
                if cmd in (0x24, 0x25, 0x2F, 0x30, 0x32)
                else cmd
            )
            _require(family not in singletons, "duplicate singleton load command")
            singletons.add(family)
        if cmd in (1, 0x19):
            _require((cmd == 0x19) == wide, "segment width differs from header")
            fmt, base, section_size = ("16sQQQQiiII", 72, 80) if wide else ("16sIIIIiiII", 56, 68)
            name, address, vm_size, file_offset, file_size, maximum, initial, nsects, flags = (
                _unpack(body, endian, fmt, 8)
            )
            name = _name(name)
            if name not in FUNCTIONAL_SEGMENTS:
                findings.append("unsupported_metadata_segment")
            _require(
                nsects <= MAX_SECTIONS and size == base + nsects * section_size,
                "segment section count differs",
            )
            _require(len(sections) + nsects <= MAX_SECTIONS, "section work bound exceeded")
            _require(
                flags & ~0x1F == 0
                and flags & 1 == 0
                and 0 <= initial <= 7
                and 0 <= maximum <= 7
                and initial & ~maximum == 0,
                "unsupported segment mapping/protection",
            )
            _require(
                address + vm_size <= 1 << (64 if wide else 32) and file_size <= vm_size,
                "invalid VM range",
            )
            _range(file_offset, file_size, len(image), "segment file range outside slice")
            segment = (
                file_offset,
                file_offset + file_size,
                address,
                address + vm_size,
                initial,
                name,
            )
            segments.append(segment)
            section_ranges = []
            for section in range(nsects):
                values = _unpack(
                    body,
                    endian,
                    "16s16sQQIIIIIIII" if wide else "16s16sIIIIIIIII",
                    base + section * section_size,
                )
                (
                    section_name,
                    segment_name,
                    start,
                    length,
                    offset,
                    align,
                    reloc,
                    nreloc,
                    section_flags,
                    *_,
                ) = values
                section_name, segment_name = _name(section_name), _name(segment_name)
                section_type = section_flags & 0xFF
                if section_type not in SECTION_TYPES:
                    findings.append("unsupported_section_type")
                if section_flags & ~(SECTION_ATTRIBUTES | 0xFF):
                    findings.append("unsupported_section_attributes")
                _require(
                    segment_name == name
                    and address <= start <= address + vm_size
                    and length <= address + vm_size - start,
                    "section outside segment VM range",
                )
                _require(
                    align <= 31 and nreloc <= 1_000_000,
                    "section alignment/relocation bound exceeded",
                )
                if nreloc:
                    _range(reloc, nreloc * 8, len(image), "relocations outside slice")
                if section_type not in ZERO_FILL and length:
                    _require(
                        file_offset <= offset and length <= file_offset + file_size - offset,
                        "section outside segment file range",
                    )
                    _require(offset % (1 << align) == 0, "section file alignment differs")
                    section_ranges.append((offset, offset + length))
                pointer = 8 if wide else 4
                element_size = {
                    0x03: 4,
                    0x04: 8,
                    0x05: pointer,
                    0x06: pointer,
                    0x07: pointer,
                    0x09: pointer,
                    0x0A: pointer,
                    0x0D: 2 * pointer,
                    0x0E: 16,
                    0x10: pointer,
                    0x13: 3 * pointer,
                    0x14: pointer,
                    0x15: pointer,
                    0x16: 4,
                }.get(section_type, 1)
                if length % element_size:
                    findings.append("unsupported_section_layout")
                if section_type == 0x02 and length and image[offset + length - 1] != 0:
                    findings.append("unsupported_section_layout")
                if section_type == 0x08 and length and (values[10] == 0 or length % values[10]):
                    findings.append("unsupported_section_layout")
                if section_flags & 0x02000000 and section_type != 0x00:
                    findings.append("unsupported_section_layout")
                if any(
                    mark in section_name.lower() or mark in name.lower()
                    for mark in ("c2pa", "synthid", "ai-generated")
                ):
                    findings.append("explicit_provenance_section_name")
                if section_name == "__info_plist" or name == "__LLVM":
                    findings.append("unsupported_embedded_metadata_section")
                if section_name not in FUNCTIONAL_SECTIONS:
                    findings.append("unsupported_section_metadata")
                sections.append((section_name, length))
            _disjoint(section_ranges, "overlapping section file ranges")
        elif cmd == 2:
            _require(size == 24 and symbol_count is None, "invalid or duplicate symbol table")
            symbols, symbol_count, strings, string_size = _unpack(body, endian, "IIII", 8)
            _range(
                symbols,
                symbol_count * (16 if wide else 12),
                len(image),
                "symbol table outside slice",
            )
            _range(strings, string_size, len(image), "string table outside slice")
            if symbol_count:
                links.append((symbols, symbol_count * (16 if wide else 12)))
            if string_size:
                links.append((strings, string_size))
        elif cmd == 0xB:
            _require(size == 80 and dynamic_symbols is None, "invalid or duplicate dynamic symbols")
            dynamic_symbols = _unpack(body, endian, "18I", 8)
        elif cmd in DYLIB or cmd in STRINGS:
            minimum = 24 if cmd in DYLIB else 12
            _require(size >= minimum, "truncated functional load string")
            start = _unpack(body, endian, "I", 8)[0]
            _require(minimum <= start < size, "load string offset outside command")
            string_end = _string(body, start, size)
            _require(
                not any(body[minimum:start]) and not any(body[string_end:]),
                "unparsed load-string metadata padding",
            )
            string_count += 1
            if cmd == 0x27:
                findings.append("dyld_environment_requires_review")
        elif cmd in LINKEDIT:
            _require(size == 16, "invalid link-edit command size")
            offset, length = _unpack(body, endian, "II", 8)
            _range(offset, length, len(image), "link-edit range outside slice")
            if length:
                _require(offset >= command_end, "link-edit data overlaps load commands")
                links.append((offset, length))
            if cmd == 0x1D:
                _require(not signatures and length > 0, "duplicate or empty code signature")
                signatures.append((offset, length))
            if cmd == 0x29:
                _require(length % 8 == 0, "truncated data-in-code entries")
        elif cmd in (0x22, 0x80000022):
            _require(size == 48, "invalid dyld-info command size")
            values = _unpack(body, endian, "10I", 8)
            for offset, length in zip(values[::2], values[1::2], strict=True):
                _range(offset, length, len(image), "dyld-info range outside slice")
                if length:
                    links.append((offset, length))
        elif cmd == 0x1B:
            _require(size == 24, "invalid UUID command size")
        elif cmd == 0x32:
            _require(size >= 24, "truncated build-version command")
            tools = _unpack(body, endian, "I", 20)[0]
            _require(tools <= 64 and size == 24 + tools * 8, "build-version tool count differs")
        elif cmd in (0x24, 0x25, 0x2F, 0x30, 0x2A):
            _require(size == 16, "invalid version command size")
        elif cmd == 0x80000028:
            _require(size == 24 and not entries, "invalid or duplicate entry point")
            entries.append(_unpack(body, endian, "Q", 8)[0])
        else:
            findings.append("unsupported_load_command")
        cursor += size
    _require(cursor == command_end, "load-command sizes do not match header")
    _require(
        segments and any(seg[4] & 4 and seg[1] > seg[0] for seg in segments),
        "no file-backed executable segment",
    )
    _disjoint([(s[0], s[1]) for s in segments], "overlapping file-backed segments")
    _zero_gaps(image, [(s[0], s[1]) for s in segments], "unparsed bytes outside mapped segments")
    _disjoint([(s[2], s[3]) for s in segments], "overlapping segment VM ranges")
    _require(
        any(s[0] == 0 and s[1] >= command_end for s in segments),
        "headers are not mapped by a segment",
    )
    _require(
        len(entries) == 1
        and any(s[0] <= entries[0] < s[1] and s[4] & 4 for s in segments)
        and entries[0] >= command_end,
        "entry point is not file-backed executable code",
    )
    if dynamic_symbols is not None:
        _require(symbol_count is not None, "dynamic symbols lack symbol table")
        for begin, length in zip(dynamic_symbols[:6:2], dynamic_symbols[1:6:2], strict=True):
            _range(begin, length, symbol_count, "dynamic symbol indices outside symbol table")
        for i, stride in [(6, 8), (8, 56 if wide else 52), (10, 4), (12, 4), (14, 8), (16, 8)]:
            offset, length = dynamic_symbols[i : i + 2]
            _range(offset, length * stride, len(image), "dynamic symbol metadata outside slice")
            if length:
                links.append((offset, length * stride))
    for offset, length in links:
        _require(
            any(
                s[5] == "__LINKEDIT" and s[0] <= offset and length <= s[1] - offset
                for s in segments
            ),
            "link-edit metadata is not contained in __LINKEDIT",
        )
    _disjoint(
        [(offset, offset + length) for offset, length in links], "overlapping link-edit payloads"
    )
    for segment in segments:
        if segment[5] == "__LINKEDIT":
            begin, end = segment[:2]
            _zero_gaps(
                image[begin:end],
                [(offset - begin, offset + length - begin) for offset, length in links],
                "unparsed link-edit metadata",
            )
    if cpu not in {7, 12, 18, 0x1000007, 0x100000C, 0x1000012}:
        findings.append("unsupported_cpu_type")
    else:
        _require(wide == bool(cpu & 0x1000000), "CPU width differs from Mach-O header")
    if signatures:
        _require(sum(signatures[0]) == len(image), "uninspected bytes after code signature")
    signature = (
        _signature(image, *signatures[0])
        if signatures
        else {"present": False, "cryptographic_trust_verified": False}
    )
    return {
        "bits": 64 if wide else 32,
        "byte_order": "little" if endian == "<" else "big",
        "cpu_type": cpu,
        "cpu_subtype": subtype,
        "load_commands": count,
        "segments": len(segments),
        "sections": len(sections),
        "functional_load_strings_preserved": string_count,
        "signature": signature,
        "findings": sorted(set(findings)),
    }


def inspect_macho(data: bytes) -> dict[str, Any]:
    _require(0 < len(data) <= MAX_BYTES, "artifact size outside bound")
    _require(is_macho(data), "unsupported executable format")
    image = memoryview(data)
    if data[:4] in THIN:
        slices = [_thin(image)]
        container = "thin"
    else:
        endian, wide = FAT[data[:4]]
        # fat.h specifies big-endian on-disk headers. FAT_CIGAM constants
        # describe a swapped native view, not a second on-disk encoding.
        _require(endian == ">", "little-endian fat-container encoding is unsupported")
        count = _unpack(image, endian, "I", 4)[0]
        _require(0 < count <= MAX_ARCHITECTURES, "fat architecture count outside bound")
        entry_size, ranges, slices, cpus, records = 32 if wide else 20, [], [], set(), []
        table_end = 8 + count * entry_size
        _range(0, table_end, len(image), "truncated fat architecture table")
        for index in range(count):
            values = _unpack(image, endian, "IIQQII" if wide else "IIIII", 8 + index * entry_size)
            cpu, subtype, offset, size, align = values[:5]
            _require(not wide or values[5] == 0, "nonzero fat reserved field")
            _require(
                align <= 30 and offset % (1 << align) == 0 and offset >= table_end,
                "invalid fat slice alignment or offset",
            )
            _range(offset, size, len(image), "fat slice outside artifact")
            architecture = (cpu, subtype & 0xFFFFFF)
            _require(architecture not in cpus, "duplicate fat architecture")
            cpus.add(architecture)
            ranges.append((offset, offset + size))
            records.append((cpu, subtype, offset, size))
        _disjoint(ranges, "overlapping fat slices")
        previous = table_end
        for start, end in sorted(ranges):
            _require(not any(image[previous:start]), "uninspected nonzero fat-container padding")
            previous = end
        _require(not any(image[previous:]), "uninspected bytes after fat slices")
        for cpu, subtype, offset, size in records:
            parsed = _thin(image[offset : offset + size])
            _require(
                (cpu, subtype) == (parsed["cpu_type"], parsed["cpu_subtype"]),
                "fat CPU differs from slice",
            )
            slices.append(parsed)
        container = "fat64" if wide else "fat32"
    findings = sorted({finding for item in slices for finding in item["findings"]})
    digest = hashlib.sha256(data).hexdigest()
    return {
        "format": "mach-o",
        "container": container,
        "architecture_count": len(slices),
        "slices": slices,
        "findings": findings,
        "has_ai_metadata": "explicit_provenance_section_name" in findings,
        "changed": False,
        "input_sha256": digest,
        "output_sha256": digest,
        "release_ready": not findings,
        "review_required": bool(findings),
        "limits": {
            "artifact_bytes": MAX_BYTES,
            "load_commands_per_slice": MAX_COMMANDS,
            "load_command_bytes_per_slice": MAX_COMMAND_BYTES,
            "architectures": MAX_ARCHITECTURES,
            "sections_per_slice": MAX_SECTIONS,
            "signature_bytes_per_slice": MAX_SIGNATURE_BYTES,
        },
        "limitations": "Bounded executable/load-command/segment/link-edit/code-signature structure inspection; CodeDirectory page hashes verified when present. Not signature trust, malware analysis, semantic inspection of code/data, external resources, or universal watermark/authorship proof. Unknown load commands or provenance-like section metadata require review. No bytes are changed.",
    }


def clean_macho(data: bytes, options: dict[str, Any]) -> dict[str, Any]:
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
    inspected = inspect_macho(data)
    unresolved = bool(inspected["findings"])
    status = "requires_review" if unresolved else "inspected_no_change"
    digest = hashlib.sha256(data).hexdigest()
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
            "input_sha256": digest,
            "output_sha256": digest,
            "actions": [],
            "before": inspected,
            "after": inspected,
            "limitations": inspected["limitations"],
        },
    }
    if not unresolved:
        result["cleaned"] = base64.b64encode(data).decode("ascii")
    return result
