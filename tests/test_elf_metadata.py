"""Read-only ELF executable inspection: structural rejection and exact bytes.

Author: Daniel Hallman
"""

from __future__ import annotations

import base64
import hashlib
import json
import os
import struct
import subprocess
import threading
from http.server import ThreadingHTTPServer
from pathlib import Path

import elf_metadata as elf
import pytest
import server


def note(owner=b"GNU", kind=3, desc=bytes(range(20)), align=4):
    name = owner + b"\0"
    raw = struct.pack("<III", len(name), len(desc), kind) + name
    raw += bytes((-len(raw)) % align)
    raw += desc
    return raw + bytes((-len(raw)) % align)


def executable(
    *,
    kind=3,
    note_data=None,
    note_name=b".note.gnu.build-id",
    note_align=4,
    comment=b"GCC: (GNU) 15.2.0\0rustc version 1.90.0\0",
    extra=(),
    program_note=False,
):
    phnum = 2 if program_note else 1
    cursor = (64 + phnum * 56 + 15) & ~15
    entry = cursor
    section_data = [
        (b".text", 1, 6, 16, b"C2PA AI-generated SynthID\xff\x00".ljust(64, b"\x90"), 0, 0, 0),
        (b".rodata", 1, 2, 8, b"AI-generated C2PA\x00\xe2\x80\x8b".ljust(32, b"\0"), 0, 0, 0),
        (note_name, 7, 2, note_align, note() if note_data is None else note_data, 0, 0, 0),
        (b".comment", 1, 0, 1, comment, 0, 0, 0),
        *extra,
    ]
    string_table = b"\0" + b"\0".join(s[0] for s in section_data) + b"\0.shstrtab\0"
    section_data.append((b".shstrtab", 3, 0, 1, string_table, 0, 0, 0))
    base = 0 if kind == 3 else 0x400000
    body, sections, name_cursor = bytearray(cursor), [bytes(64)], 1
    for name, stype, flags, align, payload, link, info, entsize in section_data:
        offset = (len(body) + align - 1) & ~(align - 1)
        body.extend(bytes(offset - len(body)))
        body.extend(payload)
        sections.append(
            struct.pack(
                "<IIQQQQIIQQ",
                name_cursor,
                stype,
                flags,
                base + offset if flags & 2 else 0,
                offset,
                len(payload),
                link,
                info,
                align,
                entsize,
            )
        )
        name_cursor += len(name) + 1
    shoff = (len(body) + 7) & ~7
    body.extend(bytes(shoff - len(body)))
    body.extend(b"".join(sections))
    body[:64] = (
        b"\x7fELF\x02\x01\x01"
        + bytes(9)
        + struct.pack(
            "<HHIQQQIHHHHHH",
            kind,
            62,
            1,
            base + entry,
            64,
            shoff,
            0,
            64,
            56,
            phnum,
            64,
            len(sections),
            len(sections) - 1,
        )
    )
    body[64:120] = struct.pack("<IIQQQQQQ", 1, 5, 0, base, base, len(body), len(body), 0x1000)
    if program_note:
        fields = struct.unpack("<IIQQQQIIQQ", sections[3])
        offset, size = fields[4:6]
        body[120:176] = struct.pack(
            "<IIQQQQQQ", 4, 4, offset, base + offset, base + offset, size, size, note_align
        )
    return bytes(body)


def replace(data, offset, fmt, *values):
    result = bytearray(data)
    struct.pack_into("<" + fmt, result, offset, *values)
    return bytes(result)


def section_offset(data, index):
    return struct.unpack_from("<Q", data, 40)[0] + 64 * index


def section_payload(data, index):
    return struct.unpack_from("<QQ", data, section_offset(data, index) + 24)


@pytest.mark.parametrize("kind", [2, 3])
@pytest.mark.parametrize("filename", ["program", "program.elf", "program.rs", "program.png"])
def test_valid_executable_routes_by_magic_without_backends(kind, filename, monkeypatch):
    for name in (
        "clean_text",
        "_apply_layer_b",
        "run_all_text_detectors",
        "score_text_stylometry",
        "clean_image",
        "inspect_image",
        "run_synthid_score",
    ):
        monkeypatch.setattr(server, name, lambda *a, **kw: pytest.fail("backend called"))
    data = executable(kind=kind)
    result = server._clean_payload(data, filename, {})
    assert result["kind"] == "executable"
    assert result["status"] == "inspected_no_change"
    assert base64.b64decode(result["cleaned"]) == data
    report = result["report"]
    assert report["input_sha256"] == report["output_sha256"] == hashlib.sha256(data).hexdigest()
    assert report["mode"] == "deterministic_only"
    assert report["changed"] is False and report["actions"] == []
    assert report["release_ready"] is True and report["review_required"] is False
    assert report["before"]["elf_type"] == ("ET_EXEC" if kind == 2 else "ET_DYN")
    inspected = server._inspect_payload(data, filename, False)
    assert inspected["kind"] == "executable"
    assert inspected["suspicious"]["verdict"] is False
    assert "AI-generated" not in str(report)


@pytest.mark.parametrize(
    "data", [b"", b"ELF", b"\x7fELF", b"\x7fELF" + bytes(59), b"MZ" + bytes(128)]
)
def test_short_wrong_format_never_clean(data):
    with pytest.raises(ValueError):
        elf.inspect_elf(data)


@pytest.mark.parametrize(
    "offset,fmt,value,message",
    [
        (4, "B", 1, "ELF64"),
        (5, "B", 2, "little-endian"),
        (6, "B", 2, "version"),
        (7, "B", 9, "OS/ABI"),
        (8, "B", 1, "OS/ABI"),
        (9, "B", 1, "padding"),
        (16, "H", 1, "ET_EXEC/ET_DYN"),
        (18, "H", 183, "AMD64"),
        (20, "I", 2, "version"),
        (24, "Q", 0, "entry"),
        (24, "Q", 2**64 - 1, "entry"),
        (32, "Q", 2**64 - 8, "program table"),
        (32, "Q", 65, "offset/alignment"),
        (40, "Q", 2**64 - 8, "section table"),
        (48, "I", 1, "flags"),
        (52, "H", 63, "sizes"),
        (54, "H", 48, "sizes"),
        (56, "H", 4097, "count"),
        (56, "H", 0xFFFF, "count"),
        (58, "H", 56, "sizes"),
        (60, "H", 0, "count"),
        (62, "H", 0xFFFF, "index"),
        (62, "H", 0, "index"),
        (64 + 4, "I", 8, "flags"),
        (64 + 16, "Q", 1, "alignment"),
        (64 + 32, "Q", 2**64 - 1, "segment outside"),
        (64 + 40, "Q", 1, "exceeds memory"),
        (64 + 48, "Q", 3, "alignment"),
    ],
)
def test_header_and_segment_errors_rejected(offset, fmt, value, message):
    with pytest.raises(ValueError, match=message):
        server._clean_payload(replace(executable(), offset, fmt, value), "program", {})


@pytest.mark.parametrize(
    "relative,fmt,value,message",
    [
        (0, "I", 0xFFFF, "string offset"),
        (4, "I", 0, "null section"),
        (8, "Q", 0x800, "compression"),
        (16, "Q", 1, "alignment"),
        (24, "Q", 2**64 - 1, "outside artifact"),
        (32, "Q", 2**64 - 1, "address overflow"),
        (40, "I", 999, "link/info"),
        (48, "Q", 3, "alignment"),
        (56, "Q", 3, "partial"),
    ],
)
def test_section_errors_rejected(relative, fmt, value, message):
    data = executable()
    with pytest.raises(ValueError, match=message):
        elf.inspect_elf(replace(data, section_offset(data, 1) + relative, fmt, value))


def test_sections_tables_and_padding_must_not_overlap_or_hide_bytes():
    data = executable()
    with pytest.raises(ValueError, match="null section"):
        elf.inspect_elf(replace(data, section_offset(data, 0), "I", 1))
    with pytest.raises(ValueError, match="overlapping"):
        elf.inspect_elf(replace(data, section_offset(data, 2) + 16, "QQ", 128, 128))
    with pytest.raises(ValueError, match="nonzero bytes"):
        elf.inspect_elf(data + b"c2pa trailing data")
    assert elf.inspect_elf(data + bytes(16))["release_ready"] is True
    with pytest.raises(ValueError, match="outside artifact"):
        elf.inspect_elf(data[:-1])


@pytest.mark.parametrize(
    "payload,align,message",
    [
        (b"\0", 4, "truncated"),
        (note()[:-1], 4, "truncated"),
        (replace(note(), 0, "I", 4097), 4, "oversized"),
        (replace(note(), 4, "I", 2**32 - 1), 4, "truncated"),
        (replace(note(), 15, "B", 65), 4, "terminator"),
        (replace(note(owner=b"TESTX"), 18, "B", 88), 4, "padding"),
        (note(kind=1, desc=bytes(15)), 4, "ABI-tag"),
        (note(kind=3, desc=bytes(65)), 4, "build-id"),
        (note(), 2, "alignment"),
        (note(kind=5, desc=struct.pack("<III", 0xC0000002, 4, 3)), 4, "eight-byte"),
        (note(kind=5, desc=struct.pack("<IIQ", 0xC0000002, 8, 3), align=8), 8, "property size"),
    ],
)
def test_malformed_note_is_error(payload, align, message):
    with pytest.raises(ValueError, match=message):
        elf.inspect_elf(executable(note_data=payload, note_align=align))


def test_legitimate_gnu_notes_preserved_and_program_note_duplicate_inspection():
    for payload, alignment in [
        (note(), 4),
        (note(kind=1, desc=struct.pack("<4I", 0, 3, 2, 0)), 4),
        (note(kind=5, desc=struct.pack("<III", 0xC0000002, 4, 3) + bytes(4), align=8), 8),
    ]:
        data = executable(note_data=payload, note_align=alignment, program_note=True)
        result = elf.clean_elf(data, {})
        assert result["status"] == "inspected_no_change"
        assert result["report"]["before"]["notes"] == 1
        assert base64.b64decode(result["cleaned"]) == data


@pytest.mark.parametrize(
    "kwargs,finding",
    [
        ({"note_name": b".note.c2pa"}, "explicit_provenance_section_name"),
        ({"note_data": note(owner=b"C2PA", desc=b"manifest")}, "explicit_provenance_note_owner"),
        ({"comment": b"AI-generated by ChatGPT\0"}, "explicit_provenance_compiler_comment"),
        ({"note_data": note(owner=b"UNKNOWN")}, "unsupported_note_metadata"),
        (
            {"extra": [(b".custom_metadata", 1, 0, 1, b"opaque", 0, 0, 0)]},
            "unsupported_section_metadata",
        ),
    ],
)
def test_provenance_and_unknown_metadata_require_review_without_output(kwargs, finding):
    data = executable(**kwargs)
    result = server._clean_payload(data, "program", {"deterministic_only": True})
    assert result["status"] == "requires_review"
    assert "cleaned" not in result
    assert finding in result["report"]["before"]["findings"]
    assert result["report"]["changed"] is False
    assert result["report"]["release_ready"] is False
    assert result["report"]["input_sha256"] == result["report"]["output_sha256"]
    inspected = server._inspect_payload(data, "program", False)
    assert inspected["suspicious"]["verdict"] is True


def test_metadata_signals_do_not_confuse_ai_with_c2pa_or_function_names():
    result = elf.inspect_elf(executable(comment=b"AI-generated by ChatGPT\0"))
    assert result["has_ai_metadata"] is True
    assert result["has_c2pa"] is False
    result = elf.inspect_elf(executable(note_data=note(owner=b"C2PA")))
    assert result["has_c2pa"] is True
    assert (
        elf.inspect_elf(
            executable(
                extra=[
                    (b".text.openai", 1, 6, 8, b"c2pa AI-generated", 0, 0, 0),
                    (b".data.c2pa", 1, 3, 8, b"chatgpt\0", 0, 0, 0),
                ]
            )
        )["release_ready"]
        is True
    )
    result = elf.inspect_elf(
        executable(note_data=note(owner=b"TOOL", desc=b"AI-generated by ChatGPT"))
    )
    assert "explicit_provenance_note_descriptor" in result["findings"]


def symbol_fixture(*, nameoff=1, shindex=1, dynamic_string=1, terminate=True):
    symbols = bytes(24) + struct.pack("<IBBHQQ", nameoff, 0, 0, shindex, 0, 0)
    dynamic = struct.pack("<qQ", 1, dynamic_string) + (bytes(16) if terminate else b"")
    return executable(
        extra=[
            (b".strtab", 3, 0, 1, b"\0openai_c2pa_function\0", 0, 0, 0),
            (b".symtab", 2, 0, 8, symbols, 5, 1, 24),
            (b".dynamic", 6, 2, 8, dynamic, 5, 0, 16),
        ]
    )


def test_functional_symbol_and_dynamic_strings_are_bounded_without_provenance_scan():
    result = elf.inspect_elf(symbol_fixture())
    assert result["release_ready"] is True
    with pytest.raises(ValueError, match="string offset"):
        elf.inspect_elf(symbol_fixture(nameoff=0xFFFF))
    with pytest.raises(ValueError, match="symbol section index"):
        elf.inspect_elf(symbol_fixture(shindex=0xFFFF))
    with pytest.raises(ValueError, match="string offset"):
        elf.inspect_elf(symbol_fixture(dynamic_string=0xFFFF))
    with pytest.raises(ValueError, match="lacks terminator"):
        elf.inspect_elf(symbol_fixture(terminate=False))


def test_linker_retain_and_array_metadata_preserved_and_array_width_required():
    data = executable(extra=[(b".init_array", 14, 0x200003, 8, bytes(8), 0, 0, 0)])
    assert elf.inspect_elf(data)["release_ready"] is True
    data = executable(extra=[(b".init_array", 14, 0x200003, 8, bytes(7), 0, 0, 0)])
    with pytest.raises(ValueError, match="partial structured"):
        elf.inspect_elf(data)


def test_unknown_program_type_and_gnu_property_require_review_without_output():
    data = executable(program_note=True)
    assert elf.clean_elf(replace(data, 120, "I", 0x70000000), {})["status"] == "requires_review"
    unknown = note(kind=5, desc=struct.pack("<II", 0xC000BEEF, 0), align=8)
    assert (
        elf.clean_elf(executable(note_data=unknown, note_align=8), {})["status"]
        == "requires_review"
    )


def test_work_bounds_and_no_note_or_comment_truncation(monkeypatch):
    with pytest.raises(ValueError, match="unterminated compiler"):
        elf.inspect_elf(executable(comment=b"compiler string without terminator"))
    with pytest.raises(ValueError, match="comment UTF-8"):
        elf.inspect_elf(executable(comment=b"\xff\0"))
    monkeypatch.setattr(elf, "MAX_NOTES", 1)
    with pytest.raises(ValueError, match="note count"):
        elf.inspect_elf(executable(note_data=note() + note()))
    monkeypatch.setattr(elf, "MAX_METADATA_BYTES", 64)
    with pytest.raises(ValueError, match="metadata bytes"):
        elf.inspect_elf(executable(comment=b"x" * 100 + b"\0"))


@pytest.mark.skipif(
    not os.environ.get("ELF_ACCEPTANCE_CLIENT"), reason="explicit installed native client only"
)
def test_native_client_exact_output_and_review_refusal(tmp_path, monkeypatch):
    for name in ("clean_text", "_apply_layer_b", "run_all_text_detectors", "score_text_stylometry"):
        monkeypatch.setattr(server, name, lambda *a, **kw: pytest.fail("backend called"))
    service = ThreadingHTTPServer(("127.0.0.1", 0), server.Handler)
    thread = threading.Thread(target=service.serve_forever, daemon=True)
    thread.start()
    environment = {
        **os.environ,
        "WATERMARKS_SERVICE_URL": f"http://127.0.0.1:{service.server_port}",
    }
    client = os.environ["ELF_ACCEPTANCE_CLIENT"]
    try:
        source, output = tmp_path / "program.elf", tmp_path / "program.inspected.elf"
        data = executable()
        source.write_bytes(data)
        result = subprocess.run(
            [client, "--deterministic-only", "--json-report", "--output", str(output), str(source)],
            env=environment,
            capture_output=True,
            timeout=30,
            check=False,
        )
        assert result.returncode == 0, result.stderr
        assert source.read_bytes() == output.read_bytes() == data
        assert b"inspected_no_change" in result.stderr
        output.unlink()
        flagged = executable(comment=b"AI-generated by ChatGPT\0")
        source.write_bytes(flagged)
        for arguments in (["--output", str(output)], ["--in-place"]):
            result = subprocess.run(
                [client, "--deterministic-only", "--json-report", *arguments, str(source)],
                env=environment,
                capture_output=True,
                timeout=30,
                check=False,
            )
            assert result.returncode != 0
            assert b"service response did not include cleaned bytes" in result.stderr
            assert not output.exists()
            assert source.read_bytes() == flagged
            assert sorted(path.name for path in tmp_path.iterdir()) == ["program.elf"]
        source.write_bytes(data[:-1])
        result = subprocess.run(
            [client, "--deterministic-only", "--output", str(output), str(source)],
            env=environment,
            capture_output=True,
            timeout=30,
            check=False,
        )
        assert result.returncode != 0 and not output.exists()
    finally:
        service.shutdown()
        service.server_close()
        thread.join(timeout=5)


@pytest.mark.parametrize(
    "option",
    [
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
    ],
)
def test_transform_and_detector_requests_rejected(option):
    with pytest.raises(ValueError, match="transformations"):
        server._clean_payload(executable(), "program", {option: True})


def test_detector_routes_capabilities_and_openapi_contract():
    with pytest.raises(ValueError, match="detectors"):
        server._inspect_payload(executable(), "program", True)
    with pytest.raises(ValueError, match="detectors"):
        server._detect_payload(executable(), "program")
    assert server.capabilities()["cleaning_modes"]["elf64_amd64_executable_inspection"] is True
    props = server.openapi_spec()["paths"]["/capabilities"]["get"]["responses"]["200"]["content"][
        "application/json"
    ]["schema"]["properties"]
    assert "elf64_amd64_executable_inspection" in props["cleaning_modes"]["properties"]


@pytest.mark.skipif(
    not os.environ.get("ELF_ACCEPTANCE_ARTIFACT"), reason="explicit operator artifact only"
)
def test_explicit_operator_artifact_read_only_acceptance():
    path = Path(os.environ["ELF_ACCEPTANCE_ARTIFACT"])
    expected = os.environ["ELF_ACCEPTANCE_SHA256"]
    before = path.stat()
    data = path.read_bytes()
    assert hashlib.sha256(data).hexdigest() == expected
    result = server._inspect_payload(data, path.name, False)
    report = result["report"]
    assert result["kind"] == "executable"
    assert report["release_ready"] is True
    assert report["input_sha256"] == report["output_sha256"] == expected
    assert report["changed"] is False
    after = path.stat()
    assert (before.st_size, before.st_mtime_ns, before.st_ino) == (
        after.st_size,
        after.st_mtime_ns,
        after.st_ino,
    )
    assert hashlib.sha256(path.read_bytes()).hexdigest() == expected
    if os.environ.get("ELF_ACCEPTANCE_REPORT"):
        receipt = Path(os.environ["ELF_ACCEPTANCE_REPORT"])
        receipt.write_text(
            json.dumps(
                {
                    "runtime": "Python 3.12",
                    "input": str(path),
                    "stat_unchanged": True,
                    "result": result,
                },
                indent=2,
            )
            + "\n"
        )
