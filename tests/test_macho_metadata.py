"""Exact-byte executable inspection, never a machine-code text rewrite.

Author: Daniel Hallman
"""

from __future__ import annotations

import base64
import hashlib
import http.client
import json
import os
import struct
import subprocess
import threading
from http.server import ThreadingHTTPServer
from pathlib import Path

import macho_metadata as macho
import pytest
import server


def command(code, payload=b"", *, endian="<", wide=True):
    alignment = 8 if wide else 4
    size = (8 + len(payload) + alignment - 1) // alignment * alignment
    return struct.pack(endian + "II", code, size) + payload.ljust(size - 8, b"\0")


def thin(
    *, wide=True, endian="<", cpu=None, subtype=0, extra=(), section_name=b"__text", signed=False
):
    cpu = cpu if cpu is not None else 0x100000C if wide else 12
    header_size, base, section_size = (32, 72, 80) if wide else (28, 56, 68)
    extras = list(extra)
    if signed:
        extras.append(command(0x1D, struct.pack(endian + "II", 512, 148), endian=endian, wide=wide))
    command_size = base + section_size + (72 if signed else 0) + 24 + sum(map(len, extras))
    entry = (header_size + command_size + 15) // 16 * 16
    size = 512 if signed else entry + 64
    assert entry + 64 <= size
    vm = 0x100000000 if wide else 0x1000
    if wide:
        segment = struct.pack(
            endian + "II16sQQQQiiII",
            0x19,
            base + section_size,
            b"__TEXT",
            vm,
            size,
            0,
            size,
            5,
            5,
            1,
            0,
        )
        section = struct.pack(
            endian + "16s16sQQIIIIIIII",
            section_name,
            b"__TEXT",
            vm + entry,
            64,
            entry,
            4,
            0,
            0,
            0,
            0,
            0,
            0,
        )
    else:
        segment = struct.pack(
            endian + "II16sIIIIiiII",
            1,
            base + section_size,
            b"__TEXT",
            vm,
            size,
            0,
            size,
            5,
            5,
            1,
            0,
        )
        section = struct.pack(
            endian + "16s16sIIIIIIIII",
            section_name,
            b"__TEXT",
            vm + entry,
            64,
            entry,
            4,
            0,
            0,
            0,
            0,
            0,
        )
    commands = segment + section
    if signed:
        commands += struct.pack(
            endian + "II16sQQQQiiII",
            0x19,
            72,
            b"__LINKEDIT",
            0x200000000,
            148,
            512,
            148,
            1,
            1,
            0,
            0,
        )
    commands += command(
        0x80000028, struct.pack(endian + "QQ", entry, 0), endian=endian, wide=wide
    ) + b"".join(extras)
    header = struct.pack(
        endian + "7I",
        0xFEEDFACF if wide else 0xFEEDFACE,
        cpu,
        subtype,
        2,
        3 + len(extras) if signed else 2 + len(extras),
        command_size,
        0,
    )
    if wide:
        header += struct.pack(endian + "I", 0)
    image = bytearray((header + commands).ljust(size, b"\0"))
    # These are functional opaque code/data bytes, not text-cleaning candidates.
    image[entry : entry + 64] = b"AI-generated C2PA SynthID\xff\x00".ljust(64, b"\x90")
    if signed:
        directory = struct.pack(
            ">9I4BI", 0xFADE0C02, 128, 0x20400, 2, 96, 88, 0, 1, 512, 32, 2, 0, 12, 0
        )
        directory += struct.pack(">IIIQQQQ", 0, 0, 0, 0, 0, 512, 1)
        directory += b"unit\0\0\0\0" + hashlib.sha256(image).digest()
        assert len(directory) == 128
        image += struct.pack(">IIIII", 0xFADE0CC0, 148, 1, 0, 20) + directory
    return bytes(image)


def fat(images, *, wide=False, endian=">"):
    entries, payload, offset = [], bytearray(), 4096
    for image in images:
        thin_endian = macho.THIN[image[:4]][0]
        cpu, subtype = struct.unpack_from(thin_endian + "II", image, 4)
        fields = (
            (cpu, subtype, offset, len(image), 12, 0)
            if wide
            else (cpu, subtype, offset, len(image), 12)
        )
        entries.append(struct.pack(endian + ("IIQQII" if wide else "IIIII"), *fields))
        payload += image
        aligned = (len(payload) + 4095) // 4096 * 4096
        payload.extend(b"\0" * (aligned - len(payload)))
        offset = 4096 + len(payload)
    header = struct.pack(endian + "II", 0xCAFEBABF if wide else 0xCAFEBABE, len(images)) + b"".join(
        entries
    )
    return header.ljust(4096, b"\0") + bytes(payload)


def replace(data, offset, fmt, *values, endian="<"):
    changed = bytearray(data)
    struct.pack_into(endian + fmt, changed, offset, *values)
    return bytes(changed)


def section_flags(data, flags, *, length=None, stub_size=None):
    endian, wide = macho.THIN[data[:4]]
    base = (32 + 72) if wide else (28 + 56)
    data = replace(data, base + (64 if wide else 56), "I", flags, endian=endian)
    if length is not None:
        data = replace(
            data, base + (40 if wide else 36), "Q" if wide else "I", length, endian=endian
        )
    if stub_size is not None:
        data = replace(data, base + (72 if wide else 64), "I", stub_size, endian=endian)
    return data


@pytest.mark.parametrize("wide", [False, True])
@pytest.mark.parametrize("endian", ["<", ">"])
def test_thin_exact_no_change(wide, endian, monkeypatch):
    data = thin(wide=wide, endian=endian)
    monkeypatch.setattr(
        server, "clean_text", lambda *a, **k: pytest.fail("text normalization called")
    )
    monkeypatch.setattr(server, "_apply_layer_b", lambda *a, **k: pytest.fail("rewrite called"))
    result = server._clean_payload(data, "program", {})
    assert result["kind"] == "executable"
    assert result["status"] == "inspected_no_change"
    assert base64.b64decode(result["cleaned"]) == data
    assert (
        result["report"]["input_sha256"]
        == result["report"]["output_sha256"]
        == hashlib.sha256(data).hexdigest()
    )
    assert result["report"]["release_ready"] is True
    assert result["report"]["actions"] == []
    inspected = server._inspect_payload(data, "program.rs", False)
    assert inspected["kind"] == "executable"
    assert inspected["suspicious"]["verdict"] is False
    assert inspected["report"]["changed"] is False


@pytest.mark.parametrize("wide", [False, True])
def test_fat_exact_no_change(wide):
    data = fat([thin(cpu=0x100000C), thin(cpu=0x1000007)], wide=wide)
    report = macho.inspect_macho(data)
    assert report["architecture_count"] == 2
    assert report["release_ready"] is True
    assert report["container"] == ("fat64" if wide else "fat32")


@pytest.mark.parametrize("wide", [False, True])
def test_little_endian_fat_encoding_rejected(wide):
    with pytest.raises(ValueError, match="little-endian fat-container"):
        macho.inspect_macho(fat([thin()], wide=wide, endian="<"))


def test_signature_structure_and_page_hashes():
    data = thin(signed=True)
    report = macho.inspect_macho(data)
    signature = report["slices"][0]["signature"]
    assert signature["present"] is True
    assert signature["cryptographic_trust_verified"] is False
    assert signature["directories"][0]["code_pages_verified"] is True
    assert signature["directories"][0]["ad_hoc"] is True
    assert report["release_ready"] is True
    assert base64.b64decode(macho.clean_macho(data, {})["cleaned"]) == data


@pytest.mark.parametrize(
    "mutation",
    [
        lambda b: b[:3],
        lambda b: b[:31],
        lambda b: replace(b, 16, "I", 0),
        lambda b: replace(b, 16, "I", 4097),
        lambda b: replace(b, 20, "I", 16 << 20 | 1),
        lambda b: replace(b, 20, "I", 4),
        lambda b: replace(b, 28, "I", 1),
        lambda b: replace(b, 36, "I", 12),
        lambda b: replace(b, 36, "I", 4096),
        lambda b: replace(b, 12, "I", 6),
        lambda b: replace(b, 16, "I", 1),
        lambda b: replace(b, 32 + 56, "ii", 2, 1),
        lambda b: replace(b, 32 + 64, "I", 4097),
        lambda b: replace(b, 32 + 72 + 48, "I", 4096),
        lambda b: replace(b, 32 + 72 + 40, "Q", 4096),
        lambda b: replace(b, 32 + 72 + 52, "I", 32),
        lambda b: replace(b, 32 + 72 + 56, "II", 4096, 1),
        lambda b: replace(b, 32 + 152 + 8, "Q", 1),
    ],
)
def test_malformed_thin_is_never_clean(mutation):
    with pytest.raises(ValueError):
        macho.inspect_macho(mutation(thin()))


@pytest.mark.parametrize(
    "mutation",
    [
        lambda b: replace(b, 4, "I", 33, endian=">"),
        lambda b: replace(b, 16, "I", 8, endian=">"),
        lambda b: replace(b, 20, "I", 0xFFFFFFFF, endian=">"),
        lambda b: replace(b, 24, "I", 31, endian=">"),
        lambda b: replace(b, 8, "I", 12, endian=">"),
        lambda b: replace(b, 28, "II", 0x100000C, 0, endian=">"),
        lambda b: replace(b, 36, "I", 4096, endian=">"),
    ],
)
def test_malformed_fat_is_never_clean(mutation):
    data = fat([thin(cpu=0x100000C), thin(cpu=0x1000007)])
    with pytest.raises(ValueError):
        macho.inspect_macho(mutation(data))


def test_fat64_reserved_and_normalized_duplicate_architecture():
    data = fat([thin()], wide=True)
    with pytest.raises(ValueError, match="reserved"):
        macho.inspect_macho(replace(data, 8 + 28, "I", 1, endian=">"))
    duplicate = fat([thin(subtype=0), thin(subtype=0x80000000)])
    with pytest.raises(ValueError, match="duplicate"):
        macho.inspect_macho(duplicate)


@pytest.mark.parametrize(
    "offset,fmt,value",
    [
        (512, "I", 0),
        (516, "I", 9999),
        (520, "I", 65),
        (524, "I", 2),
        (524, "I", 0x1005),
        (528, "I", 1),
        (536, "I", 7),
        (540, "I", 0x20700),
        (548, "I", 0),
        (552, "I", 1),
        (556, "I", 65),
        (560, "I", 2),
        (564, "I", 511),
        (568, "B", 0),
        (571, "B", 31),
        (572, "I", 1),
        (576, "I", 1),
        (584, "I", 1),
        (624, "B", 255),
    ],
)
def test_bad_signature_metadata_or_hash_is_never_clean(offset, fmt, value):
    data = replace(thin(signed=True), offset, fmt, value, endian=">")
    with pytest.raises(ValueError):
        macho.inspect_macho(data)


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
def test_executable_transform_options_rejected(option):
    with pytest.raises(ValueError, match="transformations"):
        server._clean_payload(thin(), "main.rs", {option: True})


@pytest.mark.parametrize("code", [0x31, 0x80000099, 0x99])
def test_unknown_command_requires_review_without_claiming_ai(code):
    data = thin(extra=[command(code)])
    result = server._clean_payload(data, "program", {})
    assert result["status"] == "requires_review"
    assert result["report"]["release_ready"] is False
    assert result["report"]["before"]["has_ai_metadata"] is False
    assert "cleaned" not in result
    assert server._inspect_payload(data, "program", False)["suspicious"]["verdict"] is True


@pytest.mark.parametrize("name", [b"__info_plist", b"__c2pa", b"__synthid"])
def test_explicit_or_unsupported_metadata_section_requires_review(name):
    result = macho.clean_macho(thin(section_name=name), {})
    assert result["status"] == "requires_review"
    assert not result["report"]["release_ready"]
    assert "cleaned" not in result


@pytest.mark.parametrize("wide", [False, True])
@pytest.mark.parametrize("endian", ["<", ">"])
@pytest.mark.parametrize(
    "flags,finding",
    [
        (0x17, "unsupported_section_type"),
        (0xFF, "unsupported_section_type"),
        (0x0F, "unsupported_section_type"),
        (0x01000000, "unsupported_section_attributes"),
        (0x00000800, "unsupported_section_attributes"),
        (0x00800000, "unsupported_section_attributes"),
        (0xDEADBEEF, "unsupported_section_type"),
    ],
)
def test_unknown_section_type_or_attribute_cannot_hide_behind_text_name(
    wide, endian, flags, finding
):
    data = section_flags(thin(wide=wide, endian=endian), flags)
    result = server._clean_payload(data, "program", {})
    assert result["status"] == "requires_review"
    assert finding in result["report"]["before"]["findings"]
    assert result["report"]["release_ready"] is False
    assert result["report"]["before"]["has_ai_metadata"] is False
    assert "cleaned" not in result
    assert (
        result["report"]["input_sha256"]
        == result["report"]["output_sha256"]
        == hashlib.sha256(data).hexdigest()
    )


@pytest.mark.parametrize(
    "flags",
    [
        0x80000400,
        0x40000000,
        0x20000000,
        0x10000000,
        0x08000000,
        0x04000000,
        0x02000000,
        0x00000400,
        0x00000200,
        0x00000100,
    ],
)
def test_named_section_attributes_preserve_supported_regular_section(flags):
    data = section_flags(thin(), flags)
    result = macho.clean_macho(data, {})
    assert result["status"] == "inspected_no_change"
    assert base64.b64decode(result["cleaned"]) == data


@pytest.mark.parametrize(
    "kind,length,stub_size",
    [
        (0x03, 64, None),
        (0x04, 64, None),
        (0x08, 64, 4),
        (0x0D, 64, None),
        (0x0E, 64, None),
        (0x11, 64, None),
        (0x13, 48, None),
        (0x14, 64, None),
        (0x15, 64, None),
        (0x16, 64, None),
    ],
)
def test_supported_declared_layouts_preserve_bytes(kind, length, stub_size):
    data = section_flags(thin(), kind, length=length, stub_size=stub_size)
    assert base64.b64decode(macho.clean_macho(data, {})["cleaned"]) == data


@pytest.mark.parametrize(
    "kind,length,stub_size",
    [
        (0x02, 64, None),
        (0x03, 63, None),
        (0x04, 63, None),
        (0x08, 64, 0),
        (0x08, 64, 3),
        (0x0E, 63, None),
        (0x13, 64, None),
        (0x16, 63, None),
        (0x02000016, 64, None),
    ],
)
def test_known_section_types_require_the_declared_layout(kind, length, stub_size):
    data = section_flags(thin(), kind, length=length, stub_size=stub_size)
    result = macho.clean_macho(data, {})
    assert result["status"] == "requires_review"
    assert "unsupported_section_layout" in result["report"]["before"]["findings"]
    assert "cleaned" not in result


def refusal_artifact(kind):
    return thin(extra=[command(0x31)]) if kind == "command" else section_flags(thin(), kind)


@pytest.mark.parametrize("kind", ["command", 0x17, 0x01000000, 0xDEADBEEF])
def test_http_single_and_batch_review_responses_never_include_bytes(kind):
    data = refusal_artifact(kind)
    service = ThreadingHTTPServer(("127.0.0.1", 0), server.Handler)
    thread = threading.Thread(target=service.serve_forever, daemon=True)
    thread.start()
    item = {
        "file": base64.b64encode(data).decode("ascii"),
        "name": "program",
        "options": {"deterministic_only": True},
    }
    try:
        for route, body in [("/clean", item), ("/clean/batch", {"files": [item]})]:
            connection = http.client.HTTPConnection("127.0.0.1", service.server_port, timeout=10)
            try:
                connection.request(
                    "POST",
                    route,
                    body=json.dumps(body),
                    headers={"Content-Type": "application/json"},
                )
                response = connection.getresponse()
                assert response.status == 200
                result = json.loads(response.read())
            finally:
                connection.close()
            if route.endswith("/batch"):
                result = result["results"][0]
            assert result["status"] == "requires_review"
            assert result["report"]["release_ready"] is False
            assert "cleaned" not in result
    finally:
        service.shutdown()
        service.server_close()
        thread.join(timeout=5)


@pytest.mark.skipif(
    not (os.environ.get("MACHO_ACCEPTANCE_CLIENT") or os.environ.get("ELF_ACCEPTANCE_CLIENT")),
    reason="explicit installed native client only",
)
@pytest.mark.parametrize("kind", ["command", 0x17, 0x01000000, 0xDEADBEEF])
def test_installed_client_review_refusal_preserves_input_and_never_writes_backup(kind, tmp_path):
    data = refusal_artifact(kind)
    source, output = tmp_path / "program", tmp_path / "program.inspected"
    source.write_bytes(data)
    before = source.stat()
    service = ThreadingHTTPServer(("127.0.0.1", 0), server.Handler)
    thread = threading.Thread(target=service.serve_forever, daemon=True)
    thread.start()
    client = os.environ.get("MACHO_ACCEPTANCE_CLIENT") or os.environ["ELF_ACCEPTANCE_CLIENT"]
    environment = {
        **os.environ,
        "WATERMARKS_SERVICE_URL": f"http://127.0.0.1:{service.server_port}",
    }
    try:
        for arguments in (["--output", str(output)], ["--in-place"]):
            result = subprocess.run(
                [client, "--deterministic-only", "--json-report", *arguments, str(source)],
                env=environment,
                capture_output=True,
                timeout=30,
                check=False,
            )
            assert result.returncode != 0
            assert not output.exists()
            assert source.read_bytes() == data
            assert sorted(path.name for path in tmp_path.iterdir()) == ["program"]
            after = source.stat()
            assert (before.st_ino, before.st_size, before.st_mtime_ns) == (
                after.st_ino,
                after.st_size,
                after.st_mtime_ns,
            )
    finally:
        service.shutdown()
        service.server_close()
        thread.join(timeout=5)


def test_functional_load_string_is_validated_in_context_and_preserved():
    dylib = command(0xC, struct.pack("<IIII", 24, 0, 0, 0) + b"/usr/lib/AI-generated.dylib\0")
    data = thin(extra=[dylib])
    report = macho.inspect_macho(data)
    assert report["release_ready"] is True
    assert report["slices"][0]["functional_load_strings_preserved"] == 1
    assert "AI-generated.dylib" not in str(report)
    with pytest.raises(ValueError, match="padding"):
        macho.inspect_macho(thin(extra=[dylib[:-1] + b"X"]))
    with pytest.raises(ValueError, match="offset"):
        macho.inspect_macho(thin(extra=[replace(dylib, 8, "I", 8)]))


def test_duplicate_singleton_and_detector_route_rejected():
    uuid = command(0x1B, bytes(16))
    with pytest.raises(ValueError, match="duplicate"):
        macho.inspect_macho(thin(extra=[uuid, uuid]))
    with pytest.raises(ValueError, match="detectors"):
        server._inspect_payload(thin(), "program", True)
    with pytest.raises(ValueError, match="detectors"):
        server._detect_payload(thin(), "program")
    assert server.capabilities()["cleaning_modes"]["mach_o_executable_inspection"] is True


def test_signature_rejects_code_page_tampering():
    data = bytearray(thin(signed=True))
    data[500] ^= 1
    with pytest.raises(ValueError, match="page hash"):
        macho.inspect_macho(bytes(data))


@pytest.mark.parametrize(
    "commands",
    [
        [command(0x22, bytes(40)), command(0x80000022, bytes(40))],
        [command(0x24, bytes(8)), command(0x25, bytes(8))],
        [command(0x24, bytes(8)), command(0x32, bytes(16))],
    ],
)
def test_exclusive_load_command_alias_families_rejected(commands):
    with pytest.raises(ValueError, match="duplicate"):
        macho.inspect_macho(thin(extra=commands))


def test_overlapping_linkedit_payloads_and_unknown_section_metadata_rejected():
    overlap = command(0x26, struct.pack("<II", 512, 4))
    with pytest.raises(ValueError, match="overlapping link-edit"):
        macho.inspect_macho(thin(signed=True, extra=[overlap]))
    result = macho.inspect_macho(thin(section_name=b"__custom_meta"))
    assert result["review_required"] is True
    assert result["has_ai_metadata"] is False


@pytest.mark.parametrize("data", [thin(cpu=12), thin(wide=False, cpu=0x100000C)])
def test_known_cpu_width_must_match_header(data):
    with pytest.raises(ValueError, match="CPU width"):
        macho.inspect_macho(data)


def test_zero_fill_has_vm_bounds_but_no_file_payload():
    data = replace(thin(), 32 + 72 + 48, "I", 0)
    data = replace(data, 32 + 72 + 64, "I", 1)
    assert macho.inspect_macho(data)["release_ready"] is True


def test_nonzero_outer_fat_padding_is_uninspected_and_blocked():
    data = bytearray(fat([thin()]))
    data[100] = 1
    with pytest.raises(ValueError, match="padding"):
        macho.inspect_macho(bytes(data))


def test_unsigned_thin_tail_and_unmapped_segment_gap_are_blocked():
    with pytest.raises(ValueError, match="outside mapped segments"):
        macho.inspect_macho(thin() + b"c2pa unindexed metadata")
    assert macho.inspect_macho(thin() + bytes(16))["release_ready"] is True
    data = bytearray(thin(signed=True))
    # Leave bytes 496..512 outside both mapped segments, without changing code.
    struct.pack_into("<Q", data, 32 + 48, 496)
    data[500] = 1
    with pytest.raises(ValueError, match="outside mapped segments"):
        macho.inspect_macho(bytes(data))


def test_code_directory_unparsed_string_padding_is_blocked():
    data = replace(thin(signed=True), 626, "B", 88)
    with pytest.raises(ValueError, match="CodeDirectory metadata"):
        macho.inspect_macho(data)


def signed_with_metadata_blob(signature):
    """Keep the synthetic signed image structurally consistent after blob changes."""
    data = bytearray(thin(signed=True)[:512] + signature)
    struct.pack_into("<Q", data, 32 + 152 + 32, len(signature))
    struct.pack_into("<Q", data, 32 + 152 + 48, len(signature))
    struct.pack_into("<I", data, 32 + 152 + 72 + 24 + 12, len(signature))
    directory = 512 + struct.unpack_from(">I", signature, 16)[0]
    hashes = directory + struct.unpack_from(">I", data, directory + 16)[0]
    data[hashes : hashes + 32] = hashlib.sha256(data[:512]).digest()
    return bytes(data)


def ad_hoc_signature(*, padding=0, requirements=None, wrapper=None):
    """Apple ad-hoc layout: hashed empty requirements and an empty CMS wrapper."""
    requirements = struct.pack(">III", 0xFADE0C01, 12, 0) if requirements is None else requirements
    wrapper = struct.pack(">II", 0xFADE0B01, 8) if wrapper is None else wrapper
    directory = bytearray(thin(signed=True)[532:])
    struct.pack_into(">I", directory, 4, 192)
    struct.pack_into(">I", directory, 16, 160)
    struct.pack_into(">I", directory, 24, 2)
    directory[96:96] = hashlib.sha256(requirements).digest() + bytes(32)
    length = 36 + len(directory) + len(requirements) + len(wrapper)
    signature = struct.pack(
        ">9I",
        0xFADE0CC0,
        length,
        3,
        0,
        36,
        2,
        36 + len(directory),
        0x10000,
        36 + len(directory) + len(requirements),
    )
    return signature + directory + requirements + wrapper + bytes(padding)


@pytest.mark.parametrize("padding", [0, 4096, 4097, 18005, 18012, 32768])
@pytest.mark.parametrize("with_empty_metadata", [False, True])
def test_zero_signature_allocation_padding_preserves_exact_bytes(padding, with_empty_metadata):
    signature = (
        ad_hoc_signature(padding=padding)
        if with_empty_metadata
        else thin(signed=True)[512:] + bytes(padding)
    )
    data = signed_with_metadata_blob(signature)
    result = macho.clean_macho(data, {})
    assert result["status"] == "inspected_no_change"
    assert base64.b64decode(result["cleaned"]) == data
    parsed = result["report"]["before"]["slices"][0]["signature"]
    assert parsed["outer_padding_bytes"] == padding
    assert parsed["empty_requirements_verified"] is with_empty_metadata
    assert parsed["empty_cms_wrapper_verified"] is with_empty_metadata
    assert parsed["directories"][0]["code_pages_verified"] is True
    assert parsed["directories"][0]["special_slots_verified"] == (2 if with_empty_metadata else 0)
    assert parsed["cryptographic_trust_verified"] is False


@pytest.mark.parametrize("padding", [1, 4096, 18012, 32768])
@pytest.mark.parametrize("position", [0, -1])
def test_nonzero_signature_allocation_padding_is_blocked(padding, position):
    signature = bytearray(ad_hoc_signature(padding=padding))
    signature[len(signature) - padding + (position if position >= 0 else padding + position)] = 1
    with pytest.raises(ValueError, match="nonzero or excessive signature padding"):
        macho.inspect_macho(signed_with_metadata_blob(signature))


def test_excessive_zero_signature_allocation_padding_is_blocked():
    signature = ad_hoc_signature(padding=32769)
    with pytest.raises(ValueError, match="nonzero or excessive signature padding"):
        macho.inspect_macho(signed_with_metadata_blob(signature))


@pytest.mark.parametrize(
    "requirements,wrapper",
    [
        (struct.pack(">III", 0xFADE0C01, 12, 1), None),
        (struct.pack(">III", 0xFADE0C01, 12, 0) + bytes(4), None),
        (struct.pack(">III", 0xFADE0C01, 16, 0) + bytes(4), None),
        (struct.pack(">III", 0xFADE0C00, 12, 0), None),
        (None, struct.pack(">II", 0xFADE0B01, 12) + bytes(4)),
        (None, struct.pack(">II", 0xFADE0B01, 8) + b"CMS"),
        (None, struct.pack(">II", 0xFADE0B02, 8)),
    ],
)
def test_nonempty_or_malformed_signature_metadata_is_blocked(requirements, wrapper):
    signature = ad_hoc_signature(requirements=requirements, wrapper=wrapper)
    with pytest.raises(ValueError):
        macho.inspect_macho(signed_with_metadata_blob(signature))


@pytest.mark.parametrize(
    "offset,fmt,value,reason",
    [
        (36 + 12, "I", 0, "ad-hoc"),
        (36 + 24, "I", 0, "special"),
        (36 + 24, "I", 1, "special"),
        (36 + 24, "I", 3, "special"),
        (36 + 96, "B", 0, "special.*hash"),
        (36 + 128, "B", 1, "external.*metadata"),
        (20, "I", 0x10001, "unsupported signature child"),
        (28, "I", 5, "unsupported signature child"),
        (24, "I", 36, "overlapping signature children|requirements"),
        (16, "I", 1, "signature index"),
    ],
)
def test_empty_signature_metadata_requires_valid_binding(offset, fmt, value, reason):
    data = signed_with_metadata_blob(ad_hoc_signature())
    data = replace(data, 512 + offset, fmt, value, endian=">")
    with pytest.raises(ValueError, match=reason):
        macho.inspect_macho(data)


def test_superblob_unindexed_gap_is_blocked():
    original = thin(signed=True)[512:]
    signature = bytearray(original[:20] + b"META" + original[20:])
    struct.pack_into(">I", signature, 4, len(signature))
    struct.pack_into(">I", signature, 16, 24)
    with pytest.raises(ValueError, match="signature metadata padding"):
        macho.inspect_macho(signed_with_metadata_blob(signature))


def test_code_directory_unindexed_hash_suffix_is_blocked():
    signature = bytearray(thin(signed=True)[512:] + b"META")
    struct.pack_into(">I", signature, 4, len(signature))
    struct.pack_into(">I", signature, 20 + 4, 132)
    with pytest.raises(ValueError, match="CodeDirectory metadata"):
        macho.inspect_macho(signed_with_metadata_blob(signature))


def test_openapi_and_runtime_executable_contract_agree():
    paths = server.openapi_spec()["paths"]
    for route in ("/inspect", "/clean", "/inspect/batch", "/clean/batch"):
        props = paths[route]["post"]["responses"]["200"]["content"]["application/json"]["schema"][
            "properties"
        ]
        if route.endswith("/batch"):
            props = props["results"]["items"]["properties"]
        assert "executable" in props["kind"]["enum"]
    props = paths["/capabilities"]["get"]["responses"]["200"]["content"]["application/json"][
        "schema"
    ]["properties"]
    assert "mach_o_executable_inspection" in props["cleaning_modes"]["properties"]


@pytest.mark.skipif(
    not os.environ.get("MACHO_ACCEPTANCE_ARTIFACT"), reason="explicit operator artifact only"
)
def test_explicit_operator_artifact_read_only_acceptance():
    path = Path(os.environ["MACHO_ACCEPTANCE_ARTIFACT"])
    expected = os.environ["MACHO_ACCEPTANCE_SHA256"]
    before = path.stat()
    assert 0 < before.st_size <= macho.MAX_BYTES
    data = path.read_bytes()
    assert hashlib.sha256(data).hexdigest() == expected
    result = server._inspect_payload(data, path.name, False)
    assert result["kind"] == "executable"
    assert result["report"]["release_ready"] is True
    assert result["report"]["input_sha256"] == result["report"]["output_sha256"] == expected
    assert result["report"]["changed"] is False
    cleaned = server._clean_payload(data, path.name, {"deterministic_only": True})
    assert cleaned["status"] == "inspected_no_change"
    assert base64.b64decode(cleaned["cleaned"]) == data
    expected_padding = os.environ.get("MACHO_ACCEPTANCE_SIGNATURE_PADDING")
    if expected_padding is not None:
        signature = result["report"]["slices"][0]["signature"]
        assert signature["outer_padding_bytes"] == int(expected_padding)
        assert signature["empty_requirements_verified"] is True
        assert signature["empty_cms_wrapper_verified"] is True
        for directory in signature["directories"]:
            assert directory["code_pages_verified"] is True
            assert directory["special_slots_verified"] == 2
            assert directory["ad_hoc"] is True
    after = path.stat()
    assert (before.st_size, before.st_mtime_ns, before.st_ino) == (
        after.st_size,
        after.st_mtime_ns,
        after.st_ino,
    )
    assert hashlib.sha256(path.read_bytes()).hexdigest() == expected
