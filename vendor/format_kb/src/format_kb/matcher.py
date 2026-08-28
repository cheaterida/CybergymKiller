from __future__ import annotations

import json
import re
import struct
import xml.etree.ElementTree as ET
from pathlib import Path
from typing import Callable

from .catalog import FORMATS, get_format
from .models import FamilyMatch, FormatSpec, MatchDiagnosis, MatchResult


Probe = Callable[[bytes], bool | None]


def parse_header(value: bytes | bytearray | memoryview | str) -> bytes:
    if isinstance(value, (bytes, bytearray, memoryview)):
        return bytes(value)
    text = value.strip().replace("0x", "").replace("0X", "")
    text = re.sub(r"[\s:_-]", "", text)
    if len(text) % 2:
        raise ValueError("hex header must contain an even number of digits")
    if text and not re.fullmatch(r"[0-9A-Fa-f]+", text):
        raise ValueError("header string must be hexadecimal")
    return bytes.fromhex(text)


def _extension(value: str | None) -> str | None:
    if not value:
        return None
    text = str(value).lower().strip()
    name = Path(text).name
    if "." in name:
        return name.rsplit(".", 1)[1]
    return name.lstrip(".")


def _fourcc_brands(data: bytes) -> set[bytes] | None:
    if len(data) < 12:
        return None
    if data[4:8] != b"ftyp":
        return set()
    box_size = int.from_bytes(data[:4], "big")
    end = min(len(data), box_size if box_size >= 16 else len(data))
    return {data[8:12], *(data[offset : offset + 4] for offset in range(16, end - 3, 4))}


def _brand_probe(accepted: set[bytes], *, prefixes: tuple[bytes, ...] = ()) -> Probe:
    def probe(data: bytes) -> bool | None:
        brands = _fourcc_brands(data)
        if brands is None:
            return None
        return any(brand in accepted or any(brand.startswith(prefix) for prefix in prefixes) for brand in brands)

    return probe


def _m4a_probe(data: bytes) -> bool | None:
    brands = _fourcc_brands(data)
    if brands is None:
        return None
    if any(brand in {b"M4A ", b"M4B ", b"M4P "} for brand in brands):
        return True
    if b"mp4a" in data[:1024 * 1024] or b"soun" in data[:1024 * 1024]:
        return True
    return None if any(brand in {b"isom", b"iso2", b"mp41", b"mp42"} for brand in brands) else False


def _quicktime_probe(data: bytes) -> bool | None:
    brands = _fourcc_brands(data)
    if brands is None:
        if len(data) >= 8 and data[4:8] in {b"moov", b"mdat", b"wide", b"free", b"skip"}:
            return True
        return None
    if b"qt  " in brands:
        return True
    return False


def _ebml_doctype(data: bytes, expected: bytes) -> bool | None:
    if len(data) < 4:
        return None
    if not data.startswith(b"\x1aE\xdf\xa3"):
        return False
    position = data.find(b"\x42\x82", 4, min(len(data), 4096))
    if position < 0 or position + 3 > len(data):
        return None
    first = data[position + 2]
    marker = 0x80
    width = 1
    while width <= 8 and not first & marker:
        marker >>= 1
        width += 1
    if width > 8 or position + 2 + width > len(data):
        return False
    size = first & (marker - 1)
    for byte in data[position + 3 : position + 2 + width]:
        size = (size << 8) | byte
    start = position + 2 + width
    if start + size > len(data):
        return None
    return data[start : start + size] == expected


def _ogg(data: bytes, signature: bytes) -> bool | None:
    if len(data) < 5:
        return None
    if not data.startswith(b"OggS\x00"):
        return False
    if signature in data[:4096]:
        return True
    return None if len(data) < 4096 else False


def _pe(data: bytes, magic: int) -> bool | None:
    if len(data) < 64:
        return None if data.startswith(b"MZ") else False
    if not data.startswith(b"MZ"):
        return False
    offset = int.from_bytes(data[0x3C:0x40], "little")
    if offset > 16 * 1024 * 1024:
        return False
    if offset + 26 > len(data):
        return None
    return data[offset : offset + 4] == b"PE\x00\x00" and int.from_bytes(data[offset + 24 : offset + 26], "little") == magic


def _mpeg_ts(data: bytes) -> bool | None:
    for start, stride in ((0, 188), (4, 192)):
        positions = [start + stride * item for item in range(3)]
        if len(data) > positions[-1] and all(data[position] == 0x47 for position in positions):
            return True
    return None if len(data) < 377 else False


def _pcx(data: bytes) -> bool | None:
    if len(data) < 4:
        return None
    return data[0] == 0x0A and data[1] in {0, 2, 3, 4, 5} and data[2] == 1 and data[3] in {1, 2, 4, 8}


def _tar(data: bytes) -> bool | None:
    if len(data) < 512:
        return None
    if data[:512] == b"\x00" * 512:
        return True if len(data) >= 1024 and data[512:1024] == b"\x00" * 512 else None
    return None


def _zip_kind(data: bytes, marker: bytes) -> bool | None:
    if len(data) < 4:
        return None
    if not data.startswith((b"PK\x03\x04", b"PK\x05\x06", b"PK\x07\x08")):
        return False
    return True if marker in data[:1024 * 1024] else None


def _zip_epub(data: bytes) -> bool | None:
    if len(data) < 38:
        return None
    if not data.startswith(b"PK\x03\x04"):
        return False
    method = int.from_bytes(data[8:10], "little")
    name_length = int.from_bytes(data[26:28], "little")
    extra_length = int.from_bytes(data[28:30], "little")
    name = data[30 : 30 + name_length]
    start = 30 + name_length + extra_length
    payload = b"application/epub+zip"
    if name == b"mimetype" and method == 0:
        return None if len(data) < start + len(payload) else data[start : start + len(payload)] == payload
    return False


def _zip_mimetype(data: bytes, payload: bytes) -> bool | None:
    if len(data) < 30:
        return None
    if not data.startswith(b"PK\x03\x04"):
        return False
    method = int.from_bytes(data[8:10], "little")
    name_length = int.from_bytes(data[26:28], "little")
    extra_length = int.from_bytes(data[28:30], "little")
    start = 30 + name_length + extra_length
    name = data[30 : 30 + name_length]
    if len(data) < start + len(payload):
        return None
    return method == 0 and name == b"mimetype" and data[start : start + len(payload)] == payload


def _sfnt_color(data: bytes) -> bool | None:
    if len(data) < 12:
        return None
    if data[:4] not in {b"\x00\x01\x00\x00", b"OTTO", b"true"}:
        return False
    count = int.from_bytes(data[4:6], "big")
    if count > 4096:
        return False
    if len(data) < 12 + 16 * count:
        return None
    tags = {data[12 + 16 * index : 16 + 16 * index] for index in range(count)}
    return True if b"COLR" in tags and b"CPAL" in tags else False


def _bitmap_font(data: bytes) -> bool | None:
    if len(data) < 2:
        return None
    if data[:2] in {b"\x00\x02", b"\x00\x03"}:
        return None if len(data) < 6 else int.from_bytes(data[2:6], "little") <= len(data)
    if data[:2] != b"MZ":
        return False
    if len(data) < 64:
        return None
    offset = int.from_bytes(data[0x3C:0x40], "little")
    return None if offset + 2 > len(data) else data[offset : offset + 2] == b"NE"


def _rtp_probe(data: bytes) -> bool | None:
    if len(data) < 12:
        return None
    if data[0] >> 6 != 2:
        return False
    csrc_end = 12 + 4 * (data[0] & 0x0F)
    if csrc_end > len(data):
        return None
    if data[0] & 0x10:
        if csrc_end + 4 > len(data):
            return None
        csrc_end += 4 + 4 * int.from_bytes(data[csrc_end + 2 : csrc_end + 4], "big")
    return csrc_end <= len(data)


def _rtcp_probe(data: bytes) -> bool | None:
    if len(data) < 4:
        return None
    if data[0] >> 6 != 2 or not 192 <= data[1] <= 223:
        return False
    packet_length = 4 * (int.from_bytes(data[2:4], "big") + 1)
    return None if len(data) < packet_length else packet_length <= len(data)


def _sip_probe(data: bytes) -> bool | None:
    line_end = data.find(b"\r\n")
    if line_end < 0:
        return None if len(data) < 8192 else False
    first = data[:line_end]
    if first.startswith(b"SIP/2.0 "):
        return len(first) >= 12 and first[8:11].isdigit()
    parts = first.split(b" ")
    return len(parts) == 3 and bool(re.fullmatch(rb"[A-Z][A-Z0-9.-]*", parts[0])) and parts[2] == b"SIP/2.0"


def _nfs_probe(data: bytes) -> bool | None:
    # Probe an ONC RPC CALL without TCP record marking.
    if len(data) < 24:
        return None
    return (
        int.from_bytes(data[4:8], "big") == 0
        and int.from_bytes(data[8:12], "big") == 2
        and int.from_bytes(data[12:16], "big") == 100003
        and int.from_bytes(data[16:20], "big") in {2, 3, 4}
    )


def _modbus_tcp_probe(data: bytes) -> bool | None:
    if len(data) < 8:
        return None
    length = int.from_bytes(data[4:6], "big")
    if data[2:4] != b"\0\0" or not 2 <= length <= 254:
        return False
    return None if len(data) < 6 + length else True


def _mqtt_probe(data: bytes) -> bool | None:
    if len(data) < 2:
        return None
    packet_type = data[0] >> 4
    if not 1 <= packet_type <= 15:
        return False
    multiplier = 1
    remaining = 0
    for index in range(1, min(len(data), 5)):
        byte = data[index]
        remaining += (byte & 0x7F) * multiplier
        if not byte & 0x80:
            return None if len(data) < index + 1 + remaining else True
        multiplier *= 128
    return False if len(data) >= 5 else None


def _java_class(data: bytes) -> bool | None:
    if len(data) < 8:
        return None
    if data[:4] != b"\xca\xfe\xba\xbe":
        return False
    major = int.from_bytes(data[6:8], "big")
    return 45 <= major <= 100


def _macho_fat(data: bytes) -> bool | None:
    if len(data) < 8:
        return None
    magic = data[:4]
    if magic not in {b"\xca\xfe\xba\xbe", b"\xbe\xba\xfe\xca", b"\xca\xfe\xba\xbf", b"\xbf\xba\xfe\xca"}:
        return False
    endian = "big" if magic in {b"\xca\xfe\xba\xbe", b"\xca\xfe\xba\xbf"} else "little"
    count = int.from_bytes(data[4:8], endian)
    if not 1 <= count <= 64:
        return False
    entry_size = 32 if magic in {b"\xca\xfe\xba\xbf", b"\xbf\xba\xfe\xca"} else 20
    if len(data) < 8 + entry_size:
        return None
    first_offset = int.from_bytes(data[16:24] if entry_size == 32 else data[16:20], endian)
    return first_offset >= 8 + count * entry_size


def _json_probe(data: bytes) -> bool | None:
    stripped = data.removeprefix(b"\xef\xbb\xbf").lstrip()
    if not stripped:
        return None
    if stripped[:1] not in b'{["-0123456789tfn':
        return False
    try:
        json.loads(stripped.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError):
        return None
    return True


def _xml_probe(data: bytes) -> bool | None:
    stripped = data
    for bom in (b"\xef\xbb\xbf", b"\xff\xfe", b"\xfe\xff", b"\x00\x00\xfe\xff", b"\xff\xfe\x00\x00"):
        if stripped.startswith(bom):
            stripped = stripped[len(bom) :]
            break
    stripped = stripped.lstrip(b"\x00\x09\x0a\x0d\x20")
    if not stripped:
        return None
    if not stripped.startswith(b"<"):
        return False
    try:
        ET.fromstring(data)
    except (ET.ParseError, UnicodeDecodeError, ValueError):
        return None
    return True


def identify_families(header: bytes | bytearray | memoryview | str = b"") -> list[FamilyMatch]:
    data = parse_header(header)
    results: list[FamilyMatch] = []
    if data.startswith(b"RIFF"):
        form = data[8:12] if len(data) >= 12 else b""
        mapping = {b"WAVE": "wav", b"AVI ": "avi", b"WEBP": "webp"}
        matched = (mapping[form],) if form in mapping else ()
        results.append(
            FamilyMatch(
                "riff",
                0.99 if matched else 0.85,
                ("wav", "avi", "webp"),
                matched,
                {"wav": "RIFF + WAVE", "avi": "RIFF + AVI ", "webp": "RIFF + WEBP"},
                ("RIFF@0", f"form={form.decode('latin1') if form else 'unavailable'}"),
            )
        )
    if len(data) >= 8 and data[4:8] == b"ftyp":
        members = ("avif", "heif", "m4a", "mp4", "quicktime", "3gp")
        matched = tuple(item for item in members if PROBES[get_format(item).probe](data) is True)
        brands = sorted(item.decode("latin1") for item in (_fourcc_brands(data) or set()))
        results.append(
            FamilyMatch(
                "isobmff",
                0.99 if matched else 0.88,
                members,
                matched,
                {"avif": "avif/avis brand", "heif": "heic/heix/mif1 brand", "m4a": "M4A/M4B audio", "mp4": "isom/mp4* brand", "quicktime": "qt  brand", "3gp": "3gp*/3g2* brand"},
                ("ftyp@4", f"brands={','.join(brands)}"),
            )
        )
    if data.startswith(b"\x1aE\xdf\xa3"):
        members = ("matroska", "webm")
        matched = tuple(item for item in members if PROBES[get_format(item).probe](data) is True)
        results.append(
            FamilyMatch(
                "ebml",
                0.99 if matched else 0.88,
                members,
                matched,
                {"matroska": "EBML DocType=matroska", "webm": "EBML DocType=webm"},
                ("EBML header ID 1A45DFA3", "DocType probe"),
            )
        )
    if data.startswith(b"OggS"):
        members = ("ogg", "ogg-vorbis", "ogg-opus", "ogg-theora")
        matched = ("ogg",) + tuple(item for item in members[1:] if PROBES[get_format(item).probe](data) is True)
        results.append(
            FamilyMatch(
                "ogg",
                0.99 if matched else 0.88,
                members,
                matched,
                {"ogg": "OggS page framing", "ogg-vorbis": "first packet 01vorbis", "ogg-opus": "first packet OpusHead", "ogg-theora": "first packet 80theora"},
                ("OggS@0", "first logical-stream packet codec marker"),
            )
        )
    return results


def identify_family(header: bytes | bytearray | memoryview | str = b"") -> FamilyMatch | None:
    families = identify_families(header)
    return families[0] if families else None


PROBES: dict[str, Probe] = {
    "pcx": _pcx,
    "tar": _tar,
    "isobmff_avif": _brand_probe({b"avif", b"avis"}),
    "isobmff_heif": _brand_probe({b"heic", b"heix", b"hevc", b"hevx", b"mif1", b"msf1"}),
    "isobmff_m4a": _m4a_probe,
    "isobmff_mp4": _brand_probe({b"isom", b"iso2", b"iso3", b"iso4", b"iso5", b"iso6", b"mp41", b"mp42", b"avc1", b"dash", b"M4V ", b"F4V "}),
    "isobmff_quicktime": _quicktime_probe,
    "isobmff_3gp": _brand_probe(set(), prefixes=(b"3gp", b"3g2")),
    "ebml_matroska": lambda data: _ebml_doctype(data, b"matroska"),
    "ebml_webm": lambda data: _ebml_doctype(data, b"webm"),
    "ogg_vorbis": lambda data: _ogg(data, b"\x01vorbis"),
    "ogg_opus": lambda data: _ogg(data, b"OpusHead"),
    "ogg_theora": lambda data: _ogg(data, b"\x80theora"),
    "mpeg_ts": _mpeg_ts,
    "pe32": lambda data: _pe(data, 0x10B),
    "pe32plus": lambda data: _pe(data, 0x20B),
    "macho_fat": _macho_fat,
    "java_class": _java_class,
    "zip_epub": _zip_epub,
    "zip_docx": lambda data: _zip_kind(data, b"word/"),
    "zip_xlsx": lambda data: _zip_kind(data, b"xl/"),
    "zip_pptx": lambda data: _zip_kind(data, b"ppt/"),
    "json": _json_probe,
    "xml": _xml_probe,
    "sfnt_color": _sfnt_color,
    "bitmap_font": _bitmap_font,
    "rtp": _rtp_probe,
    "rtcp": _rtcp_probe,
    "sip": _sip_probe,
    "nfs": _nfs_probe,
    "modbus_tcp": _modbus_tcp_probe,
    "mqtt": _mqtt_probe,
    "zip_odt": lambda data: _zip_mimetype(data, b"application/vnd.oasis.opendocument.text"),
    "zip_ods": lambda data: _zip_mimetype(data, b"application/vnd.oasis.opendocument.spreadsheet"),
    "zip_odp": lambda data: _zip_mimetype(data, b"application/vnd.oasis.opendocument.presentation"),
}


_PROBE_EXPECTATIONS: dict[str, tuple[int, bytes, str]] = {
    "pcx": (0, b"\x0a", "PCX manufacturer byte; version/encoding/depth also checked by probe"),
    "isobmff_avif": (4, b"ftyp", "ISO BMFF ftyp plus AVIF brand"),
    "isobmff_heif": (4, b"ftyp", "ISO BMFF ftyp plus HEIF brand"),
    "isobmff_m4a": (4, b"ftyp", "ISO BMFF ftyp plus M4A/audio evidence"),
    "isobmff_mp4": (4, b"ftyp", "ISO BMFF ftyp plus MP4 brand"),
    "isobmff_quicktime": (4, b"ftyp", "ISO BMFF ftyp/QuickTime atom plus qt brand"),
    "isobmff_3gp": (4, b"ftyp", "ISO BMFF ftyp plus 3gp/3g2 brand"),
    "mpeg_ts": (0, b"\x47", "sync byte repeated every 188 or 192 bytes"),
    "json": (0, b"{", "complete JSON value after BOM/whitespace"),
    "xml": (0, b"<", "complete well-formed XML after BOM/whitespace"),
    "sfnt_color": (0, b"\x00\x01\x00\x00", "sfnt directory containing both COLR and CPAL"),
    "bitmap_font": (0, b"\x00\x03", "FNT v2/v3 header or NE-wrapped FON resource"),
    "rtp": (0, b"\x80", "RTP version 2 plus bounded CSRC/extension header"),
    "rtcp": (0, b"\x80", "RTCP version 2, control packet type and word length"),
    "sip": (0, b"SIP/2.0 ", "SIP status line or METHOD target SIP/2.0 request line"),
    "nfs": (8, b"\x00\x00\x00\x02", "ONC RPC version 2 call for program 100003"),
    "modbus_tcp": (2, b"\x00\x00", "MBAP protocol ID zero and bounded length"),
    "mqtt": (0, b"\x10", "valid MQTT packet type and remaining-length encoding"),
    "zip_odt": (0, b"PK\x03\x04", "stored first ODT mimetype entry"),
    "zip_ods": (0, b"PK\x03\x04", "stored first ODS mimetype entry"),
    "zip_odp": (0, b"PK\x03\x04", "stored first ODP mimetype entry"),
}


def _diagnose_clause(data: bytes, offset: int, expected: bytes, mask: bytes | None = None) -> tuple[int, str, tuple[dict[str, object], ...]]:
    mismatches: list[dict[str, object]] = []
    actual = data[offset : offset + len(expected)] if offset < len(data) else b""
    bitmasks = mask or b"\xff" * len(expected)
    for index, (wanted, bitmask) in enumerate(zip(expected, bitmasks, strict=True)):
        absolute = offset + index
        if absolute >= len(data):
            mismatches.append({"offset": absolute, "expected": f"{wanted:02X}", "got": None, "reason": "missing"})
        elif data[absolute] & bitmask != wanted & bitmask:
            mismatches.append({"offset": absolute, "expected": f"{wanted:02X}", "got": f"{data[absolute]:02X}", "mask": f"{bitmask:02X}"})
    return len(mismatches), actual.hex().upper(), tuple(mismatches)


def diagnose_formats(
    header: bytes | bytearray | memoryview | str = b"",
    extension: str | None = None,
    *,
    limit: int = 5,
) -> list[MatchDiagnosis]:
    data = parse_header(header)
    ext = _extension(extension)
    ranked: list[tuple[tuple[int, int, int, str], MatchDiagnosis]] = []
    for spec in FORMATS:
        ext_match = ext is not None and ext in spec.extensions
        best: tuple[int, int, str, str, int, tuple[dict[str, object], ...]] | None = None
        for rule in spec.magic:
            for clause in rule.clauses:
                distance, got, mismatches = _diagnose_clause(data, clause.offset, clause.value, clause.mask)
                candidate = (distance, clause.offset, rule.name, got, clause.specificity, mismatches)
                if best is None or (candidate[0], -candidate[4], candidate[1]) < (best[0], -best[4], best[1]):
                    best = candidate
                    expected = clause.value.hex().upper()
        checked = "magic"
        if best is None and spec.probe in _PROBE_EXPECTATIONS:
            offset, value, hint = _PROBE_EXPECTATIONS[spec.probe]
            distance, got, mismatches = _diagnose_clause(data, offset, value)
            best = (distance, offset, hint, got, len(value) * 8, mismatches)
            expected = value.hex().upper()
            checked = "probe"
        if best is None:
            continue
        distance, offset, rule_name, got, specificity, mismatches = best
        diagnosis = MatchDiagnosis(
            spec.id,
            spec.name,
            checked,
            expected,
            got,
            distance,
            offset,
            rule_name,
            ext_match,
            mismatches,
        )
        ranked.append(((0 if ext_match else 1, distance, -specificity, spec.id), diagnosis))
    ranked.sort(key=lambda item: item[0])
    return [item[1] for item in ranked[: max(0, int(limit))]]


def match_formats_detailed(
    header: bytes | bytearray | memoryview | str = b"",
    extension: str | None = None,
    *,
    limit: int = 10,
    diagnosis_limit: int = 5,
) -> dict[str, object]:
    matches = match_formats(header, extension, limit=limit)
    return {
        "matches": [item.to_dict() for item in matches],
        "diagnosis": [] if matches else [item.to_dict() for item in diagnose_formats(header, extension, limit=diagnosis_limit)],
    }


def match_formats(
    header: bytes | bytearray | memoryview | str = b"",
    extension: str | None = None,
    *,
    limit: int = 10,
    include_structure: bool = True,
) -> list[MatchResult]:
    data = parse_header(header)
    ext = _extension(extension)
    results: list[MatchResult] = []
    for spec in FORMATS:
        ext_match = ext is not None and ext in spec.extensions
        matched_rules = [rule for rule in spec.magic if rule.matches(data)] if data else []
        signature_match = bool(matched_rules)
        compatible_rule = False
        for rule in spec.magic:
            rule_compatible = True
            for clause in rule.clauses:
                if clause.offset >= len(data):
                    continue
                available = min(len(clause.value), len(data) - clause.offset)
                actual = data[clause.offset : clause.offset + available]
                expected = clause.value[:available]
                mask = clause.mask[:available] if clause.mask else bytes([0xFF]) * available
                if any((left & bitmask) != (right & bitmask) for left, right, bitmask in zip(actual, expected, mask, strict=True)):
                    rule_compatible = False
                    break
            if rule_compatible:
                compatible_rule = True
                break
        signature_conflict = bool(data and spec.magic and not signature_match and not compatible_rule)
        probe_result = PROBES[spec.probe](data) if data and spec.probe else None
        if probe_result is False:
            continue
        if signature_conflict and probe_result is not True:
            continue
        if not (ext_match or signature_match or probe_result is True):
            continue

        reasons: list[str] = []
        score = 0
        if signature_match:
            best = max(matched_rules, key=lambda rule: rule.specificity)
            score += 100 + min(40, best.specificity // 8)
            reasons.append(f"magic:{best.name}")
        if probe_result is True:
            score += 80
            reasons.append(f"probe:{spec.probe}")
        elif spec.probe and data:
            reasons.append(f"probe:{spec.probe}:insufficient-header")
        if ext_match:
            score += 35
            reasons.append(f"extension:.{ext}")

        unresolved_probe = bool(spec.probe and data and probe_result is None)
        if (signature_match or probe_result is True) and ext_match and not unresolved_probe:
            confidence = 0.99
        elif (signature_match or ext_match) and unresolved_probe:
            confidence = 0.72
        elif probe_result is True:
            confidence = 0.96
        elif signature_match:
            confidence = 0.94 if len(matched_rules) == 1 else 0.90
        else:
            confidence = 0.58
        results.append(MatchResult(spec, confidence, score, tuple(reasons)))

    results.sort(key=lambda item: (-item.score, item.spec.id))
    return results[: max(0, int(limit))]


def identify(
    header: bytes | bytearray | memoryview | str = b"",
    extension: str | None = None,
) -> MatchResult | None:
    matches = match_formats(header, extension, limit=2)
    if not matches:
        return None
    if len(matches) > 1 and matches[0].score == matches[1].score and matches[0].confidence == matches[1].confidence:
        return None
    return matches[0]
