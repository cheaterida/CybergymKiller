from __future__ import annotations

import binascii
import bz2
import gzip
import io
import json
import lzma
import shutil
import sqlite3
import struct
import subprocess
import sys
import tarfile
import tempfile
import wave
import zipfile
import zlib
import xml.etree.ElementTree as ET
from pathlib import Path
from typing import Any

from .catalog import get_format
from .matcher import match_formats


def _result(format_id: str, valid: bool, checks: list[str], errors: list[str], mode: str = "format") -> dict[str, Any]:
    return {"format_id": format_id, "valid": valid, "mode": mode, "checks": checks, "errors": errors}


def _png(data: bytes) -> list[str]:
    if not data.startswith(b"\x89PNG\r\n\x1a\n"):
        raise ValueError("bad PNG signature")
    position = 8
    kinds: list[bytes] = []
    idat = bytearray()
    while position < len(data):
        if position + 12 > len(data):
            raise ValueError("truncated PNG chunk header")
        size = int.from_bytes(data[position : position + 4], "big")
        end = position + 12 + size
        if end > len(data):
            raise ValueError("PNG chunk exceeds file")
        kind = data[position + 4 : position + 8]
        payload = data[position + 8 : position + 8 + size]
        crc = int.from_bytes(data[position + 8 + size : end], "big")
        if crc != binascii.crc32(kind + payload) & 0xFFFFFFFF:
            raise ValueError(f"bad PNG CRC for {kind!r}")
        kinds.append(kind)
        if kind == b"IDAT":
            idat.extend(payload)
        position = end
    if not kinds or kinds[0] != b"IHDR" or kinds[-1] != b"IEND" or kinds.count(b"IHDR") != 1:
        raise ValueError("invalid PNG critical chunk order")
    if len(data[16:29]) != 13 or int.from_bytes(data[16:20], "big") == 0 or int.from_bytes(data[20:24], "big") == 0:
        raise ValueError("invalid PNG dimensions")
    zlib.decompress(bytes(idat))
    return ["signature", "chunk-bounds", "chunk-order", "CRC32", "zlib"]


def _gif(data: bytes) -> list[str]:
    if data[:6] not in {b"GIF87a", b"GIF89a"} or len(data) < 14 or data[-1:] != b";":
        raise ValueError("invalid/truncated GIF")
    if int.from_bytes(data[6:8], "little") == 0 or int.from_bytes(data[8:10], "little") == 0:
        raise ValueError("zero GIF logical screen")
    return ["signature", "logical-screen", "trailer"]


def _bmp(data: bytes) -> list[str]:
    if len(data) < 54 or data[:2] != b"BM":
        raise ValueError("invalid BMP header")
    declared = int.from_bytes(data[2:6], "little")
    pixel_offset = int.from_bytes(data[10:14], "little")
    dib_size = int.from_bytes(data[14:18], "little")
    if declared != len(data) or dib_size < 40 or not 14 + dib_size <= pixel_offset <= len(data):
        raise ValueError("invalid BMP size/offset")
    return ["signature", "file-size", "DIB", "pixel-offset"]


def _midi(data: bytes) -> list[str]:
    if len(data) < 22 or data[:4] != b"MThd" or int.from_bytes(data[4:8], "big") != 6:
        raise ValueError("invalid SMF header")
    tracks = int.from_bytes(data[10:12], "big")
    position = 14
    seen = 0
    while position < len(data):
        if data[position : position + 4] != b"MTrk" or position + 8 > len(data):
            raise ValueError("invalid SMF track header")
        size = int.from_bytes(data[position + 4 : position + 8], "big")
        end = position + 8 + size
        if end > len(data) or not data[end - 4 : end] == b"\x00\xff\x2f\x00":
            raise ValueError("SMF track missing bounded End-of-Track")
        position = end
        seen += 1
    if position != len(data) or seen != tracks:
        raise ValueError("SMF track count mismatch")
    return ["MThd", "track-count", "track-lengths", "End-of-Track"]


def _wasm(data: bytes) -> list[str]:
    if not data.startswith(b"\0asm\x01\0\0\0"):
        raise ValueError("invalid WebAssembly magic/version")
    position = 8
    last_standard = 0
    seen: set[int] = set()
    while position < len(data):
        section_id = data[position]
        position += 1
        value = 0
        shift = 0
        for _ in range(5):
            if position >= len(data):
                raise ValueError("truncated WebAssembly section length")
            byte = data[position]
            position += 1
            value |= (byte & 0x7F) << shift
            if not byte & 0x80:
                break
            shift += 7
        else:
            raise ValueError("overlong WebAssembly section length")
        if position + value > len(data):
            raise ValueError("WebAssembly section exceeds file")
        if section_id:
            if section_id in seen or section_id < last_standard:
                raise ValueError("duplicate/out-of-order WebAssembly section")
            seen.add(section_id)
            last_standard = section_id
        position += value
    return ["magic/version", "section-order", "section-bounds"]


def _elf32_le(data: bytes) -> list[str]:
    if len(data) < 52 or data[:7] != b"\x7fELF\x01\x01\x01":
        raise ValueError("invalid ELF32 little-endian identity")
    if int.from_bytes(data[20:24], "little") != 1 or int.from_bytes(data[40:42], "little") != 52:
        raise ValueError("invalid ELF header version/size")
    for label, offset_offset, entry_offset, count_offset in (
        ("program", 28, 42, 44), ("section", 32, 46, 48),
    ):
        offset = int.from_bytes(data[offset_offset : offset_offset + 4], "little")
        entry_size = int.from_bytes(data[entry_offset : entry_offset + 2], "little")
        count = int.from_bytes(data[count_offset : count_offset + 2], "little")
        if count and (not entry_size or offset < 52 or offset + entry_size * count > len(data)):
            raise ValueError(f"ELF {label} header table exceeds file")
    section_offset = int.from_bytes(data[32:36], "little")
    section_count = int.from_bytes(data[48:50], "little")
    section_size = int.from_bytes(data[46:48], "little")
    if section_count and data[section_offset : section_offset + section_size] != bytes(section_size):
        raise ValueError("ELF section zero must be the all-zero null section")
    return ["ELF identity/version", "header size", "program/section table bounds", "null section"]


def _macho64_le(data: bytes) -> list[str]:
    if len(data) < 32 or data[:4] != b"\xcf\xfa\xed\xfe":
        raise ValueError("invalid little-endian Mach-O 64 header")
    command_count = int.from_bytes(data[16:20], "little")
    command_bytes = int.from_bytes(data[20:24], "little")
    if 32 + command_bytes > len(data):
        raise ValueError("Mach-O load-command region exceeds file")
    position = 32
    for _ in range(command_count):
        if position + 8 > 32 + command_bytes:
            raise ValueError("truncated Mach-O load command")
        size = int.from_bytes(data[position + 4 : position + 8], "little")
        if size < 8 or size % 8 or position + size > 32 + command_bytes:
            raise ValueError("invalid Mach-O load command size/alignment")
        position += size
    if position != 32 + command_bytes:
        raise ValueError("Mach-O ncmds/sizeofcmds disagreement")
    return ["Mach-O 64 magic/header", "load-command count", "command size/alignment"]


def _pdf(data: bytes) -> list[str]:
    if not data.startswith(b"%PDF-") or b"%%EOF" not in data[-64:]:
        raise ValueError("invalid PDF header/EOF")
    marker = data.rfind(b"startxref\n")
    if marker < 0:
        raise ValueError("PDF missing startxref")
    end = data.find(b"\n", marker + 10)
    offset = int(data[marker + 10 : end])
    if not 0 <= offset < len(data) or data[offset : offset + 4] != b"xref":
        raise ValueError("PDF startxref does not point to xref")
    if b"/Type /Catalog" not in data or b"/Type /Page" not in data:
        raise ValueError("PDF missing catalog/page tree")
    return ["header/EOF", "startxref", "xref", "catalog/page"]


def _rtf(data: bytes) -> list[str]:
    if not data.startswith(b"{\\rtf1"):
        raise ValueError("invalid RTF prolog")
    depth = 0
    escaped = False
    for byte in data:
        if escaped:
            escaped = False
        elif byte == 0x5C:
            escaped = True
        elif byte == 0x7B:
            depth += 1
        elif byte == 0x7D:
            depth -= 1
            if depth < 0:
                raise ValueError("RTF group underflow")
    if depth:
        raise ValueError("unclosed RTF groups")
    return ["prolog", "balanced-groups"]


def _postscript(data: bytes) -> list[str]:
    if not data.startswith(b"%!") or b"%%EOF" not in data[-32:]:
        raise ValueError("invalid PostScript prolog/EOF")
    return ["prolog", "DSC EOF"]


def _sqlite(data: bytes) -> list[str]:
    if len(data) < 512 or data[:16] != b"SQLite format 3\0":
        raise ValueError("invalid SQLite header")
    with tempfile.NamedTemporaryFile(suffix=".sqlite") as stream:
        stream.write(data)
        stream.flush()
        connection = sqlite3.connect(f"file:{stream.name}?mode=ro", uri=True)
        try:
            result = connection.execute("PRAGMA integrity_check").fetchone()
        finally:
            connection.close()
    if result != ("ok",):
        raise ValueError(f"SQLite integrity_check failed: {result!r}")
    return ["header", "SQLite integrity_check"]


def _pcap(data: bytes) -> list[str]:
    magics = {b"\xd4\xc3\xb2\xa1": "little", b"\xa1\xb2\xc3\xd4": "big"}
    if len(data) < 24 or data[:4] not in magics:
        raise ValueError("invalid pcap header")
    endian = "little" if magics[data[:4]] == "little" else "big"
    snaplen = int.from_bytes(data[16:20], endian)
    position = 24
    while position < len(data):
        if position + 16 > len(data):
            raise ValueError("truncated pcap packet header")
        captured = int.from_bytes(data[position + 8 : position + 12], endian)
        original = int.from_bytes(data[position + 12 : position + 16], endian)
        if captured > original or captured > snaplen or position + 16 + captured > len(data):
            raise ValueError("invalid pcap packet length")
        position += 16 + captured
    return ["global-header", "packet-bounds"]


def _pcapng(data: bytes) -> list[str]:
    position = 0
    endian: str | None = None
    interfaces = 0
    while position < len(data):
        if position + 12 > len(data):
            raise ValueError("truncated pcapng block")
        block_type_raw = data[position : position + 4]
        if block_type_raw == b"\x0a\x0d\x0d\x0a":
            bom = data[position + 8 : position + 12]
            endian = "little" if bom == b"\x4d\x3c\x2b\x1a" else "big" if bom == b"\x1a\x2b\x3c\x4d" else None
            if endian is None:
                raise ValueError("invalid pcapng byte-order magic")
        if endian is None:
            raise ValueError("pcapng must begin with section header")
        total = int.from_bytes(data[position + 4 : position + 8], endian)
        if total < 12 or total % 4 or position + total > len(data):
            raise ValueError("invalid pcapng block length")
        if int.from_bytes(data[position + total - 4 : position + total], endian) != total:
            raise ValueError("pcapng trailing block length mismatch")
        block_type = int.from_bytes(block_type_raw, endian)
        if block_type == 1:
            interfaces += 1
        position += total
    if interfaces == 0:
        raise ValueError("pcapng section has no Interface Description Block")
    return ["SHB/BOM", "block-lengths", "IDB"]


def _adts(data: bytes) -> list[str]:
    position = 0
    frames = 0
    while position < len(data):
        if position + 7 > len(data) or data[position] != 0xFF or data[position + 1] & 0xF6 != 0xF0:
            raise ValueError("invalid ADTS sync/layer")
        header_size = 7 if data[position + 1] & 1 else 9
        frame_size = ((data[position + 3] & 3) << 11) | (data[position + 4] << 3) | (data[position + 5] >> 5)
        if frame_size < header_size or position + frame_size > len(data):
            raise ValueError("ADTS frame length exceeds stream")
        position += frame_size
        frames += 1
    if frames == 0:
        raise ValueError("ADTS stream contains no frames")
    return ["ADTS sync/layer", "frame-lengths", f"frames={frames}"]


def _jbig2(data: bytes) -> list[str]:
    if len(data) < 9 or data[:8] != b"\x97JB2\r\n\x1a\n":
        raise ValueError("invalid JBIG2 file signature")
    sequential = bool(data[8] & 1)
    pages_unknown = bool(data[8] & 2)
    position = 9 if pages_unknown else 13
    eof_seen = False
    while position < len(data):
        if position + 11 > len(data):
            raise ValueError("truncated JBIG2 segment header")
        number = int.from_bytes(data[position : position + 4], "big")
        flags = data[position + 4]
        referred = data[position + 5] >> 5
        if referred >= 5:
            raise ValueError("extended JBIG2 reference counts are not accepted by the lightweight validator")
        reference_width = 1 if number <= 256 else 2 if number <= 65536 else 4
        page_width = 4 if flags & 0x40 else 1
        header_size = 6 + referred * reference_width + page_width + 4
        if position + header_size > len(data):
            raise ValueError("truncated JBIG2 referred/page fields")
        payload_size = int.from_bytes(data[position + header_size - 4 : position + header_size], "big")
        if payload_size == 0xFFFFFFFF or position + header_size + payload_size > len(data):
            raise ValueError("unsupported/invalid JBIG2 segment length")
        eof_seen |= flags & 0x3F == 51
        position += header_size + payload_size
        if not sequential:
            raise ValueError("random-access JBIG2 requires a full segment-table validator")
    if position != len(data) or not eof_seen:
        raise ValueError("JBIG2 file lacks a bounded End-of-File segment")
    return ["signature/flags", "sequential-segment-bounds", "End-of-File segment"]


def _rtp(data: bytes) -> list[str]:
    if len(data) < 12 or data[0] >> 6 != 2:
        raise ValueError("invalid RTP version/header")
    position = 12 + 4 * (data[0] & 0x0F)
    if position > len(data):
        raise ValueError("RTP CSRC list exceeds packet")
    if data[0] & 0x10:
        if position + 4 > len(data):
            raise ValueError("truncated RTP extension")
        position += 4 + 4 * int.from_bytes(data[position + 2 : position + 4], "big")
    if position > len(data):
        raise ValueError("RTP extension exceeds packet")
    if data[0] & 0x20 and (not data[-1] or data[-1] > len(data) - position):
        raise ValueError("invalid RTP padding")
    return ["version", "CSRC/extension bounds", "padding"]


def _rtcp(data: bytes) -> list[str]:
    position = 0
    packets = 0
    while position < len(data):
        if position + 4 > len(data) or data[position] >> 6 != 2 or not 192 <= data[position + 1] <= 223:
            raise ValueError("invalid RTCP header")
        size = 4 * (int.from_bytes(data[position + 2 : position + 4], "big") + 1)
        if size < 4 or position + size > len(data):
            raise ValueError("RTCP packet length exceeds compound packet")
        if data[position] & 0x20 and position + size != len(data):
            raise ValueError("RTCP padding is only legal on the final packet")
        position += size
        packets += 1
    if packets == 0:
        raise ValueError("empty RTCP compound packet")
    return ["version/types", "compound packet lengths", "padding"]


def _sip(data: bytes) -> list[str]:
    separator = data.find(b"\r\n\r\n")
    if separator < 0:
        raise ValueError("SIP message lacks header/body separator")
    lines = data[:separator].split(b"\r\n")
    first = lines[0]
    if not (first.startswith(b"SIP/2.0 ") or first.endswith(b" SIP/2.0")):
        raise ValueError("invalid SIP request/status line")
    lengths: list[int] = []
    for line in lines[1:]:
        if b":" not in line:
            raise ValueError("malformed SIP header")
        name, value = line.split(b":", 1)
        if name.lower() in {b"content-length", b"l"}:
            lengths.append(int(value.strip()))
    if lengths and (len(set(lengths)) != 1 or lengths[0] != len(data) - separator - 4):
        raise ValueError("SIP Content-Length mismatch")
    return ["start-line", "CRLF headers", "Content-Length"]


def _smb(data: bytes) -> list[str]:
    if len(data) < 64 or data[:4] != b"\xfeSMB" or int.from_bytes(data[4:6], "little") != 64:
        raise ValueError("invalid SMB2 header")
    position = 0
    commands = 0
    while True:
        if position + 64 > len(data) or data[position : position + 4] != b"\xfeSMB":
            raise ValueError("invalid SMB2 compound command boundary")
        next_command = int.from_bytes(data[position + 20 : position + 24], "little")
        commands += 1
        if not next_command:
            break
        if next_command < 64 or next_command % 8 or position + next_command >= len(data):
            raise ValueError("invalid SMB2 NextCommand")
        position += next_command
    if int.from_bytes(data[12:14], "little") == 0 and (len(data) < 100 or int.from_bytes(data[64:66], "little") != 36):
        raise ValueError("invalid SMB2 NEGOTIATE request structure")
    return ["SMB2 header", "compound NextCommand chain", "command StructureSize"]


def _nfs(data: bytes) -> list[str]:
    if len(data) < 24 or int.from_bytes(data[4:8], "big") != 0 or int.from_bytes(data[8:12], "big") != 2:
        raise ValueError("not an ONC RPC v2 CALL")
    if int.from_bytes(data[12:16], "big") != 100003 or int.from_bytes(data[16:20], "big") not in {2, 3, 4}:
        raise ValueError("not an NFS RPC call")
    position = 24
    for label in ("credential", "verifier"):
        if position + 8 > len(data):
            raise ValueError(f"truncated RPC {label}")
        length = int.from_bytes(data[position + 4 : position + 8], "big")
        position += 8 + (length + 3) // 4 * 4
        if position > len(data):
            raise ValueError(f"RPC {label} exceeds message")
    if int.from_bytes(data[20:24], "big") == 0 and position != len(data):
        raise ValueError("NFS NULL procedure must have no arguments")
    return ["ONC RPC CALL", "NFS program/version", "XDR auth bounds"]


def _modbus(data: bytes) -> list[str]:
    if len(data) < 8 or data[2:4] != b"\0\0":
        raise ValueError("invalid Modbus TCP MBAP header")
    length = int.from_bytes(data[4:6], "big")
    if not 2 <= length <= 254 or len(data) != 6 + length:
        raise ValueError("Modbus MBAP length mismatch")
    function = data[7] & 0x7F
    if function in {1, 2, 3, 4} and len(data) == 12:
        quantity = int.from_bytes(data[10:12], "big")
        maximum = 2000 if function in {1, 2} else 125
        if not 1 <= quantity <= maximum:
            raise ValueError("invalid Modbus read quantity")
    return ["protocol ID", "MBAP length", "function-specific quantity"]


def _mqtt(data: bytes) -> list[str]:
    if len(data) < 2 or not 1 <= data[0] >> 4 <= 15:
        raise ValueError("invalid MQTT control packet type")
    value = 0
    multiplier = 1
    position = 1
    for _ in range(4):
        if position >= len(data):
            raise ValueError("truncated MQTT remaining length")
        byte = data[position]
        position += 1
        value += (byte & 0x7F) * multiplier
        if not byte & 0x80:
            break
        multiplier *= 128
    else:
        raise ValueError("overlong MQTT remaining length")
    if position + value != len(data):
        raise ValueError("MQTT remaining length mismatch")
    fixed_flags = {1: 0, 2: 0, 4: 0, 5: 0, 6: 2, 7: 0, 8: 2, 9: 0, 10: 2, 11: 0, 12: 0, 13: 0, 14: 0, 15: 0}
    packet_type = data[0] >> 4
    if packet_type != 3 and data[0] & 0x0F != fixed_flags[packet_type]:
        raise ValueError("invalid MQTT fixed-header flags")
    return ["packet type/flags", "canonical bounded remaining length", "packet boundary"]


def _ogg(data: bytes) -> list[str]:
    from .blueprints import _ogg_crc

    position = 0
    pages = 0
    while position < len(data):
        if position + 27 > len(data) or data[position : position + 5] != b"OggS\0":
            raise ValueError("invalid Ogg page header")
        segment_count = data[position + 26]
        if position + 27 + segment_count > len(data):
            raise ValueError("truncated Ogg lacing table")
        payload_size = sum(data[position + 27 : position + 27 + segment_count])
        page_size = 27 + segment_count + payload_size
        if position + page_size > len(data):
            raise ValueError("Ogg page payload exceeds stream")
        page = bytearray(data[position : position + page_size])
        expected = int.from_bytes(page[22:26], "little")
        page[22:26] = b"\0\0\0\0"
        if _ogg_crc(page) != expected:
            raise ValueError("Ogg page CRC mismatch")
        position += page_size
        pages += 1
    if not pages:
        raise ValueError("empty Ogg stream")
    return ["capture/version", "lacing/page bounds", "Ogg CRC32"]


def _bson(data: bytes) -> list[str]:
    if len(data) < 5 or int.from_bytes(data[:4], "little", signed=True) != len(data) or data[-1] != 0:
        raise ValueError("invalid BSON document length/terminator")
    return ["document length", "terminator"]


def _capnp(data: bytes) -> list[str]:
    if len(data) < 8 or len(data) % 8:
        raise ValueError("Cap'n Proto message is not word-aligned")
    segments = int.from_bytes(data[:4], "little") + 1
    if not 1 <= segments <= 512:
        raise ValueError("invalid Cap'n Proto segment count")
    table_words32 = 1 + segments + ((1 + segments) & 1)
    table_bytes = table_words32 * 4
    if len(data) < table_bytes:
        raise ValueError("truncated Cap'n Proto segment table")
    words = sum(int.from_bytes(data[4 + 4 * index : 8 + 4 * index], "little") for index in range(segments))
    if table_bytes + words * 8 != len(data):
        raise ValueError("Cap'n Proto segment sizes do not equal message length")
    return ["segment count/table", "word alignment", "total segment sizes"]


def _font(data: bytes) -> list[str]:
    from fontTools.ttLib import TTFont

    font = TTFont(io.BytesIO(data), lazy=False, checkChecksums=2, recalcBBoxes=False, recalcTimestamp=False)
    tables = set(font.keys())
    required = {"head", "maxp", "cmap", "hhea", "hmtx", "name", "post"}
    if not required <= tables:
        raise ValueError(f"sfnt font lacks required tables: {sorted(required - tables)}")
    glyphs = font.getGlyphOrder()
    if not glyphs or font["maxp"].numGlyphs != len(glyphs):
        raise ValueError("sfnt maxp glyph count disagrees with glyph order")
    return ["sfnt/WOFF directory bounds", "table checksums", "required tables", "glyph count"]


def _odf(data: bytes, media_type: str) -> list[str]:
    with zipfile.ZipFile(io.BytesIO(data)) as archive:
        infos = archive.infolist()
        if not infos or infos[0].filename != "mimetype" or infos[0].compress_type != zipfile.ZIP_STORED:
            raise ValueError("OpenDocument mimetype must be first and stored")
        if archive.read("mimetype") != media_type.encode():
            raise ValueError("OpenDocument mimetype content mismatch")
        if archive.testzip() is not None:
            raise ValueError("OpenDocument ZIP CRC failure")
        ET.fromstring(archive.read("META-INF/manifest.xml"))
        ET.fromstring(archive.read("content.xml"))
    return ["ZIP/CRC", "first stored mimetype", "manifest/content XML"]


def validate_bytes(format_id: str, data: bytes, *, prefix_only: bool = False) -> dict[str, Any]:
    spec = get_format(format_id)
    checks: list[str] = []
    errors: list[str] = []
    if prefix_only:
        candidates = match_formats(data, spec.extensions[0], limit=100)
        valid = spec.id in {item.spec.id for item in candidates}
        return _result(spec.id, valid, ["matcher signature/probe self-check"] if valid else [], [] if valid else ["prefix did not match target"], "prefix")

    try:
        if spec.id == "png":
            checks = _png(data)
        elif spec.id in {"gif87a", "gif89a"}:
            checks = _gif(data)
        elif spec.id == "bmp":
            checks = _bmp(data)
        elif spec.id == "wav":
            with wave.open(io.BytesIO(data), "rb") as audio:
                audio.getparams()
            checks = ["RIFF/WAVE via wave"]
        elif spec.id == "midi":
            checks = _midi(data)
        elif spec.id == "zip":
            with zipfile.ZipFile(io.BytesIO(data)) as archive:
                if archive.testzip() is not None:
                    raise ValueError("ZIP CRC failure")
            checks = ["ZIP records/CRC via zipfile"]
        elif spec.id == "gzip":
            gzip.decompress(data)
            checks = ["gzip header/deflate/CRC/ISIZE"]
        elif spec.id == "bzip2":
            bz2.decompress(data)
            checks = ["bzip2 stream/CRC"]
        elif spec.id == "xz":
            lzma.decompress(data)
            checks = ["XZ blocks/index/footer/check"]
        elif spec.id == "tar":
            with tarfile.open(fileobj=io.BytesIO(data)) as archive:
                archive.getmembers()
            checks = ["tar headers/padding"]
        elif spec.id == "unix-ar":
            if not data.startswith(b"!<arch>\n"):
                raise ValueError("invalid ar signature")
            checks = ["ar signature"]
        elif spec.id == "wasm":
            checks = _wasm(data)
        elif spec.id == "elf32-le":
            checks = _elf32_le(data)
        elif spec.id == "macho64-le":
            checks = _macho64_le(data)
        elif spec.id == "pdf":
            checks = _pdf(data)
        elif spec.id == "rtf":
            checks = _rtf(data)
        elif spec.id == "postscript":
            checks = _postscript(data)
        elif spec.id == "sqlite3":
            checks = _sqlite(data)
        elif spec.id == "json":
            json.loads(data.decode("utf-8"))
            checks = ["UTF-8", "JSON grammar"]
        elif spec.id == "xml":
            ET.fromstring(data)
            checks = ["XML well-formedness"]
        elif spec.id in {"pcap-le", "pcap-be"}:
            checks = _pcap(data)
        elif spec.id == "pcapng":
            checks = _pcapng(data)
        elif spec.id == "jbig2":
            checks = _jbig2(data)
        elif spec.id == "aac":
            checks = _adts(data)
        elif spec.id == "rtp":
            checks = _rtp(data)
        elif spec.id == "rtcp":
            checks = _rtcp(data)
        elif spec.id == "sip":
            checks = _sip(data)
        elif spec.id == "smb":
            checks = _smb(data)
        elif spec.id == "nfs":
            checks = _nfs(data)
        elif spec.id == "modbus":
            checks = _modbus(data)
        elif spec.id == "mqtt":
            checks = _mqtt(data)
        elif spec.id == "ogg":
            checks = _ogg(data)
        elif spec.id == "msgpack":
            if data != b"\x80":
                raise ValueError("lightweight MessagePack validator currently accepts the canonical empty-map template only")
            checks = ["empty fixmap token", "single complete value"]
        elif spec.id == "bson":
            checks = _bson(data)
        elif spec.id == "capnp":
            checks = _capnp(data)
        elif spec.id in {"odt", "ods", "odp"}:
            media = {
                "odt": "application/vnd.oasis.opendocument.text",
                "ods": "application/vnd.oasis.opendocument.spreadsheet",
                "odp": "application/vnd.oasis.opendocument.presentation",
            }[spec.id]
            checks = _odf(data, media)
        elif spec.id in {"ttf", "opentype-cff", "woff", "woff2"}:
            checks = _font(data)
        else:
            from .blueprints import get_blueprint

            expected = bytes.fromhex(get_blueprint(spec.id).minimal_template.hex)
            if not expected or data != expected:
                raise ValueError("no general internal parser; bytes differ from the verified static template")
            checks = ["exact verified static-template bytes"]
    except (ArithmeticError, EOFError, ET.ParseError, OSError, UnicodeError, ValueError, zipfile.BadZipFile, zlib.error, sqlite3.DatabaseError, tarfile.TarError, wave.Error) as exc:
        errors.append(str(exc))
    return _result(spec.id, not errors, checks, errors)


def validate_file(format_id: str, path: str | Path, *, prefix_only: bool = False, max_bytes: int = 64 * 1024 * 1024) -> dict[str, Any]:
    target = Path(path)
    size = target.stat().st_size
    if size > max_bytes:
        raise ValueError(f"validation input exceeds {max_bytes} bytes")
    return validate_bytes(format_id, target.read_bytes(), prefix_only=prefix_only)


def run_template_validators(format_id: str, path: str | Path, *, timeout: float = 15.0) -> list[dict[str, Any]]:
    from .blueprints import get_blueprint

    target = str(Path(path))
    results: list[dict[str, Any]] = []
    for validator in get_blueprint(format_id).minimal_template.validators:
        args = [item.replace("{file}", target) for item in validator.args]
        if validator.cmd == "format-kb":
            command = [sys.executable, "-m", "format_kb.cli", *args]
        else:
            executable = shutil.which(validator.cmd)
            if not executable:
                results.append({**validator.to_dict(), "available": False, "passed": False, "error": "command not found"})
                continue
            command = [executable, *args]
        try:
            completed = subprocess.run(command, capture_output=True, text=True, check=False, timeout=timeout)
            results.append(
                {
                    **validator.to_dict(),
                    "available": True,
                    "actual_exit": completed.returncode,
                    "passed": completed.returncode == validator.expect_exit,
                    "stdout": completed.stdout[-2000:],
                    "stderr": completed.stderr[-2000:],
                }
            )
        except subprocess.TimeoutExpired:
            results.append({**validator.to_dict(), "available": True, "passed": False, "error": "timeout"})
    return results
