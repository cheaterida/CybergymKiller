from __future__ import annotations

import binascii
import io
import json
import os
import shutil
import struct
import subprocess
import tempfile
import zipfile
from pathlib import Path, PurePosixPath
from typing import Any, Callable

from .models import TemplateFieldOffset, ValidatorCommand


ContainerResult = dict[str, Any]


def _as_bytes(value: Any, *, field: str = "data") -> bytes:
    if value is None:
        return b""
    if isinstance(value, bytes):
        return value
    if isinstance(value, (bytearray, memoryview)):
        return bytes(value)
    if isinstance(value, str):
        text = value.strip()
        if text.startswith("text:"):
            return text[5:].encode("utf-8")
        compact = "".join(text.split())
        if len(compact) % 2 == 0:
            try:
                return bytes.fromhex(compact)
            except ValueError:
                pass
        return text.encode("utf-8")
    raise TypeError(f"{field} must be bytes or a hexadecimal/text string")


def _safe_name(value: Any) -> str:
    name = str(value)
    path = PurePosixPath(name)
    if not name or name.startswith(("/", "\\")) or "\0" in name or ".." in path.parts:
        raise ValueError(f"unsafe or empty archive path: {name!r}")
    return name.replace("\\", "/")


def _vint(value: int) -> bytes:
    if not isinstance(value, int) or value < 0 or value > 0xFFFFFFFFFFFFFFFF:
        raise ValueError("vint must be an unsigned 64-bit integer")
    output = bytearray()
    while True:
        byte = value & 0x7F
        value >>= 7
        output.append(byte | (0x80 if value else 0))
        if not value:
            return bytes(output)


def _read_vint(data: bytes, offset: int, *, limit: int | None = None) -> tuple[int, int]:
    value = 0
    shift = 0
    end = len(data) if limit is None else min(len(data), limit)
    for index in range(10):
        if offset + index >= end:
            raise ValueError(f"truncated vint at offset 0x{offset:X}")
        byte = data[offset + index]
        value |= (byte & 0x7F) << shift
        if not byte & 0x80:
            return value, index + 1
        shift += 7
    raise ValueError(f"vint exceeds 10 bytes at offset 0x{offset:X}")


def _semantic_field(
    path: str,
    offset: int,
    length: int,
    data: bytes,
    type_name: str,
    role: str,
    note: str,
    *,
    value_range: tuple[int, int] | None = None,
    related: tuple[str, ...] = (),
    enum: tuple[tuple[int, str], ...] = (),
) -> TemplateFieldOffset:
    return TemplateFieldOffset(
        path,
        offset,
        length,
        data[offset : offset + length].hex().upper(),
        note,
        type_name,
        role,
        value_range,
        related,
        enum,
    )


def _map(name: str, offset: int, data: bytes, fields: list[TemplateFieldOffset], **metadata: Any) -> dict[str, Any]:
    return {
        "name": name,
        "offset": offset,
        "length": len(data),
        "field_offsets": [field.to_dict() for field in fields],
        **metadata,
    }


def _validator_dicts(commands: tuple[ValidatorCommand, ...]) -> list[dict[str, Any]]:
    return [command.to_dict() for command in commands]


def _result(format_id: str, data: bytes, block_map: list[dict[str, Any]], validators: tuple[ValidatorCommand, ...], **extra: Any) -> ContainerResult:
    return {
        "format_id": format_id,
        "bytes": data,
        "hex": data.hex().upper(),
        "byte_length": len(data),
        "block_map": block_map,
        "validators": _validator_dicts(validators),
        "validated_by": "parser",
        "validation_status": "verified",
        **extra,
    }


RAR5_SIGNATURE = b"Rar!\x1a\x07\x01\x00"

# A minimal verified RAR5 compressed block (flags 0xCA: bit_size=2, 2-byte block
# size, last block, table present). Its huffman tables come from libarchive's own
# test corpus and its symbol stream decodes to exactly two 0x00 literals — enough
# output to exercise a parser's unpack path. Used by `container-build rar5` when a
# file entry is marked `"compressed": true` and no data is supplied.
_RAR5_COMPRESSED_BLOCK_TEMPLATE = bytes.fromhex(
    "cac25200276560541f55765dbf949271c9cf6596590c70d9659318c5921386424924e19"
    "09092492424e3924921084924210924909248421212cdb56f7b7d330e807d1d03ae3f9e"
    "ba9ff741fef7daf7dd79af3a5c8200"
)


def _rar5_block(
    name: str,
    block_type: int,
    header_flags: int,
    specific: list[tuple[str, bytes, str, str, str, tuple[str, ...]]],
    data_area: bytes = b"",
    extra_area: bytes = b"",
) -> tuple[bytes, list[TemplateFieldOffset]]:
    if data_area:
        header_flags |= 0x0002
    if extra_area:
        header_flags |= 0x0001
    body = bytearray()
    relative: list[tuple[str, int, int, str, str, str, tuple[str, ...]]] = []

    def put(path: str, encoded: bytes, type_name: str, role: str, note: str, related: tuple[str, ...] = ()) -> None:
        relative.append((path, len(body), len(encoded), type_name, role, note, related))
        body.extend(encoded)

    put("header.type", _vint(block_type), "vint", "enum", "RAR5 block type", enum_related(block_type))
    put("header.flags", _vint(header_flags), "vint", "flags", "RAR5 common block flags", ("header.data_size", "data"))
    if extra_area:
        put("header.extra_size", _vint(len(extra_area)), "vint", "length", "extra area length", ("header.extra",))
    if data_area:
        put("header.data_size", _vint(len(data_area)), "vint", "length", "packed data area length", ("data",))
    for item in specific:
        put(*item)
    if extra_area:
        put("header.extra", extra_area, f"bytes[{len(extra_area)}]", "payload", "extra records", ())

    size_bytes = _vint(len(body))
    covered = size_bytes + bytes(body)
    checksum = struct.pack("<I", binascii.crc32(covered) & 0xFFFFFFFF)
    block = checksum + covered + data_area
    fields = [
        _semantic_field("header.crc32", 0, 4, block, "uint32le", "checksum", "CRC32(header_size encoding + header data)", related=("header",)),
        _semantic_field("header.size", 4, len(size_bytes), block, "vint", "length", "bytes from header.type through optional extra area", value_range=(0, 2 * 1024 * 1024), related=("header.type", "header.flags")),
    ]
    body_start = 4 + len(size_bytes)
    for path, offset, length, type_name, role, note, related in relative:
        fields.append(_semantic_field(path, body_start + offset, length, block, type_name, role, note, related=related))
    if data_area:
        fields.append(_semantic_field("data", len(block) - len(data_area), len(data_area), block, f"bytes[{len(data_area)}]", "payload", "stored file data", related=("header.data_size", "file.unpacked_size", "file.crc32")))
    return block, fields


def enum_related(block_type: int) -> tuple[str, ...]:
    return ({1: "main", 2: "file", 3: "service", 4: "encryption", 5: "end"}.get(block_type, "unknown"),)


def _rar5_build(spec: dict[str, Any]) -> ContainerResult:
    requested = [dict(block) for block in spec.get("blocks", [])]
    if not requested and "files" in spec:
        requested = [{"type": "main", "flags": int(spec.get("flags", 0))}]
        requested.extend(
            {
                "type": "file",
                "name": entry["name"],
                "data": entry["data"],
                "is_dir": entry["is_dir"],
                **{key: value for key, value in entry.items() if key not in {"name", "data", "is_dir", "type"}},
            }
            for entry in _entries_from_spec(spec)
        )
    if not requested or requested[0].get("type") != "main":
        requested.insert(0, {"type": "main", "flags": 0})
    if requested[-1].get("type") != "end":
        requested.append({"type": "end", "flags": 0})

    output = bytearray(RAR5_SIGNATURE)
    maps = [
        _map(
            "signature",
            0,
            RAR5_SIGNATURE,
            [_semantic_field("signature", 0, 8, RAR5_SIGNATURE, "bytes[8]", "enum", "RAR5 fixed signature")],
            type="signature",
        )
    ]
    for index, block_spec in enumerate(requested):
        kind = str(block_spec.get("type", "file")).lower()
        header_flags = int(block_spec.get("header_flags", 0))
        extra = _as_bytes(block_spec.get("extra", b""))
        data = b""
        if kind == "main":
            archive_flags = int(block_spec.get("flags", 0))
            specific = [("main.archive_flags", _vint(archive_flags), "vint", "flags", "volume/solid/recovery/locked flags", ())]
            block_type = 1
            map_name = "main"
        elif kind == "file":
            name = _safe_name(block_spec.get("name", f"entry-{index}.bin"))
            data = _as_bytes(block_spec.get("data", b""))
            file_flags = int(block_spec.get("flags", 0))
            compression_info = int(block_spec.get("compression_info", 0))
            embedded_template = False
            if not data and block_spec.get("compressed"):
                # Embed a verified minimal compressed block so a caller can build a
                # compressed entry without hand-crafting the RAR5 huffman stream.
                data = _RAR5_COMPRESSED_BLOCK_TEMPLATE
                embedded_template = True
                if compression_info == 0:
                    compression_info = 5 << 7  # RAR5 method 5, version 0
            method = (compression_info >> 7) & 7
            compressed = method != 0
            directory = bool(file_flags & 1 or block_spec.get("is_dir"))
            if directory and data and not compressed:
                raise ValueError("RAR5 stored directory entries cannot carry file data")
            if directory:
                file_flags |= 1
            else:
                file_flags |= 4  # Data CRC32 is always emitted for deterministic integrity.
            if "unp_size_override" in block_spec:
                unpacked_size = int(block_spec["unp_size_override"])
            elif "unp_size" in block_spec:
                unpacked_size = int(block_spec["unp_size"])
            elif embedded_template:
                # The built-in template decompresses to two 0x00 bytes.
                unpacked_size = 2
            else:
                unpacked_size = len(data)
            if not compressed and file_flags & 8 == 0 and unpacked_size != len(data):
                raise ValueError("RAR5 known unpacked size must equal stored data length")
            attributes = int(block_spec.get("attributes", 0x10 if directory else 0x20))
            host_os = int(block_spec.get("host_os", 0))
            if host_os not in {0, 1}:
                raise ValueError("RAR5 host_os must be 0 (Windows) or 1 (Unix)")
            name_bytes = name.encode("utf-8")
            specific = [
                ("file.flags", _vint(file_flags), "vint", "flags", "directory/time/CRC/unknown-size flags", ("file.mtime", "file.crc32")),
                ("file.unpacked_size", _vint(unpacked_size), "vint", "length", "unpacked size; ignored when flag 0x8 is set", ("data", "file.flags")),
                ("file.attributes", _vint(attributes), "vint", "flags", "host-OS file attributes", ("file.host_os",)),
            ]
            if file_flags & 2:
                specific.append(("file.mtime", struct.pack("<I", int(block_spec.get("mtime", 0))), "uint32le", "integer", "Unix modification time", ()))
            if file_flags & 4:
                if "file_crc" in block_spec:
                    file_crc = int(block_spec["file_crc"]) & 0xFFFFFFFF
                    if not compressed and file_crc != binascii.crc32(data) & 0xFFFFFFFF:
                        raise ValueError("RAR5 file_crc does not match unpacked data; omit it to auto-calculate")
                else:
                    # Stored entries get the CRC derived from their data. Compressed
                    # entries cannot have a computed CRC here (it covers the
                    # decompressed stream), so a structural stand-in is emitted;
                    # parsers only verify it after unpacking, making a wrong value
                    # harmless for triggering/differential purposes.
                    file_crc = binascii.crc32(data) & 0xFFFFFFFF
                crc_note = "CRC32 of unpacked data" if not compressed else "CRC32 of decompressed data (not verifiable from raw stream)"
                specific.append(("file.crc32", struct.pack("<I", file_crc), "uint32le", "checksum", crc_note, ("data",)))
            specific.extend(
                [
                    ("file.compression_info", _vint(compression_info), "vint", "flags", "compression version/method/dictionary code", ("data",)),
                    ("file.host_os", _vint(host_os), "vint", "enum", "0=Windows, 1=Unix", ("file.attributes",)),
                    ("file.name_length", _vint(len(name_bytes)), "vint", "length", "UTF-8 name byte length", ("file.name",)),
                    ("file.name", name_bytes, f"utf8[{len(name_bytes)}]", "payload", "archive path without terminator", ("file.name_length",)),
                ]
            )
            block_type = 2
            map_name = f"file:{name}"
        elif kind == "end":
            specific = [("end.flags", _vint(int(block_spec.get("flags", 0))), "vint", "flags", "volume continuation flag", ())]
            block_type = 5
            map_name = "end"
        else:
            raise ValueError(f"unsupported RAR5 block type: {kind}")

        block, fields = _rar5_block(map_name, block_type, header_flags, specific, data, extra)
        offset = len(output)
        output.extend(block)
        absolute_fields = [
            TemplateFieldOffset(
                field.path,
                field.offset + offset,
                field.length,
                field.value_hex,
                field.note,
                field.type,
                field.role,
                field.value_range,
                field.related,
                field.enum,
            )
            for field in fields
        ]
        maps.append(_map(map_name, offset, block, absolute_fields, type=kind, block_index=len(maps) - 1))

    validators = (
        ValidatorCommand("format-kb", ("container-diagnose", "rar5", "{file}")),
        ValidatorCommand("7z", ("t", "-bd", "-y", "{file}")),
    )
    result = _result("rar5", bytes(output), maps, validators)
    diagnosis = _rar5_diagnose(result["bytes"], include_specs=False)
    if not diagnosis["valid"]:
        raise RuntimeError(f"internal RAR5 build validation failed: {diagnosis['errors']}")
    result["diagnosis"] = diagnosis
    return result


def _rar5_diagnose(data: bytes, *, include_specs: bool = False) -> dict[str, Any]:
    errors: list[dict[str, Any]] = []
    warnings: list[dict[str, Any]] = []
    blocks: list[dict[str, Any]] = []
    specs: list[dict[str, Any]] = []
    if not data.startswith(RAR5_SIGNATURE):
        return {"format_id": "rar5", "valid": False, "block_count": 0, "blocks": [], "errors": [{"level": "signature", "offset": 0, "message": "RAR5 signature mismatch"}], "warnings": []}
    position = len(RAR5_SIGNATURE)
    end_seen = False
    while position < len(data) and not errors:
        start = position
        try:
            if position + 5 > len(data):
                raise ValueError("truncated RAR5 block CRC/header size")
            declared_crc = int.from_bytes(data[position : position + 4], "little")
            size, size_width = _read_vint(data, position + 4)
            if size > 2 * 1024 * 1024:
                raise ValueError("RAR5 header size exceeds 2 MiB")
            header_start = position + 4 + size_width
            header_end = header_start + size
            if header_end > len(data):
                raise ValueError("RAR5 header extends beyond file")
            actual_crc = binascii.crc32(data[position + 4 : header_end]) & 0xFFFFFFFF
            if declared_crc != actual_crc:
                raise ValueError(f"block CRC32 mismatch: declared 0x{declared_crc:08X}, actual 0x{actual_crc:08X}")
            cursor = header_start
            block_type, width = _read_vint(data, cursor, limit=header_end)
            cursor += width
            header_flags, width = _read_vint(data, cursor, limit=header_end)
            cursor += width
            extra_size = 0
            data_size = 0
            if header_flags & 1:
                extra_size, width = _read_vint(data, cursor, limit=header_end)
                cursor += width
            if header_flags & 2:
                data_size, width = _read_vint(data, cursor, limit=header_end)
                cursor += width
            parsed: dict[str, Any] = {"type": block_type, "header_flags": header_flags}
            name = {1: "main", 2: "file", 3: "service", 4: "encryption", 5: "end"}.get(block_type, f"unknown-{block_type}")
            if block_type == 1:
                archive_flags, width = _read_vint(data, cursor, limit=header_end)
                cursor += width
                parsed.update({"type": "main", "flags": archive_flags})
            elif block_type in {2, 3}:
                file_flags, width = _read_vint(data, cursor, limit=header_end)
                cursor += width
                unpacked_size, width = _read_vint(data, cursor, limit=header_end)
                cursor += width
                attributes, width = _read_vint(data, cursor, limit=header_end)
                cursor += width
                mtime = None
                if file_flags & 2:
                    if cursor + 4 > header_end:
                        raise ValueError("truncated RAR5 mtime")
                    mtime = int.from_bytes(data[cursor : cursor + 4], "little")
                    cursor += 4
                file_crc = None
                if file_flags & 4:
                    if cursor + 4 > header_end:
                        raise ValueError("truncated RAR5 file CRC")
                    file_crc = int.from_bytes(data[cursor : cursor + 4], "little")
                    cursor += 4
                compression_info, width = _read_vint(data, cursor, limit=header_end)
                cursor += width
                host_os, width = _read_vint(data, cursor, limit=header_end)
                cursor += width
                name_length, width = _read_vint(data, cursor, limit=header_end)
                cursor += width
                if cursor + name_length > header_end - extra_size:
                    raise ValueError("RAR5 file name exceeds header")
                file_name = data[cursor : cursor + name_length].decode("utf-8")
                cursor += name_length
                parsed.update(
                    {
                        "type": "file" if block_type == 2 else "service",
                        "name": file_name,
                        "flags": file_flags,
                        "unp_size": unpacked_size,
                        "attributes": attributes,
                        "mtime": mtime,
                        "file_crc": file_crc,
                        "compression_info": compression_info,
                        "host_os": host_os,
                    }
                )
                name = f"{'file' if block_type == 2 else 'service'}:{file_name}"
            elif block_type == 5:
                end_flags, width = _read_vint(data, cursor, limit=header_end)
                cursor += width
                parsed.update({"type": "end", "flags": end_flags})
                end_seen = True
            if extra_size > 0:
                parsed["extra"] = data[header_end - extra_size : header_end]
            if cursor > header_end - extra_size:
                raise ValueError("RAR5 type-specific fields overlap extra area")
            data_start = header_end
            data_end = data_start + data_size
            if data_end > len(data):
                raise ValueError("RAR5 data area extends beyond file")
            payload = data[data_start:data_end]
            if block_type == 2:
                is_stored = parsed["compression_info"] & 0x0380 == 0
                if is_stored and not parsed["flags"] & 8 and parsed["unp_size"] != data_size:
                    raise ValueError("stored RAR5 file unpacked size differs from data size")
                if is_stored and parsed["file_crc"] is not None and parsed["file_crc"] != binascii.crc32(payload) & 0xFFFFFFFF:
                    raise ValueError("RAR5 file data CRC32 mismatch")
                elif not is_stored and parsed["file_crc"] is not None:
                    # For compressed entries, file_crc is the CRC of the *decompressed*
                    # data and cannot be checked against the raw byte stream. A
                    # legitimate compressed archive must not be flagged invalid here.
                    warnings.append({
                        "level": "file",
                        "block_index": len(blocks),
                        "offset": start,
                        "message": "compressed RAR5 entry: stored file_crc covers decompressed data and is not verifiable from the raw stream",
                    })
                parsed["data"] = payload
            blocks.append({"index": len(blocks), "name": name, "type": block_type, "offset": start, "header_length": header_end - start, "data_length": data_size, "length": data_end - start, "crc32": f"0x{declared_crc:08X}", "status": "ok"})
            specs.append(parsed)
            position = data_end
        except (UnicodeDecodeError, ValueError) as exc:
            errors.append({"level": "block", "block_index": len(blocks), "offset": start, "message": str(exc)})
    if not errors and not end_seen:
        errors.append({"level": "archive", "offset": position, "message": "RAR5 End of archive block is missing"})
    if end_seen and position < len(data):
        warnings.append({"level": "archive", "offset": position, "message": f"{len(data) - position} trailing bytes after End of archive block"})
    result: dict[str, Any] = {"format_id": "rar5", "valid": not errors, "block_count": len(blocks), "blocks": blocks, "errors": errors[:1], "warnings": warnings}
    if include_specs:
        result["specs"] = specs
    return result


def _rar5_mutate(data: bytes, mutation: dict[str, Any]) -> ContainerResult:
    diagnosis = _rar5_diagnose(data, include_specs=True)
    if not diagnosis["valid"]:
        raise ValueError(f"cannot mutate invalid RAR5 archive: {diagnosis['errors'][0]['message']}")
    specs = [dict(item) for item in diagnosis["specs"]]
    block_index = int(mutation.get("block_idx", -1))
    if not 0 <= block_index < len(specs):
        raise IndexError(f"block_idx {block_index} outside 0..{len(specs) - 1}")
    field = str(mutation.get("field", ""))
    value = mutation.get("value")
    target = specs[block_index]
    aliases = {"archive_flags": "flags", "file_flags": "flags", "unp_size": "unp_size", "file_crc": "file_crc"}
    key = aliases.get(field, field)
    if key not in {"flags", "name", "host_os", "attributes", "mtime", "unp_size", "data", "file_crc"}:
        raise KeyError(f"RAR5 field is not structurally mutable: {field}")
    old = target.get(key)
    if key == "data":
        target["data"] = _as_bytes(value)
        target["unp_size"] = len(target["data"])
        target.pop("file_crc", None)
    elif key == "unp_size":
        integer = int(value)
        if not 0 <= integer <= 0xFFFFFFFFFFFFFFFF:
            raise ValueError("unp_size must fit unsigned 64-bit vint")
        target["unp_size_override"] = integer
        target["flags"] = int(target.get("flags", 0)) | 8
        target.pop("unp_size", None)
        target.pop("file_crc", None)
    elif key == "file_crc":
        if bool((int(target.get("compression_info", 0)) >> 7) & 7):
            # Compressed entries: the stored CRC covers the decompressed stream and
            # cannot be derived from the raw payload — accept whatever is given.
            target["file_crc"] = int(value) & 0xFFFFFFFF
        else:
            expected = binascii.crc32(_as_bytes(target.get("data", b""))) & 0xFFFFFFFF
            if int(value) != expected:
                raise ValueError(f"file_crc is derived and must equal 0x{expected:08X}")
            target["file_crc"] = expected
    elif key == "name":
        target["name"] = _safe_name(value)
    else:
        target[key] = int(value)

    clean_blocks: list[dict[str, Any]] = []
    for item in specs:
        compressed = bool((int(item.get("compression_info", 0)) >> 7) & 7)
        clean = {key_: value_ for key_, value_ in item.items() if value_ is not None}
        # compression_info and file_crc must survive the round trip: a compressed
        # entry stays compressed and keeps its (decompressed-data) CRC instead of
        # being re-emitted as stored with a fabricated CRC.
        if clean.get("type") == "file" and not compressed and not clean.get("flags", 0) & 8:
            clean["unp_size"] = len(_as_bytes(clean.get("data", b"")))
        clean_blocks.append(clean)
    rebuilt = _rar5_build({"blocks": clean_blocks})
    new_specs = _rar5_diagnose(rebuilt["bytes"], include_specs=True)["specs"]
    new_value = new_specs[block_index].get(key, new_specs[block_index].get("unp_size"))
    old_block = diagnosis["blocks"][block_index]
    new_block = rebuilt["diagnosis"]["blocks"][block_index]
    changed = [
        {
            "block_idx": block_index,
            "field": field,
            "old": old.hex().upper() if isinstance(old, bytes) else old,
            "new": new_value.hex().upper() if isinstance(new_value, bytes) else new_value,
            "offset_shift": new_block["offset"] - old_block["offset"],
        }
    ]
    cumulative_shift = 0
    for index, (before, after) in enumerate(zip(diagnosis["blocks"], rebuilt["diagnosis"]["blocks"], strict=True)):
        shift = after["offset"] - before["offset"]
        if shift != cumulative_shift or after["length"] != before["length"]:
            changed.append({"block_idx": index, "field": "block.layout", "old": before["length"], "new": after["length"], "offset_shift": shift})
        cumulative_shift = shift
    rebuilt["changed_fields"] = changed
    return rebuilt


def _entries_from_spec(spec: dict[str, Any]) -> list[dict[str, Any]]:
    source = spec.get("blocks", spec.get("files", []))
    entries: list[dict[str, Any]] = []
    if isinstance(source, dict):
        source = [{"name": name, "data": value} for name, value in source.items()]
    for index, raw in enumerate(source):
        item = {"name": raw} if isinstance(raw, str) else dict(raw)
        if item.get("type") in {"main", "end"}:
            continue
        name = _safe_name(item.get("name", f"entry-{index}.bin"))
        is_dir = bool(item.get("is_dir") or item.get("type") == "dir" or name.endswith("/"))
        if is_dir and not name.endswith("/"):
            name += "/"
        payload = b"" if is_dir else _as_bytes(item.get("data", b""))
        entries.append({"name": name, "data": payload, "is_dir": is_dir, **{key: value for key, value in item.items() if key not in {"name", "data", "is_dir"}}})
    return entries


def _zip_build(spec: dict[str, Any]) -> ContainerResult:
    entries = _entries_from_spec(spec)
    output = bytearray()
    maps: list[dict[str, Any]] = []
    central_records: list[tuple[bytes, str, int, int, int, int]] = []
    for index, entry in enumerate(entries):
        name_bytes = entry["name"].encode("utf-8")
        flags = 0x0800
        payload = entry["data"]
        crc = binascii.crc32(payload) & 0xFFFFFFFF
        local_offset = len(output)
        header = struct.pack(
            "<IHHHHHIIIHH",
            0x04034B50,
            20,
            flags,
            0,
            0,
            0,
            crc,
            len(payload),
            len(payload),
            len(name_bytes),
            0,
        )
        block = header + name_bytes + payload
        output.extend(block)
        fields = [
            _semantic_field("local.signature", local_offset, 4, bytes(output), "uint32le", "enum", "ZIP local file header signature"),
            _semantic_field("local.flags", local_offset + 6, 2, bytes(output), "uint16le", "flags", "UTF-8 filename flag", related=("local.name",)),
            _semantic_field("local.method", local_offset + 8, 2, bytes(output), "uint16le", "enum", "0=stored"),
            _semantic_field("local.crc32", local_offset + 14, 4, bytes(output), "uint32le", "checksum", "CRC32 of uncompressed data", related=("local.data",)),
            _semantic_field("local.compressed_size", local_offset + 18, 4, bytes(output), "uint32le", "length", "stored payload size", related=("local.data",)),
            _semantic_field("local.uncompressed_size", local_offset + 22, 4, bytes(output), "uint32le", "length", "decoded payload size", related=("local.data",)),
            _semantic_field("local.name_length", local_offset + 26, 2, bytes(output), "uint16le", "length", "UTF-8 name byte length", related=("local.name",)),
            _semantic_field("local.extra_length", local_offset + 28, 2, bytes(output), "uint16le", "length", "extra field bytes", related=("local.extra",)),
            _semantic_field("local.name", local_offset + 30, len(name_bytes), bytes(output), f"utf8[{len(name_bytes)}]", "payload", "archive path", related=("local.name_length",)),
        ]
        if payload:
            fields.append(_semantic_field("local.data", local_offset + 30 + len(name_bytes), len(payload), bytes(output), f"bytes[{len(payload)}]", "payload", "stored entry bytes", related=("local.crc32", "local.compressed_size", "local.uncompressed_size")))
        maps.append(_map(f"local:{entry['name']}", local_offset, block, fields, type="local", block_index=index))
        external = (0x10 if entry["is_dir"] else 0) << 16
        central_records.append((name_bytes, entry["name"], crc, len(payload), local_offset, external))

    central_start = len(output)
    for index, (name_bytes, name, crc, size, local_offset, external) in enumerate(central_records):
        offset = len(output)
        header = struct.pack(
            "<IHHHHHHIIIHHHHHII",
            0x02014B50,
            0x031E,
            20,
            0x0800,
            0,
            0,
            0,
            crc,
            size,
            size,
            len(name_bytes),
            0,
            0,
            0,
            0,
            external,
            local_offset,
        )
        block = header + name_bytes
        output.extend(block)
        snapshot = bytes(output)
        fields = [
            _semantic_field("central.signature", offset, 4, snapshot, "uint32le", "enum", "ZIP central directory signature"),
            _semantic_field("central.crc32", offset + 16, 4, snapshot, "uint32le", "checksum", "copy of entry CRC32", related=("local.crc32",)),
            _semantic_field("central.compressed_size", offset + 20, 4, snapshot, "uint32le", "length", "copy of stored size", related=("local.data",)),
            _semantic_field("central.uncompressed_size", offset + 24, 4, snapshot, "uint32le", "length", "copy of decoded size", related=("local.data",)),
            _semantic_field("central.name_length", offset + 28, 2, snapshot, "uint16le", "length", "name byte length", related=("central.name",)),
            _semantic_field("central.local_offset", offset + 42, 4, snapshot, "uint32le", "offset", "absolute local header offset", related=("local.signature",)),
            _semantic_field("central.name", offset + 46, len(name_bytes), snapshot, f"utf8[{len(name_bytes)}]", "payload", "central path copy", related=("local.name",)),
        ]
        maps.append(_map(f"central:{name}", offset, block, fields, type="central", block_index=index))
    central_size = len(output) - central_start
    if len(entries) > 0xFFFF or central_start > 0xFFFFFFFF or central_size > 0xFFFFFFFF:
        raise ValueError("ZIP64 is not emitted by the lightweight deterministic builder")
    eocd_offset = len(output)
    eocd = struct.pack("<IHHHHIIH", 0x06054B50, 0, 0, len(entries), len(entries), central_size, central_start, 0)
    output.extend(eocd)
    snapshot = bytes(output)
    eocd_fields = [
        _semantic_field("EOCD.signature", eocd_offset, 4, snapshot, "uint32le", "enum", "end of central directory signature"),
        _semantic_field("EOCD.entry_count", eocd_offset + 8, 4, snapshot, "uint16le[2]", "length", "entries on disk and total entries", related=("central directory",)),
        _semantic_field("EOCD.central_size", eocd_offset + 12, 4, snapshot, "uint32le", "length", "central directory byte length", related=("central directory",)),
        _semantic_field("EOCD.central_offset", eocd_offset + 16, 4, snapshot, "uint32le", "offset", "central directory start", related=("central directory",)),
        _semantic_field("EOCD.comment_length", eocd_offset + 20, 2, snapshot, "uint16le", "length", "archive comment bytes", related=("EOCD.comment",)),
    ]
    maps.append(_map("EOCD", eocd_offset, eocd, eocd_fields, type="end"))
    validators = (
        ValidatorCommand("format-kb", ("container-diagnose", "zip", "{file}")),
        ValidatorCommand("unzip", ("-t", "{file}")),
        ValidatorCommand("7z", ("t", "-bd", "-y", "{file}")),
    )
    result = _result("zip", bytes(output), maps, validators)
    diagnosis = _zip_diagnose(result["bytes"], include_specs=False)
    if not diagnosis["valid"]:
        raise RuntimeError(f"internal ZIP build validation failed: {diagnosis['errors']}")
    result["diagnosis"] = diagnosis
    return result


def _zip_diagnose(data: bytes, *, include_specs: bool = False) -> dict[str, Any]:
    errors: list[dict[str, Any]] = []
    warnings: list[dict[str, Any]] = []
    blocks: list[dict[str, Any]] = []
    specs: list[dict[str, Any]] = []
    position = 0
    try:
        while data[position : position + 4] == b"PK\x03\x04":
            start = position
            if position + 30 > len(data):
                raise ValueError("truncated ZIP local header")
            flags, method = struct.unpack_from("<HH", data, position + 6)
            crc, compressed, uncompressed = struct.unpack_from("<III", data, position + 14)
            name_length, extra_length = struct.unpack_from("<HH", data, position + 26)
            data_start = position + 30 + name_length + extra_length
            data_end = data_start + compressed
            if data_end > len(data):
                raise ValueError("ZIP local payload exceeds file")
            if flags & 8:
                raise ValueError("ZIP data descriptors are not supported by deterministic diagnosis")
            if method != 0:
                raise ValueError("only stored ZIP entries are supported by deterministic diagnosis")
            name = data[position + 30 : position + 30 + name_length].decode("utf-8" if flags & 0x800 else "cp437")
            payload = data[data_start:data_end]
            if compressed != uncompressed:
                raise ValueError("stored ZIP compressed/uncompressed sizes differ")
            if binascii.crc32(payload) & 0xFFFFFFFF != crc:
                raise ValueError(f"ZIP entry CRC32 mismatch for {name!r}")
            blocks.append({"index": len(blocks), "name": f"local:{name}", "type": "local", "offset": start, "length": data_end - start, "status": "ok"})
            specs.append({"type": "file", "name": name, "data": payload, "is_dir": name.endswith("/")})
            position = data_end
        central_start = position
        central_count = 0
        while data[position : position + 4] == b"PK\x01\x02":
            start = position
            if position + 46 > len(data):
                raise ValueError("truncated ZIP central directory header")
            name_length, extra_length, comment_length = struct.unpack_from("<HHH", data, position + 28)
            local_offset = int.from_bytes(data[position + 42 : position + 46], "little")
            end = position + 46 + name_length + extra_length + comment_length
            if end > len(data) or local_offset >= central_start or data[local_offset : local_offset + 4] != b"PK\x03\x04":
                raise ValueError("ZIP central directory references invalid local header")
            blocks.append({"index": len(blocks), "name": "central", "type": "central", "offset": start, "length": end - start, "status": "ok"})
            position = end
            central_count += 1
        central_size = position - central_start
        if position + 22 > len(data) or data[position : position + 4] != b"PK\x05\x06":
            raise ValueError("ZIP EOCD is missing")
        entries_disk, entries_total = struct.unpack_from("<HH", data, position + 8)
        declared_size, declared_offset = struct.unpack_from("<II", data, position + 12)
        comment_length = int.from_bytes(data[position + 20 : position + 22], "little")
        if position + 22 + comment_length != len(data):
            raise ValueError("ZIP EOCD comment length/file end mismatch")
        if entries_disk != entries_total or entries_total != central_count or central_count != len(specs):
            raise ValueError("ZIP local/central/EOCD entry counts disagree")
        if declared_size != central_size or declared_offset != central_start:
            raise ValueError("ZIP EOCD central size/offset mismatch")
        blocks.append({"index": len(blocks), "name": "EOCD", "type": "end", "offset": position, "length": 22 + comment_length, "status": "ok"})
        with zipfile.ZipFile(io.BytesIO(data)) as archive:
            if archive.testzip() is not None:
                raise ValueError("ZIP library CRC validation failed")
    except (UnicodeDecodeError, ValueError, zipfile.BadZipFile) as exc:
        errors.append({"level": "block", "block_index": len(blocks), "offset": position, "message": str(exc)})
    result: dict[str, Any] = {"format_id": "zip", "valid": not errors, "block_count": len(blocks), "blocks": blocks, "errors": errors[:1], "warnings": warnings}
    if include_specs:
        result["specs"] = specs
    return result


def _zip_mutate(data: bytes, mutation: dict[str, Any]) -> ContainerResult:
    diagnosis = _zip_diagnose(data, include_specs=True)
    if not diagnosis["valid"]:
        raise ValueError(f"cannot mutate invalid ZIP: {diagnosis['errors'][0]['message']}")
    specs = [dict(item) for item in diagnosis["specs"]]
    block_index = int(mutation.get("block_idx", -1))
    if not 0 <= block_index < len(specs):
        raise IndexError(f"block_idx {block_index} outside ZIP entry range")
    field = str(mutation.get("field", ""))
    value = mutation.get("value")
    if field in {"name", "local.name"}:
        old = specs[block_index]["name"]
        specs[block_index]["name"] = _safe_name(value)
        if specs[block_index]["is_dir"] and not specs[block_index]["name"].endswith("/"):
            specs[block_index]["name"] += "/"
        new = specs[block_index]["name"]
    elif field in {"data", "local.data"}:
        old = specs[block_index]["data"]
        specs[block_index]["data"] = _as_bytes(value)
        new = specs[block_index]["data"]
    elif field in {"crc32", "local.crc32", "central.crc32", "central.local_offset", "EOCD.central_offset"}:
        raise ValueError(f"{field} is derived; mutate name/data and it will be recalculated")
    else:
        raise KeyError(f"ZIP field is not structurally mutable: {field}")
    rebuilt = _zip_build({"files": specs})
    rebuilt["changed_fields"] = [{"block_idx": block_index, "field": field, "old": old.hex().upper() if isinstance(old, bytes) else old, "new": new.hex().upper() if isinstance(new, bytes) else new, "offset_shift": 0}]
    return rebuilt


RAR4_SIGNATURE = b"Rar!\x1a\x07\x00"


def _rar4_header(header_type: int, flags: int, body: bytes) -> bytes:
    size = 7 + len(body)
    if size > 0xFFFF:
        raise ValueError("RAR4 header exceeds uint16 size")
    covered = struct.pack("<BHH", header_type, flags, size) + body
    return struct.pack("<H", binascii.crc32(covered) & 0xFFFF) + covered


def _rar4_build(spec: dict[str, Any]) -> ContainerResult:
    entries = _entries_from_spec(spec)
    output = bytearray(RAR4_SIGNATURE)
    maps: list[dict[str, Any]] = [
        _map("signature", 0, RAR4_SIGNATURE, [_semantic_field("signature", 0, 7, RAR4_SIGNATURE, "bytes[7]", "enum", "RAR4 fixed signature")], type="signature")
    ]
    main_offset = len(output)
    main = _rar4_header(0x73, int(spec.get("flags", 0)), bytes(6))
    output.extend(main)
    snapshot = bytes(output)
    main_fields = [
        _semantic_field("header.crc16", main_offset, 2, snapshot, "uint16le", "checksum", "low 16 bits of CRC32 over header type through body", related=("header",)),
        _semantic_field("header.type", main_offset + 2, 1, snapshot, "uint8", "enum", "MAIN_HEAD=0x73"),
        _semantic_field("header.flags", main_offset + 3, 2, snapshot, "uint16le", "flags", "archive flags"),
        _semantic_field("header.size", main_offset + 5, 2, snapshot, "uint16le", "length", "main header byte length", related=("header",)),
    ]
    maps.append(_map("main", main_offset, main, main_fields, type="main", block_index=0))
    for index, entry in enumerate(entries, start=1):
        name_bytes = entry["name"].encode("utf-8")
        payload = entry["data"]
        is_dir = entry["is_dir"]
        flags = 0x8000 | (0x00E0 if is_dir else 0)
        attributes = int(entry.get("attributes", 0x10 if is_dir else 0x20))
        file_crc = binascii.crc32(payload) & 0xFFFFFFFF
        body = struct.pack(
            "<IIBIIBBHI",
            len(payload),
            len(payload),
            int(entry.get("host_os", 2)),
            file_crc,
            int(entry.get("dos_time", 0)),
            20,
            0x30,
            len(name_bytes),
            attributes,
        ) + name_bytes
        header = _rar4_header(0x74, flags, body)
        offset = len(output)
        block = header + payload
        output.extend(block)
        snapshot = bytes(output)
        fields = [
            _semantic_field("header.crc16", offset, 2, snapshot, "uint16le", "checksum", "low CRC32 of file header", related=("header",)),
            _semantic_field("header.type", offset + 2, 1, snapshot, "uint8", "enum", "FILE_HEAD=0x74"),
            _semantic_field("header.flags", offset + 3, 2, snapshot, "uint16le", "flags", "LONG_BLOCK and directory flags"),
            _semantic_field("header.size", offset + 5, 2, snapshot, "uint16le", "length", "file header including name", related=("file.name",)),
            _semantic_field("file.packed_size", offset + 7, 4, snapshot, "uint32le", "length", "stored data length", related=("data",)),
            _semantic_field("file.unpacked_size", offset + 11, 4, snapshot, "uint32le", "length", "decoded data length", related=("data",)),
            _semantic_field("file.host_os", offset + 15, 1, snapshot, "uint8", "enum", "RAR4 host OS"),
            _semantic_field("file.crc32", offset + 16, 4, snapshot, "uint32le", "checksum", "CRC32 of unpacked data", related=("data",)),
            _semantic_field("file.method", offset + 25, 1, snapshot, "uint8", "enum", "0x30=store"),
            _semantic_field("file.name_length", offset + 26, 2, snapshot, "uint16le", "length", "name byte length", related=("file.name",)),
            _semantic_field("file.attributes", offset + 28, 4, snapshot, "uint32le", "flags", "host file attributes"),
            _semantic_field("file.name", offset + 32, len(name_bytes), snapshot, f"utf8[{len(name_bytes)}]", "payload", "archive path", related=("file.name_length",)),
        ]
        if payload:
            fields.append(_semantic_field("data", offset + len(header), len(payload), snapshot, f"bytes[{len(payload)}]", "payload", "stored entry bytes", related=("file.packed_size", "file.unpacked_size", "file.crc32")))
        maps.append(_map(f"file:{entry['name']}", offset, block, fields, type="file", block_index=index))
    end_offset = len(output)
    end = _rar4_header(0x7B, 0, b"")
    output.extend(end)
    snapshot = bytes(output)
    maps.append(
        _map(
            "end",
            end_offset,
            end,
            [
                _semantic_field("header.crc16", end_offset, 2, snapshot, "uint16le", "checksum", "low CRC32 of end header", related=("header",)),
                _semantic_field("header.type", end_offset + 2, 1, snapshot, "uint8", "enum", "ENDARC_HEAD=0x7B"),
                _semantic_field("header.size", end_offset + 5, 2, snapshot, "uint16le", "length", "end header length"),
            ],
            type="end",
            block_index=len(entries) + 1,
        )
    )
    validators = (
        ValidatorCommand("format-kb", ("container-diagnose", "rar4", "{file}")),
        ValidatorCommand("7z", ("t", "-bd", "-y", "{file}")),
    )
    result = _result("rar4", bytes(output), maps, validators)
    diagnosis = _rar4_diagnose(result["bytes"], include_specs=False)
    if not diagnosis["valid"]:
        raise RuntimeError(f"internal RAR4 build validation failed: {diagnosis['errors']}")
    result["diagnosis"] = diagnosis
    return result


def _rar4_diagnose(data: bytes, *, include_specs: bool = False) -> dict[str, Any]:
    errors: list[dict[str, Any]] = []
    warnings: list[dict[str, Any]] = []
    blocks: list[dict[str, Any]] = []
    specs: list[dict[str, Any]] = []
    if not data.startswith(RAR4_SIGNATURE):
        return {"format_id": "rar4", "valid": False, "block_count": 0, "blocks": [], "errors": [{"level": "signature", "offset": 0, "message": "RAR4 signature mismatch"}], "warnings": []}
    position = 7
    end_seen = False
    while position < len(data) and not errors:
        start = position
        try:
            if position + 7 > len(data):
                raise ValueError("truncated RAR4 base header")
            declared_crc, header_type, flags, header_size = struct.unpack_from("<HBHH", data, position)
            if header_size < 7 or position + header_size > len(data):
                raise ValueError("RAR4 header size exceeds file")
            actual_crc = binascii.crc32(data[position + 2 : position + header_size]) & 0xFFFF
            if declared_crc != actual_crc:
                raise ValueError(f"header CRC16 mismatch: declared 0x{declared_crc:04X}, actual 0x{actual_crc:04X}")
            packed_size = int.from_bytes(data[position + 7 : position + 11], "little") if flags & 0x8000 else 0
            data_end = position + header_size + packed_size
            if data_end > len(data):
                raise ValueError("RAR4 packed data exceeds file")
            name = {0x73: "main", 0x74: "file", 0x7B: "end"}.get(header_type, f"header-0x{header_type:02X}")
            spec_item: dict[str, Any] = {"type": name, "flags": flags}
            if header_type == 0x74:
                if header_size < 32:
                    raise ValueError("RAR4 file header is shorter than fixed fields")
                unpacked_size = int.from_bytes(data[position + 11 : position + 15], "little")
                host_os = data[position + 15]
                file_crc = int.from_bytes(data[position + 16 : position + 20], "little")
                method = data[position + 25]
                name_length = int.from_bytes(data[position + 26 : position + 28], "little")
                if 32 + name_length > header_size:
                    raise ValueError("RAR4 file name exceeds header")
                file_name = data[position + 32 : position + 32 + name_length].decode("utf-8")
                payload = data[position + header_size : data_end]
                if method == 0x30 and unpacked_size != packed_size:
                    raise ValueError("stored RAR4 file packed/unpacked sizes differ")
                if file_crc != binascii.crc32(payload) & 0xFFFFFFFF:
                    raise ValueError("RAR4 file CRC32 mismatch")
                name = f"file:{file_name}"
                spec_item = {"type": "file", "name": file_name, "data": payload, "host_os": host_os, "attributes": int.from_bytes(data[position + 28 : position + 32], "little"), "is_dir": bool(flags & 0xE0)}
            elif header_type == 0x7B:
                end_seen = True
                spec_item = {"type": "end"}
            blocks.append({"index": len(blocks), "name": name, "type": header_type, "offset": start, "header_length": header_size, "data_length": packed_size, "length": data_end - start, "status": "ok"})
            specs.append(spec_item)
            position = data_end
        except (UnicodeDecodeError, ValueError) as exc:
            errors.append({"level": "block", "block_index": len(blocks), "offset": start, "message": str(exc)})
    if not errors and not end_seen:
        errors.append({"level": "archive", "offset": position, "message": "RAR4 end header is missing"})
    result: dict[str, Any] = {"format_id": "rar4", "valid": not errors, "block_count": len(blocks), "blocks": blocks, "errors": errors[:1], "warnings": warnings}
    if include_specs:
        result["specs"] = specs
    return result


def _rar4_mutate(data: bytes, mutation: dict[str, Any]) -> ContainerResult:
    diagnosis = _rar4_diagnose(data, include_specs=True)
    if not diagnosis["valid"]:
        raise ValueError(f"cannot mutate invalid RAR4: {diagnosis['errors'][0]['message']}")
    files = [dict(item) for item in diagnosis["specs"] if item.get("type") == "file"]
    block_index = int(mutation.get("block_idx", -1))
    file_index = block_index - 1  # main is block 0
    if not 0 <= file_index < len(files):
        raise IndexError("RAR4 block_idx must select a file block")
    field = str(mutation.get("field", ""))
    value = mutation.get("value")
    if field in {"name", "file.name"}:
        old = files[file_index]["name"]
        files[file_index]["name"] = _safe_name(value)
        new = files[file_index]["name"]
    elif field in {"data", "file.data"}:
        old = files[file_index]["data"]
        files[file_index]["data"] = _as_bytes(value)
        new = files[file_index]["data"]
    elif field in {"file.crc32", "file.packed_size", "file.unpacked_size", "header.size", "header.crc16"}:
        raise ValueError(f"{field} is derived and is recalculated from name/data")
    else:
        raise KeyError(f"RAR4 field is not structurally mutable: {field}")
    rebuilt = _rar4_build({"files": files})
    rebuilt["changed_fields"] = [{"block_idx": block_index, "field": field, "old": old.hex().upper() if isinstance(old, bytes) else old, "new": new.hex().upper() if isinstance(new, bytes) else new, "offset_shift": 0}]
    return rebuilt


def _pad4(value: int) -> int:
    return (-value) & 3


def _cpio_record(name: str, payload: bytes, *, inode: int, mode: int) -> tuple[bytes, dict[str, int]]:
    name_bytes = name.encode("utf-8") + b"\0"
    values = (inode, mode, 0, 0, 1, 0, len(payload), 0, 0, 0, 0, len(name_bytes), 0)
    header = b"070701" + b"".join(f"{value:08X}".encode("ascii") for value in values)
    name_padding = bytes(_pad4(len(header) + len(name_bytes)))
    data_padding = bytes(_pad4(len(payload)))
    record = header + name_bytes + name_padding + payload + data_padding
    return record, {"name_offset": 110, "name_length": len(name_bytes), "data_offset": 110 + len(name_bytes) + len(name_padding), "data_length": len(payload)}


def _cpio_build(spec: dict[str, Any]) -> ContainerResult:
    entries = _entries_from_spec(spec)
    output = bytearray()
    maps: list[dict[str, Any]] = []
    for index, entry in enumerate(entries, start=1):
        mode = int(entry.get("mode", 0o040755 if entry["is_dir"] else 0o100644))
        record, layout = _cpio_record(entry["name"].rstrip("/") if entry["is_dir"] else entry["name"], entry["data"], inode=index, mode=mode)
        offset = len(output)
        output.extend(record)
        snapshot = bytes(output)
        fields = [
            _semantic_field("header.magic", offset, 6, snapshot, "ascii[6]", "enum", "newc magic 070701"),
            _semantic_field("header.ino", offset + 6, 8, snapshot, "ascii-hex32", "integer", "inode number"),
            _semantic_field("header.mode", offset + 14, 8, snapshot, "ascii-hex32", "flags", "file type and permission bits"),
            _semantic_field("header.filesize", offset + 54, 8, snapshot, "ascii-hex32", "length", "payload byte length", related=("data",)),
            _semantic_field("header.namesize", offset + 94, 8, snapshot, "ascii-hex32", "length", "name bytes including NUL", related=("name",)),
            _semantic_field("name", offset + layout["name_offset"], layout["name_length"], snapshot, f"utf8-nul[{layout['name_length']}]", "payload", "archive path including NUL", related=("header.namesize",)),
        ]
        if layout["data_length"]:
            fields.append(_semantic_field("data", offset + layout["data_offset"], layout["data_length"], snapshot, f"bytes[{layout['data_length']}]", "payload", "entry data", related=("header.filesize",)))
        maps.append(_map(f"entry:{entry['name']}", offset, record, fields, type="entry", block_index=index - 1))
    trailer, layout = _cpio_record("TRAILER!!!", b"", inode=0, mode=0)
    trailer_offset = len(output)
    output.extend(trailer)
    snapshot = bytes(output)
    maps.append(
        _map(
            "trailer",
            trailer_offset,
            trailer,
            [
                _semantic_field("header.magic", trailer_offset, 6, snapshot, "ascii[6]", "enum", "newc magic"),
                _semantic_field("name", trailer_offset + layout["name_offset"], layout["name_length"], snapshot, "utf8-nul[11]", "enum", "TRAILER!!! terminator"),
            ],
            type="end",
        )
    )
    validators = (
        ValidatorCommand("format-kb", ("container-diagnose", "cpio-newc", "{file}")),
        ValidatorCommand("bsdtar", ("-tf", "{file}")),
    )
    result = _result("cpio-newc", bytes(output), maps, validators)
    diagnosis = _cpio_diagnose(result["bytes"], include_specs=False)
    if not diagnosis["valid"]:
        raise RuntimeError(f"internal cpio build validation failed: {diagnosis['errors']}")
    result["diagnosis"] = diagnosis
    return result


def _cpio_diagnose(data: bytes, *, include_specs: bool = False) -> dict[str, Any]:
    blocks: list[dict[str, Any]] = []
    specs: list[dict[str, Any]] = []
    errors: list[dict[str, Any]] = []
    warnings: list[dict[str, Any]] = []
    position = 0
    trailer_seen = False
    while position < len(data) and not errors:
        start = position
        try:
            if position + 110 > len(data) or data[position : position + 6] not in {b"070701", b"070702"}:
                raise ValueError("invalid/truncated cpio newc header")
            fields = [int(data[position + 6 + 8 * index : position + 14 + 8 * index], 16) for index in range(13)]
            mode, filesize, namesize, check = fields[1], fields[6], fields[11], fields[12]
            if namesize < 1:
                raise ValueError("cpio namesize must include a NUL byte")
            name_start = position + 110
            name_end = name_start + namesize
            if name_end > len(data) or data[name_end - 1] != 0:
                raise ValueError("cpio entry name is truncated or lacks NUL")
            data_start = name_end + _pad4(name_end - position)
            data_end = data_start + filesize
            record_end = data_end + _pad4(filesize)
            if record_end > len(data):
                raise ValueError("cpio entry payload exceeds archive")
            name = data[name_start : name_end - 1].decode("utf-8")
            payload = data[data_start:data_end]
            if data[position : position + 6] == b"070702" and sum(payload) & 0xFFFFFFFF != check:
                raise ValueError("cpio crc variant checksum mismatch")
            blocks.append({"index": len(blocks), "name": name, "type": "trailer" if name == "TRAILER!!!" else "entry", "offset": start, "length": record_end - start, "status": "ok"})
            if name == "TRAILER!!!":
                trailer_seen = True
                position = record_end
                break
            specs.append({"name": name, "data": payload, "is_dir": mode & 0o170000 == 0o040000, "mode": mode})
            position = record_end
        except (UnicodeDecodeError, ValueError) as exc:
            errors.append({"level": "entry", "block_index": len(blocks), "offset": start, "message": str(exc)})
    if not errors and not trailer_seen:
        errors.append({"level": "archive", "offset": position, "message": "cpio TRAILER!!! record is missing"})
    if trailer_seen and any(data[position:]):
        warnings.append({"level": "padding", "offset": position, "message": "nonzero bytes after cpio trailer"})
    result: dict[str, Any] = {"format_id": "cpio-newc", "valid": not errors, "block_count": len(blocks), "blocks": blocks, "errors": errors[:1], "warnings": warnings}
    if include_specs:
        result["specs"] = specs
    return result


def _cpio_mutate(data: bytes, mutation: dict[str, Any]) -> ContainerResult:
    diagnosis = _cpio_diagnose(data, include_specs=True)
    if not diagnosis["valid"]:
        raise ValueError(f"cannot mutate invalid cpio: {diagnosis['errors'][0]['message']}")
    specs = [dict(item) for item in diagnosis["specs"]]
    index = int(mutation.get("block_idx", -1))
    if not 0 <= index < len(specs):
        raise IndexError("cpio block_idx outside entry range")
    field = str(mutation.get("field", ""))
    old: Any
    if field in {"name", "entry.name"}:
        old = specs[index]["name"]
        specs[index]["name"] = _safe_name(mutation.get("value"))
        new = specs[index]["name"]
    elif field in {"data", "entry.data"}:
        old = specs[index]["data"]
        specs[index]["data"] = _as_bytes(mutation.get("value"))
        new = specs[index]["data"]
    elif field in {"header.filesize", "header.namesize"}:
        raise ValueError(f"{field} is derived and recalculated from the entry")
    else:
        raise KeyError(f"cpio field is not structurally mutable: {field}")
    rebuilt = _cpio_build({"files": specs})
    rebuilt["changed_fields"] = [{"block_idx": index, "field": field, "old": old.hex().upper() if isinstance(old, bytes) else old, "new": new.hex().upper() if isinstance(new, bytes) else new, "offset_shift": 0}]
    return rebuilt


def _ar_member(name: str, payload: bytes, mode: int = 0o100644) -> tuple[bytes, int, int]:
    name_bytes = name.encode("utf-8")
    if len(name_bytes) <= 15 and b" " not in name_bytes:
        name_field = name_bytes.ljust(16, b" ")
        stored = payload
        data_offset = 60
    else:
        marker = f"#1/{len(name_bytes)}".encode("ascii")
        if len(marker) > 16:
            raise ValueError("ar BSD extended filename is too long")
        name_field = marker.ljust(16, b" ")
        stored = name_bytes + payload
        data_offset = 60 + len(name_bytes)
    header = (
        name_field
        + b"0".ljust(12, b" ")
        + b"0".ljust(6, b" ")
        + b"0".ljust(6, b" ")
        + f"{mode:o}".encode("ascii").ljust(8, b" ")
        + str(len(stored)).encode("ascii").ljust(10, b" ")
        + b"`\n"
    )
    member = header + stored + (b"\n" if len(stored) & 1 else b"")
    return member, data_offset, len(payload)


def _ar_build(spec: dict[str, Any]) -> ContainerResult:
    entries = [entry for entry in _entries_from_spec(spec) if not entry["is_dir"]]
    output = bytearray(b"!<arch>\n")
    maps = [_map("signature", 0, b"!<arch>\n", [_semantic_field("signature", 0, 8, b"!<arch>\n", "bytes[8]", "enum", "Unix ar global signature")], type="signature")]
    for index, entry in enumerate(entries):
        member, data_offset, data_length = _ar_member(entry["name"], entry["data"], int(entry.get("mode", 0o100644)))
        offset = len(output)
        output.extend(member)
        snapshot = bytes(output)
        fields = [
            _semantic_field("member.name_field", offset, 16, snapshot, "ascii[16]", "payload", "short name or BSD #1/length marker"),
            _semantic_field("member.timestamp", offset + 16, 12, snapshot, "ascii-decimal", "integer", "deterministic epoch timestamp"),
            _semantic_field("member.mode", offset + 40, 8, snapshot, "ascii-octal", "flags", "file mode"),
            _semantic_field("member.size", offset + 48, 10, snapshot, "ascii-decimal", "length", "stored member bytes", related=("member.data",)),
            _semantic_field("member.terminator", offset + 58, 2, snapshot, "bytes[2]", "enum", "backtick + LF"),
        ]
        if data_length:
            fields.append(_semantic_field("member.data", offset + data_offset, data_length, snapshot, f"bytes[{data_length}]", "payload", "archive member payload", related=("member.size",)))
        maps.append(_map(f"member:{entry['name']}", offset, member, fields, type="member", block_index=index))
    validators = (
        ValidatorCommand("format-kb", ("container-diagnose", "unix-ar", "{file}")),
        ValidatorCommand("ar", ("-t", "{file}")),
    )
    result = _result("unix-ar", bytes(output), maps, validators)
    diagnosis = _ar_diagnose(result["bytes"], include_specs=False)
    if not diagnosis["valid"]:
        raise RuntimeError(f"internal ar build validation failed: {diagnosis['errors']}")
    result["diagnosis"] = diagnosis
    return result


def _ar_diagnose(data: bytes, *, include_specs: bool = False) -> dict[str, Any]:
    if not data.startswith(b"!<arch>\n"):
        return {"format_id": "unix-ar", "valid": False, "block_count": 0, "blocks": [], "errors": [{"level": "signature", "offset": 0, "message": "ar global signature mismatch"}], "warnings": []}
    position = 8
    blocks: list[dict[str, Any]] = []
    specs: list[dict[str, Any]] = []
    errors: list[dict[str, Any]] = []
    while position < len(data) and not errors:
        start = position
        try:
            if position + 60 > len(data) or data[position + 58 : position + 60] != b"`\n":
                raise ValueError("truncated ar member header or bad terminator")
            size = int(data[position + 48 : position + 58].decode("ascii").strip() or "0")
            stored_start = position + 60
            stored_end = stored_start + size
            if stored_end > len(data):
                raise ValueError("ar member exceeds archive")
            raw_name = data[position : position + 16].decode("ascii").rstrip()
            if raw_name.startswith("#1/"):
                name_length = int(raw_name[3:])
                if name_length > size:
                    raise ValueError("ar BSD extended name exceeds member")
                name = data[stored_start : stored_start + name_length].decode("utf-8")
                payload = data[stored_start + name_length : stored_end]
            else:
                name = raw_name.rstrip("/")
                payload = data[stored_start:stored_end]
            end = stored_end + (size & 1)
            if end > len(data):
                raise ValueError("ar odd-size member padding is missing")
            blocks.append({"index": len(blocks), "name": name, "type": "member", "offset": start, "length": end - start, "status": "ok"})
            specs.append({"name": name, "data": payload})
            position = end
        except (UnicodeDecodeError, ValueError) as exc:
            errors.append({"level": "member", "block_index": len(blocks), "offset": start, "message": str(exc)})
    result: dict[str, Any] = {"format_id": "unix-ar", "valid": not errors, "block_count": len(blocks), "blocks": blocks, "errors": errors[:1], "warnings": []}
    if include_specs:
        result["specs"] = specs
    return result


def _ar_mutate(data: bytes, mutation: dict[str, Any]) -> ContainerResult:
    diagnosis = _ar_diagnose(data, include_specs=True)
    if not diagnosis["valid"]:
        raise ValueError(f"cannot mutate invalid ar: {diagnosis['errors'][0]['message']}")
    specs = [dict(item) for item in diagnosis["specs"]]
    index = int(mutation.get("block_idx", -1))
    if not 0 <= index < len(specs):
        raise IndexError("ar block_idx outside member range")
    field = str(mutation.get("field", ""))
    if field in {"name", "member.name"}:
        old = specs[index]["name"]
        specs[index]["name"] = _safe_name(mutation.get("value"))
        new = specs[index]["name"]
    elif field in {"data", "member.data"}:
        old = specs[index]["data"]
        specs[index]["data"] = _as_bytes(mutation.get("value"))
        new = specs[index]["data"]
    elif field == "member.size":
        raise ValueError("member.size is derived and recalculated from name/data")
    else:
        raise KeyError(f"ar field is not structurally mutable: {field}")
    rebuilt = _ar_build({"files": specs})
    rebuilt["changed_fields"] = [{"block_idx": index, "field": field, "old": old.hex().upper() if isinstance(old, bytes) else old, "new": new.hex().upper() if isinstance(new, bytes) else new, "offset_shift": 0}]
    return rebuilt


ISO_SECTOR = 2048


def _both16(value: int) -> bytes:
    return struct.pack("<H", value) + struct.pack(">H", value)


def _both32(value: int) -> bytes:
    return struct.pack("<I", value) + struct.pack(">I", value)


def _iso_identifier(name: str, *, directory: bool) -> bytes:
    base = name.rstrip("/").upper()
    if not base or any(character not in "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_.-" for character in base):
        raise ValueError(f"ISO9660 level-1-compatible identifier required: {name!r}")
    encoded = base.encode("ascii")
    if len(encoded) > (31 if directory else 28):
        raise ValueError("ISO9660 identifier is too long")
    return encoded if directory else encoded + b";1"


def _iso_dir_record(identifier: bytes, extent: int, size: int, *, directory: bool) -> bytes:
    padding = b"\0" if len(identifier) % 2 == 0 else b""
    length = 33 + len(identifier) + len(padding)
    date = bytes((80, 1, 1, 0, 0, 0, 0))
    return (
        bytes((length, 0))
        + _both32(extent)
        + _both32(size)
        + date
        + bytes((2 if directory else 0, 0, 0))
        + _both16(1)
        + bytes((len(identifier),))
        + identifier
        + padding
    )


def _iso_path_record(identifier: bytes, extent: int, parent: int, *, big: bool) -> bytes:
    endian = ">" if big else "<"
    padding = b"\0" if len(identifier) & 1 else b""
    return bytes((len(identifier), 0)) + struct.pack(f"{endian}I", extent) + struct.pack(f"{endian}H", parent) + identifier + padding


def _iso9660_build(spec: dict[str, Any]) -> ContainerResult:
    entries = _entries_from_spec(spec)
    directories = [entry for entry in entries if entry["is_dir"]]
    files = [entry for entry in entries if not entry["is_dir"]]
    if any("/" in entry["name"].rstrip("/") for entry in entries):
        raise ValueError("ISO9660 builder currently supports root files and one-level empty directories")
    label = str(spec.get("label", spec.get("labels", ["FORMAT_KB"])[0] if spec.get("labels") else "FORMAT_KB")).upper()
    if not label or len(label.encode("ascii")) > 32:
        raise ValueError("ISO9660 volume label must be 1..32 ASCII bytes")

    root_sector = 20
    directory_sectors = {entry["name"]: root_sector + 1 + index for index, entry in enumerate(directories)}
    next_sector = root_sector + 1 + len(directories)
    file_sectors: dict[str, tuple[int, int]] = {}
    for entry in files:
        sectors = max(1, (len(entry["data"]) + ISO_SECTOR - 1) // ISO_SECTOR)
        file_sectors[entry["name"]] = (next_sector, sectors)
        next_sector += sectors
    volume_sectors = max(next_sector, 21)

    root_records = bytearray()
    root_records.extend(_iso_dir_record(b"\0", root_sector, ISO_SECTOR, directory=True))
    root_records.extend(_iso_dir_record(b"\1", root_sector, ISO_SECTOR, directory=True))
    for entry in directories:
        root_records.extend(_iso_dir_record(_iso_identifier(entry["name"], directory=True), directory_sectors[entry["name"]], ISO_SECTOR, directory=True))
    for entry in files:
        extent, _ = file_sectors[entry["name"]]
        root_records.extend(_iso_dir_record(_iso_identifier(entry["name"], directory=False), extent, len(entry["data"]), directory=False))
    if len(root_records) > ISO_SECTOR:
        raise ValueError("ISO9660 root directory exceeds one sector")

    path_l = bytearray(_iso_path_record(b"\0", root_sector, 1, big=False))
    path_m = bytearray(_iso_path_record(b"\0", root_sector, 1, big=True))
    for entry in directories:
        identifier = _iso_identifier(entry["name"], directory=True)
        path_l.extend(_iso_path_record(identifier, directory_sectors[entry["name"]], 1, big=False))
        path_m.extend(_iso_path_record(identifier, directory_sectors[entry["name"]], 1, big=True))
    if len(path_l) > ISO_SECTOR:
        raise ValueError("ISO9660 path table exceeds one sector")

    image = bytearray(volume_sectors * ISO_SECTOR)
    pvd_offset = 16 * ISO_SECTOR
    pvd = memoryview(image)[pvd_offset : pvd_offset + ISO_SECTOR]
    pvd[0:7] = b"\x01CD001\x01"
    pvd[8:40] = b"FORMAT_KB".ljust(32, b" ")
    pvd[40:72] = label.encode("ascii").ljust(32, b" ")
    pvd[80:88] = _both32(volume_sectors)
    pvd[120:124] = _both16(1)
    pvd[124:128] = _both16(1)
    pvd[128:132] = _both16(ISO_SECTOR)
    pvd[132:140] = _both32(len(path_l))
    pvd[140:144] = struct.pack("<I", 18)
    pvd[148:152] = struct.pack(">I", 19)
    root_record = _iso_dir_record(b"\0", root_sector, ISO_SECTOR, directory=True)
    pvd[156 : 156 + len(root_record)] = root_record
    pvd[190:318] = b"FORMAT KNOWLEDGE BASE".ljust(128, b" ")
    pvd[318:446] = b"FORMAT KNOWLEDGE BASE".ljust(128, b" ")
    pvd[446:574] = b"FORMAT_KB".ljust(128, b" ")
    pvd[574:702] = b"FORMAT_KB".ljust(128, b" ")
    pvd[702:739] = b"FORMAT_KB".ljust(37, b" ")
    pvd[739:776] = b"FORMAT_KB".ljust(37, b" ")
    pvd[776:813] = b"FORMAT_KB".ljust(37, b" ")
    for offset in (813, 830, 847, 864):
        pvd[offset : offset + 17] = b"1980010100000000\0"
    pvd[881] = 1

    term_offset = 17 * ISO_SECTOR
    image[term_offset : term_offset + 7] = b"\xFFCD001\x01"
    image[18 * ISO_SECTOR : 18 * ISO_SECTOR + len(path_l)] = path_l
    image[19 * ISO_SECTOR : 19 * ISO_SECTOR + len(path_m)] = path_m
    image[root_sector * ISO_SECTOR : root_sector * ISO_SECTOR + len(root_records)] = root_records
    for entry in directories:
        sector = directory_sectors[entry["name"]]
        records = _iso_dir_record(b"\0", sector, ISO_SECTOR, directory=True) + _iso_dir_record(b"\1", root_sector, ISO_SECTOR, directory=True)
        image[sector * ISO_SECTOR : sector * ISO_SECTOR + len(records)] = records
    for entry in files:
        sector, _ = file_sectors[entry["name"]]
        image[sector * ISO_SECTOR : sector * ISO_SECTOR + len(entry["data"])] = entry["data"]

    data = bytes(image)
    maps: list[dict[str, Any]] = []
    pvd_fields = [
        _semantic_field("PVD.type_id_version", pvd_offset, 7, data, "bytes[7]", "enum", "type=1, CD001, version=1"),
        _semantic_field("PVD.volume_id", pvd_offset + 40, 32, data, "ascii[32]", "payload", "space-padded volume label"),
        _semantic_field("PVD.volume_space_size", pvd_offset + 80, 8, data, "both-endian-uint32", "length", "total logical sectors", related=("file size",)),
        _semantic_field("PVD.logical_block_size", pvd_offset + 128, 4, data, "both-endian-uint16", "length", "2048-byte logical sector"),
        _semantic_field("PVD.path_table_size", pvd_offset + 132, 8, data, "both-endian-uint32", "length", "path table byte size", related=("path tables",)),
        _semantic_field("PVD.l_path_table_sector", pvd_offset + 140, 4, data, "uint32le", "offset", "little-endian path table sector", related=("path_table_le",)),
        _semantic_field("PVD.m_path_table_sector", pvd_offset + 148, 4, data, "uint32be", "offset", "big-endian path table sector", related=("path_table_be",)),
        _semantic_field("PVD.root_directory_record", pvd_offset + 156, len(root_record), data, f"bytes[{len(root_record)}]", "offset", "root directory extent/size record", related=("root_directory",)),
    ]
    maps.append(_map("primary-volume-descriptor", pvd_offset, data[pvd_offset : pvd_offset + ISO_SECTOR], pvd_fields, type="descriptor", block_index=0))
    maps.append(_map("volume-descriptor-terminator", term_offset, data[term_offset : term_offset + ISO_SECTOR], [_semantic_field("terminator.type_id_version", term_offset, 7, data, "bytes[7]", "enum", "type=255, CD001, version=1")], type="descriptor", block_index=1))
    maps.append(_map("path-table-le", 18 * ISO_SECTOR, data[18 * ISO_SECTOR : 19 * ISO_SECTOR], [_semantic_field("path_table_le.records", 18 * ISO_SECTOR, len(path_l), data, f"bytes[{len(path_l)}]", "payload", "little-endian directory path records")], type="path-table"))
    maps.append(_map("path-table-be", 19 * ISO_SECTOR, data[19 * ISO_SECTOR : 20 * ISO_SECTOR], [_semantic_field("path_table_be.records", 19 * ISO_SECTOR, len(path_m), data, f"bytes[{len(path_m)}]", "payload", "big-endian directory path records")], type="path-table"))
    maps.append(_map("root-directory", root_sector * ISO_SECTOR, data[root_sector * ISO_SECTOR : (root_sector + 1) * ISO_SECTOR], [_semantic_field("root.records", root_sector * ISO_SECTOR, len(root_records), data, f"bytes[{len(root_records)}]", "payload", "root directory records", related=("PVD.root_directory_record",))], type="directory"))
    for index, entry in enumerate(directories):
        sector = directory_sectors[entry["name"]]
        maps.append(_map(f"directory:{entry['name']}", sector * ISO_SECTOR, data[sector * ISO_SECTOR : (sector + 1) * ISO_SECTOR], [_semantic_field("directory.records", sector * ISO_SECTOR, 68, data, "bytes[68]", "payload", "dot and parent records")], type="directory", block_index=index))
    for index, entry in enumerate(files):
        sector, sectors = file_sectors[entry["name"]]
        maps.append(_map(f"file:{entry['name']}", sector * ISO_SECTOR, data[sector * ISO_SECTOR : (sector + sectors) * ISO_SECTOR], [_semantic_field("file.data", sector * ISO_SECTOR, max(1, len(entry["data"])), data, f"bytes[{max(1, len(entry['data']))}]", "payload", "file extent; logical size comes from directory record")], type="file", block_index=index))
    validators = (
        ValidatorCommand("format-kb", ("container-diagnose", "iso9660", "{file}")),
        ValidatorCommand("7z", ("t", "-bd", "-y", "{file}")),
    )
    result = _result("iso9660", data, maps, validators)
    diagnosis = _iso9660_diagnose(data, include_specs=False)
    if not diagnosis["valid"]:
        raise RuntimeError(f"internal ISO9660 build validation failed: {diagnosis['errors']}")
    result["diagnosis"] = diagnosis
    return result


def _iso_read_dir(data: bytes, extent: int, size: int) -> list[dict[str, Any]]:
    start = extent * ISO_SECTOR
    end = start + size
    if start < 0 or end > len(data):
        raise ValueError("ISO9660 directory extent exceeds image")
    records: list[dict[str, Any]] = []
    position = start
    while position < end:
        length = data[position]
        if length == 0:
            position = ((position // ISO_SECTOR) + 1) * ISO_SECTOR
            continue
        if length < 34 or position + length > end:
            raise ValueError("ISO9660 directory record length is invalid")
        record = data[position : position + length]
        extent_le = int.from_bytes(record[2:6], "little")
        extent_be = int.from_bytes(record[6:10], "big")
        size_le = int.from_bytes(record[10:14], "little")
        size_be = int.from_bytes(record[14:18], "big")
        if extent_le != extent_be or size_le != size_be:
            raise ValueError("ISO9660 both-endian extent/size copies disagree")
        name_length = record[32]
        if 33 + name_length > length:
            raise ValueError("ISO9660 identifier exceeds directory record")
        identifier = record[33 : 33 + name_length]
        records.append({"offset": position, "length": length, "extent": extent_le, "size": size_le, "directory": bool(record[25] & 2), "identifier": identifier})
        position += length
    return records


def _iso9660_diagnose(data: bytes, *, include_specs: bool = False) -> dict[str, Any]:
    errors: list[dict[str, Any]] = []
    warnings: list[dict[str, Any]] = []
    blocks: list[dict[str, Any]] = []
    specs: list[dict[str, Any]] = []
    pvd_offset = 16 * ISO_SECTOR
    try:
        if len(data) < 21 * ISO_SECTOR or data[pvd_offset : pvd_offset + 7] != b"\x01CD001\x01":
            raise ValueError("ISO9660 primary volume descriptor is missing")
        volume_le = int.from_bytes(data[pvd_offset + 80 : pvd_offset + 84], "little")
        volume_be = int.from_bytes(data[pvd_offset + 84 : pvd_offset + 88], "big")
        block_le = int.from_bytes(data[pvd_offset + 128 : pvd_offset + 130], "little")
        block_be = int.from_bytes(data[pvd_offset + 130 : pvd_offset + 132], "big")
        if volume_le != volume_be or volume_le * ISO_SECTOR != len(data):
            raise ValueError("ISO9660 volume space size disagrees with image length")
        if block_le != ISO_SECTOR or block_be != ISO_SECTOR:
            raise ValueError("ISO9660 logical block size is not 2048")
        descriptor_position = pvd_offset
        terminator = False
        while descriptor_position + ISO_SECTOR <= len(data):
            if data[descriptor_position + 1 : descriptor_position + 6] != b"CD001" or data[descriptor_position + 6] != 1:
                raise ValueError("ISO9660 volume descriptor identifier/version mismatch")
            descriptor_type = data[descriptor_position]
            blocks.append({"index": len(blocks), "name": f"descriptor-{descriptor_type}", "type": "descriptor", "offset": descriptor_position, "length": ISO_SECTOR, "status": "ok"})
            descriptor_position += ISO_SECTOR
            if descriptor_type == 255:
                terminator = True
                break
        if not terminator:
            raise ValueError("ISO9660 descriptor terminator is missing")
        root_record = data[pvd_offset + 156 : pvd_offset + 190]
        root_extent = int.from_bytes(root_record[2:6], "little")
        root_size = int.from_bytes(root_record[10:14], "little")
        records = _iso_read_dir(data, root_extent, root_size)
        for record in records:
            identifier = record["identifier"]
            if identifier in {b"\0", b"\1"}:
                continue
            if record["extent"] * ISO_SECTOR + record["size"] > len(data):
                raise ValueError("ISO9660 file/directory extent exceeds image")
            name = identifier.decode("ascii")
            if record["directory"]:
                _iso_read_dir(data, record["extent"], record["size"])
                specs.append({"name": name + "/", "data": b"", "is_dir": True})
            else:
                clean_name = name.removesuffix(";1")
                payload_start = record["extent"] * ISO_SECTOR
                specs.append({"name": clean_name, "data": data[payload_start : payload_start + record["size"]], "is_dir": False})
            blocks.append({"index": len(blocks), "name": name, "type": "directory" if record["directory"] else "file", "offset": record["extent"] * ISO_SECTOR, "length": record["size"], "status": "ok"})
        label = data[pvd_offset + 40 : pvd_offset + 72].decode("ascii").rstrip()
    except (UnicodeDecodeError, ValueError) as exc:
        errors.append({"level": "volume", "block_index": len(blocks), "offset": pvd_offset, "message": str(exc)})
        label = ""
    result: dict[str, Any] = {"format_id": "iso9660", "valid": not errors, "block_count": len(blocks), "blocks": blocks, "errors": errors[:1], "warnings": warnings, "volume_label": label}
    if include_specs:
        result["specs"] = specs
    return result


def _iso9660_mutate(data: bytes, mutation: dict[str, Any]) -> ContainerResult:
    diagnosis = _iso9660_diagnose(data, include_specs=True)
    if not diagnosis["valid"]:
        raise ValueError(f"cannot mutate invalid ISO9660: {diagnosis['errors'][0]['message']}")
    specs = [dict(item) for item in diagnosis["specs"]]
    field = str(mutation.get("field", ""))
    if field in {"label", "PVD.volume_id"}:
        old = diagnosis["volume_label"]
        new = str(mutation.get("value"))
        rebuilt = _iso9660_build({"files": specs, "label": new})
        block_index = 0
    else:
        index = int(mutation.get("block_idx", -1))
        if not 0 <= index < len(specs):
            raise IndexError("ISO9660 block_idx outside root entry range")
        block_index = index
        if field in {"name", "file.name", "directory.name"}:
            old = specs[index]["name"]
            specs[index]["name"] = _safe_name(mutation.get("value"))
            new = specs[index]["name"]
        elif field in {"data", "file.data"} and not specs[index]["is_dir"]:
            old = specs[index]["data"]
            specs[index]["data"] = _as_bytes(mutation.get("value"))
            new = specs[index]["data"]
        elif field in {"extent", "size", "PVD.volume_space_size"}:
            raise ValueError(f"{field} is derived and recalculated by sector layout")
        else:
            raise KeyError(f"ISO9660 field is not structurally mutable: {field}")
        rebuilt = _iso9660_build({"files": specs, "label": diagnosis["volume_label"]})
    rebuilt["changed_fields"] = [{"block_idx": block_index, "field": field, "old": old.hex().upper() if isinstance(old, bytes) else old, "new": new.hex().upper() if isinstance(new, bytes) else new, "offset_shift": 0}]
    return rebuilt


def _align(value: int, alignment: int) -> int:
    if alignment <= 0 or alignment & (alignment - 1):
        raise ValueError("alignment must be a positive power of two")
    return (value + alignment - 1) & -alignment


def _sections_from_spec(spec: dict[str, Any], *, default_name: str) -> list[dict[str, Any]]:
    raw_sections = spec.get("sections")
    if raw_sections is None:
        payload = _as_bytes(spec.get("data", b""))
        raw_sections = [{"name": default_name, "data": payload}]
    sections: list[dict[str, Any]] = []
    for index, raw in enumerate(raw_sections):
        item = dict(raw)
        name = str(item.get("name", f"{default_name}{index}"))
        if not name or "\0" in name or len(name.encode("utf-8")) > 255:
            raise ValueError(f"invalid section name: {name!r}")
        sections.append({**item, "name": name, "data": _as_bytes(item.get("data", b""))})
    return sections


def _elf_build(spec: dict[str, Any], *, bits: int) -> ContainerResult:
    if bits not in {32, 64}:
        raise ValueError("ELF builder supports 32 or 64 bits")
    sections = _sections_from_spec(spec, default_name=".data")
    shstr = bytearray(b"\0")
    name_offsets: dict[str, int] = {}
    for section in sections:
        name_offsets[section["name"]] = len(shstr)
        shstr.extend(section["name"].encode("utf-8") + b"\0")
    name_offsets[".shstrtab"] = len(shstr)
    shstr.extend(b".shstrtab\0")

    header_size = 52 if bits == 32 else 64
    sh_entry_size = 40 if bits == 32 else 64
    cursor = header_size
    section_layout: list[tuple[dict[str, Any], int]] = []
    output = bytearray(bytes(header_size))
    for section in sections:
        alignment = int(section.get("align", 1))
        cursor = _align(cursor, alignment)
        if len(output) < cursor:
            output.extend(bytes(cursor - len(output)))
        offset = cursor
        output.extend(section["data"])
        cursor += len(section["data"])
        section_layout.append((section, offset))
    cursor = _align(cursor, 1)
    shstr_offset = cursor
    output.extend(shstr)
    cursor += len(shstr)
    table_alignment = 4 if bits == 32 else 8
    shoff = _align(cursor, table_alignment)
    output.extend(bytes(shoff - len(output)))

    section_count = len(sections) + 2
    shstr_index = section_count - 1
    output.extend(bytes(sh_entry_size))
    for section, offset in section_layout:
        section_type = int(section.get("type", 1))
        flags = int(section.get("flags", 0))
        alignment = int(section.get("align", 1))
        if bits == 32:
            header = struct.pack("<IIIIIIIIII", name_offsets[section["name"]], section_type, flags, 0, offset, len(section["data"]), int(section.get("link", 0)), int(section.get("info", 0)), alignment, int(section.get("entsize", 0)))
        else:
            header = struct.pack("<IIQQQQIIQQ", name_offsets[section["name"]], section_type, flags, 0, offset, len(section["data"]), int(section.get("link", 0)), int(section.get("info", 0)), alignment, int(section.get("entsize", 0)))
        output.extend(header)
    if bits == 32:
        output.extend(struct.pack("<IIIIIIIIII", name_offsets[".shstrtab"], 3, 0, 0, shstr_offset, len(shstr), 0, 0, 1, 0))
    else:
        output.extend(struct.pack("<IIQQQQIIQQ", name_offsets[".shstrtab"], 3, 0, 0, shstr_offset, len(shstr), 0, 0, 1, 0))

    ident = b"\x7fELF" + bytes((1 if bits == 32 else 2, 1, 1, int(spec.get("osabi", 0)), 0)) + bytes(7)
    if bits == 32:
        header = ident + struct.pack("<HHIIIIIHHHHHH", 1, int(spec.get("machine", 3)), 1, 0, 0, shoff, int(spec.get("flags", 0)), 52, 0, 0, 40, section_count, shstr_index)
    else:
        header = ident + struct.pack("<HHIQQQIHHHHHH", 1, int(spec.get("machine", 62)), 1, 0, 0, shoff, int(spec.get("flags", 0)), 64, 0, 0, 64, section_count, shstr_index)
    output[:header_size] = header
    data = bytes(output)
    format_id = f"elf{bits}-le"
    maps: list[dict[str, Any]] = []
    fields = [
        _semantic_field("e_ident", 0, 16, data, "bytes[16]", "enum", f"ELF{bits} little-endian identity"),
        _semantic_field("e_type", 16, 2, data, "uint16le", "enum", "ET_REL=1"),
        _semantic_field("e_machine", 18, 2, data, "uint16le", "enum", "target machine"),
        _semantic_field("e_shoff", 32 if bits == 32 else 40, 4 if bits == 32 else 8, data, f"uint{bits}le", "offset", "section header table offset", related=("section-header-table",)),
        _semantic_field("e_shentsize", 46 if bits == 32 else 58, 2, data, "uint16le", "length", "section header entry size", related=("section-header-table",)),
        _semantic_field("e_shnum", 48 if bits == 32 else 60, 2, data, "uint16le", "length", "section header count", related=("section-header-table",)),
        _semantic_field("e_shstrndx", 50 if bits == 32 else 62, 2, data, "uint16le", "offset", "section-name string table index", related=(".shstrtab",)),
    ]
    maps.append(_map("elf-header", 0, data[:header_size], fields, type="header", block_index=0))
    for index, (section, offset) in enumerate(section_layout, start=1):
        length = max(1, len(section["data"]))
        maps.append(_map(f"section:{section['name']}", offset, data[offset : offset + length], [_semantic_field("section.data", offset, length, data, f"bytes[{length}]", "payload", "section contents", related=(f"section-header[{index}]",))], type="section", block_index=index))
    maps.append(_map("section:.shstrtab", shstr_offset, data[shstr_offset : shstr_offset + len(shstr)], [_semantic_field("section.names", shstr_offset, len(shstr), data, f"bytes[{len(shstr)}]", "payload", "NUL-terminated section names")], type="section", block_index=shstr_index))
    maps.append(_map("section-header-table", shoff, data[shoff:], [_semantic_field("section_headers", shoff, len(data) - shoff, data, f"bytes[{len(data) - shoff}]", "payload", "null + user + shstrtab section headers", related=("e_shoff", "e_shnum", "e_shentsize"))], type="table"))
    validators = (
        ValidatorCommand("format-kb", ("container-diagnose", format_id, "{file}")),
        ValidatorCommand("objdump", ("-h", "{file}")),
    )
    result = _result(format_id, data, maps, validators)
    diagnosis = _elf_diagnose(data, include_specs=False)
    if not diagnosis["valid"]:
        raise RuntimeError(f"internal ELF build validation failed: {diagnosis['errors']}")
    result["diagnosis"] = diagnosis
    return result


def _elf32_build(spec: dict[str, Any]) -> ContainerResult:
    return _elf_build(spec, bits=32)


def _elf64_build(spec: dict[str, Any]) -> ContainerResult:
    return _elf_build(spec, bits=64)


def _elf_diagnose(data: bytes, *, include_specs: bool = False) -> dict[str, Any]:
    errors: list[dict[str, Any]] = []
    blocks: list[dict[str, Any]] = []
    specs: list[dict[str, Any]] = []
    try:
        if len(data) < 52 or data[:4] != b"\x7fELF" or data[5] != 1 or data[6] != 1:
            raise ValueError("unsupported ELF identity (requires ELF32/64 little-endian v1)")
        bits = 32 if data[4] == 1 else 64 if data[4] == 2 else 0
        if not bits:
            raise ValueError("invalid ELF class")
        header_size = 52 if bits == 32 else 64
        shoff = int.from_bytes(data[32:36] if bits == 32 else data[40:48], "little")
        shentsize = int.from_bytes(data[46:48] if bits == 32 else data[58:60], "little")
        shnum = int.from_bytes(data[48:50] if bits == 32 else data[60:62], "little")
        shstrndx = int.from_bytes(data[50:52] if bits == 32 else data[62:64], "little")
        expected_size = 40 if bits == 32 else 64
        if len(data) < header_size or shentsize != expected_size or shnum < 1 or shoff + shentsize * shnum > len(data):
            raise ValueError("ELF section header table size/count/range is invalid")
        if any(data[shoff : shoff + shentsize]):
            raise ValueError("ELF section header zero is not all zero")
        if not 0 < shstrndx < shnum:
            raise ValueError("ELF shstrndx is outside section table")

        def sh_values(index: int) -> tuple[int, int, int, int, int, int, int, int, int, int]:
            offset = shoff + index * shentsize
            return struct.unpack_from("<IIIIIIIIII" if bits == 32 else "<IIQQQQIIQQ", data, offset)

        shstr_header = sh_values(shstrndx)
        string_offset, string_size = shstr_header[4], shstr_header[5]
        if string_offset + string_size > len(data) or not data[string_offset : string_offset + 1] == b"\0":
            raise ValueError("ELF section-name string table is invalid")
        strings = data[string_offset : string_offset + string_size]
        blocks.append({"index": 0, "name": "elf-header", "type": "header", "offset": 0, "length": header_size, "status": "ok"})
        for index in range(1, shnum):
            values = sh_values(index)
            name_index, section_type, flags, _address, offset, size, link, info, alignment, entsize = values
            if name_index >= len(strings):
                raise ValueError(f"ELF section {index} name offset exceeds shstrtab")
            end = strings.find(b"\0", name_index)
            if end < 0:
                raise ValueError(f"ELF section {index} name lacks terminator")
            name = strings[name_index:end].decode("utf-8")
            if section_type != 8 and offset + size > len(data):
                raise ValueError(f"ELF section {index} range exceeds file")
            if alignment and alignment & (alignment - 1):
                raise ValueError(f"ELF section {index} alignment is not a power of two")
            if link >= shnum:
                raise ValueError(f"ELF section {index} sh_link is outside table")
            payload = b"" if section_type == 8 else data[offset : offset + size]
            blocks.append({"index": index, "name": name, "type": "section", "offset": offset, "length": size, "status": "ok"})
            if index != shstrndx:
                specs.append({"name": name, "data": payload, "type": section_type, "flags": flags, "link": link, "info": info, "align": alignment or 1, "entsize": entsize})
    except (UnicodeDecodeError, ValueError) as exc:
        errors.append({"level": "section-table", "block_index": len(blocks), "offset": 0, "message": str(exc)})
        bits = 0
    result: dict[str, Any] = {"format_id": f"elf{bits}-le" if bits else "elf", "valid": not errors, "block_count": len(blocks), "blocks": blocks, "errors": errors[:1], "warnings": []}
    if include_specs:
        result["specs"] = specs
    return result


def _elf_mutate(data: bytes, mutation: dict[str, Any]) -> ContainerResult:
    diagnosis = _elf_diagnose(data, include_specs=True)
    if not diagnosis["valid"]:
        raise ValueError(f"cannot mutate invalid ELF: {diagnosis['errors'][0]['message']}")
    specs = [dict(item) for item in diagnosis["specs"]]
    index = int(mutation.get("block_idx", -1))
    section_index = index - 1 if index > 0 else index
    if not 0 <= section_index < len(specs):
        raise IndexError("ELF block_idx must select a user section")
    field = str(mutation.get("field", ""))
    key = field.removeprefix("section.")
    if key not in {"name", "data", "type", "flags", "align"}:
        if key in {"offset", "size"}:
            raise ValueError(f"{field} is derived and recalculated by section layout")
        raise KeyError(f"ELF field is not structurally mutable: {field}")
    old = specs[section_index][key]
    specs[section_index][key] = _as_bytes(mutation.get("value")) if key == "data" else str(mutation.get("value")) if key == "name" else int(mutation.get("value"))
    new = specs[section_index][key]
    bits = 32 if diagnosis["format_id"] == "elf32-le" else 64
    rebuilt = _elf_build({"sections": specs}, bits=bits)
    rebuilt["changed_fields"] = [{"block_idx": index, "field": field, "old": old.hex().upper() if isinstance(old, bytes) else old, "new": new.hex().upper() if isinstance(new, bytes) else new, "offset_shift": 0}]
    return rebuilt


def _macho64_build(spec: dict[str, Any]) -> ContainerResult:
    sections = _sections_from_spec(spec, default_name="__data")
    if any(len(section["name"].encode("ascii")) > 16 for section in sections):
        raise ValueError("Mach-O section names must be ASCII and at most 16 bytes")
    command_size = 72 + 80 * len(sections)
    data_start = _align(32 + command_size, 8)
    payload = bytearray()
    layouts: list[tuple[dict[str, Any], int]] = []
    cursor = data_start
    for section in sections:
        alignment = int(section.get("align", 1))
        cursor = _align(cursor, alignment)
        if data_start + len(payload) < cursor:
            payload.extend(bytes(cursor - (data_start + len(payload))))
        layouts.append((section, cursor))
        payload.extend(section["data"])
        cursor += len(section["data"])
    segment_file_size = len(payload)
    cputype = int(spec.get("cputype", 0x0100000C))
    cpusubtype = int(spec.get("cpusubtype", 0))
    header = struct.pack("<IiiIIIII", 0xFEEDFACF, cputype, cpusubtype, 1, 1, command_size, int(spec.get("flags", 0)), 0)
    command = bytearray(struct.pack("<II16sQQQQiiII", 0x19, command_size, bytes(16), 0, segment_file_size, data_start, segment_file_size, 7, 7, len(sections), 0))
    for section, offset in layouts:
        alignment = int(section.get("align", 1))
        align_power = alignment.bit_length() - 1
        command.extend(
            struct.pack(
                "<16s16sQQIIIIIIII",
                section["name"].encode("ascii").ljust(16, b"\0"),
                b"__DATA".ljust(16, b"\0"),
                offset - data_start,
                len(section["data"]),
                offset,
                align_power,
                0,
                0,
                int(section.get("flags", 0)),
                0,
                0,
                0,
            )
        )
    output = bytearray(header + command)
    output.extend(bytes(data_start - len(output)))
    output.extend(payload)
    data = bytes(output)
    fields = [
        _semantic_field("header.magic", 0, 4, data, "uint32le", "enum", "MH_MAGIC_64"),
        _semantic_field("header.cputype", 4, 4, data, "int32le", "enum", "CPU type"),
        _semantic_field("header.filetype", 12, 4, data, "uint32le", "enum", "MH_OBJECT=1"),
        _semantic_field("header.ncmds", 16, 4, data, "uint32le", "length", "load command count", related=("load-commands",)),
        _semantic_field("header.sizeofcmds", 20, 4, data, "uint32le", "length", "load command byte length", related=("load-commands",)),
    ]
    maps = [_map("mach-header", 0, data[:32], fields, type="header", block_index=0)]
    maps.append(_map("LC_SEGMENT_64", 32, data[32 : 32 + command_size], [_semantic_field("segment.command", 32, command_size, data, f"bytes[{command_size}]", "payload", "segment command plus section_64 records", related=("header.sizeofcmds",))], type="load-command", block_index=1))
    for index, (section, offset) in enumerate(layouts, start=2):
        length = max(1, len(section["data"]))
        maps.append(_map(f"section:{section['name']}", offset, data[offset : offset + length], [_semantic_field("section.data", offset, length, data, f"bytes[{length}]", "payload", "Mach-O section contents", related=("section_64.offset", "section_64.size"))], type="section", block_index=index))
    validators = (
        ValidatorCommand("format-kb", ("container-diagnose", "macho64-le", "{file}")),
        ValidatorCommand("otool", ("-l", "{file}")),
    )
    result = _result("macho64-le", data, maps, validators)
    diagnosis = _macho64_diagnose(data, include_specs=False)
    if not diagnosis["valid"]:
        raise RuntimeError(f"internal Mach-O build validation failed: {diagnosis['errors']}")
    result["diagnosis"] = diagnosis
    return result


def _macho64_diagnose(data: bytes, *, include_specs: bool = False) -> dict[str, Any]:
    blocks: list[dict[str, Any]] = []
    specs: list[dict[str, Any]] = []
    errors: list[dict[str, Any]] = []
    try:
        if len(data) < 32 or data[:4] != b"\xcf\xfa\xed\xfe":
            raise ValueError("Mach-O 64 little-endian magic/header is missing")
        ncmds = int.from_bytes(data[16:20], "little")
        sizeofcmds = int.from_bytes(data[20:24], "little")
        if 32 + sizeofcmds > len(data):
            raise ValueError("Mach-O load command region exceeds file")
        blocks.append({"index": 0, "name": "mach-header", "type": "header", "offset": 0, "length": 32, "status": "ok"})
        position = 32
        for command_index in range(ncmds):
            if position + 8 > 32 + sizeofcmds:
                raise ValueError("truncated Mach-O load command")
            command, size = struct.unpack_from("<II", data, position)
            if size < 8 or size % 8 or position + size > 32 + sizeofcmds:
                raise ValueError("Mach-O load command size/alignment invalid")
            blocks.append({"index": len(blocks), "name": f"load-command-{command_index}", "type": command, "offset": position, "length": size, "status": "ok"})
            if command == 0x19:
                if size < 72:
                    raise ValueError("LC_SEGMENT_64 is truncated")
                nsects = int.from_bytes(data[position + 64 : position + 68], "little")
                if size != 72 + 80 * nsects:
                    raise ValueError("LC_SEGMENT_64 cmdsize does not match nsects")
                for index in range(nsects):
                    section_offset = position + 72 + index * 80
                    name = data[section_offset : section_offset + 16].split(b"\0", 1)[0].decode("ascii")
                    section_size = int.from_bytes(data[section_offset + 40 : section_offset + 48], "little")
                    file_offset = int.from_bytes(data[section_offset + 48 : section_offset + 52], "little")
                    align_power = int.from_bytes(data[section_offset + 52 : section_offset + 56], "little")
                    if align_power > 31 or file_offset + section_size > len(data):
                        raise ValueError(f"Mach-O section {name!r} range/alignment invalid")
                    payload = data[file_offset : file_offset + section_size]
                    specs.append({"name": name, "data": payload, "align": 1 << align_power, "flags": int.from_bytes(data[section_offset + 64 : section_offset + 68], "little")})
                    blocks.append({"index": len(blocks), "name": name, "type": "section", "offset": file_offset, "length": section_size, "status": "ok"})
            position += size
        if position != 32 + sizeofcmds:
            raise ValueError("Mach-O ncmds/sizeofcmds disagreement")
    except (UnicodeDecodeError, ValueError) as exc:
        errors.append({"level": "load-command", "block_index": len(blocks), "offset": 0, "message": str(exc)})
    result: dict[str, Any] = {"format_id": "macho64-le", "valid": not errors, "block_count": len(blocks), "blocks": blocks, "errors": errors[:1], "warnings": []}
    if include_specs:
        result["specs"] = specs
    return result


def _macho64_mutate(data: bytes, mutation: dict[str, Any]) -> ContainerResult:
    diagnosis = _macho64_diagnose(data, include_specs=True)
    if not diagnosis["valid"]:
        raise ValueError(f"cannot mutate invalid Mach-O: {diagnosis['errors'][0]['message']}")
    specs = [dict(item) for item in diagnosis["specs"]]
    block_index = int(mutation.get("block_idx", -1))
    section_index = block_index - 2 if block_index >= 2 else block_index
    if not 0 <= section_index < len(specs):
        raise IndexError("Mach-O block_idx must select a section")
    field = str(mutation.get("field", ""))
    key = field.removeprefix("section.")
    if key not in {"name", "data", "align", "flags"}:
        if key in {"offset", "size"}:
            raise ValueError(f"{field} is derived and recalculated by load-command layout")
        raise KeyError(f"Mach-O field is not structurally mutable: {field}")
    old = specs[section_index][key]
    specs[section_index][key] = _as_bytes(mutation.get("value")) if key == "data" else str(mutation.get("value")) if key == "name" else int(mutation.get("value"))
    new = specs[section_index][key]
    rebuilt = _macho64_build({"sections": specs})
    rebuilt["changed_fields"] = [{"block_idx": block_index, "field": field, "old": old.hex().upper() if isinstance(old, bytes) else old, "new": new.hex().upper() if isinstance(new, bytes) else new, "offset_shift": 0}]
    return rebuilt


SEVEN_Z_SIGNATURE = b"7z\xBC\xAF\x27\x1C"


def _sevenzip_executable() -> str:
    executable = shutil.which("7z") or shutil.which("7zz")
    if not executable:
        raise RuntimeError("7z/7zz is required for deterministic 7z container construction")
    return executable


def _sevenzip_build(spec: dict[str, Any]) -> ContainerResult:
    entries = _entries_from_spec(spec)
    executable = _sevenzip_executable()
    with tempfile.TemporaryDirectory(prefix="format-kb-7z-") as directory:
        root = Path(directory) / "input"
        root.mkdir()
        targets: list[str] = []
        for entry in sorted(entries, key=lambda item: item["name"]):
            target = root.joinpath(*PurePosixPath(entry["name"]).parts)
            if entry["is_dir"]:
                target.mkdir(parents=True, exist_ok=True)
            else:
                target.parent.mkdir(parents=True, exist_ok=True)
                target.write_bytes(entry["data"])
            os.chmod(target, 0o755 if entry["is_dir"] else 0o644)
            os.utime(target, (315532800, 315532800))
            targets.append(entry["name"].rstrip("/"))
        archive = Path(directory) / "output.7z"
        command = [
            executable,
            "a",
            "-t7z",
            "-mx=0",
            "-mmt=off",
            "-mtc=off",
            "-mtm=off",
            "-mta=off",
            "-bd",
            "-y",
            str(archive),
            *targets,
        ]
        completed = subprocess.run(command, cwd=root, capture_output=True, text=True, check=False, timeout=30)
        if completed.returncode != 0 or not archive.exists():
            raise RuntimeError(f"7z construction failed: {completed.stderr or completed.stdout}")
        data = archive.read_bytes()
    diagnosis = _sevenzip_diagnose(data, include_specs=False)
    if not diagnosis["valid"]:
        raise RuntimeError(f"internal 7z build validation failed: {diagnosis['errors']}")
    next_offset = int.from_bytes(data[12:20], "little")
    next_size = int.from_bytes(data[20:28], "little")
    next_start = 32 + next_offset
    fields = [
        _semantic_field("signature", 0, 6, data, "bytes[6]", "enum", "7z fixed signature"),
        _semantic_field("version", 6, 2, data, "uint8[2]", "enum", "7z major/minor version"),
        _semantic_field("start_header_crc32", 8, 4, data, "uint32le", "checksum", "CRC32 of next-header offset/size/CRC tuple", related=("next_header_offset", "next_header_size", "next_header_crc32")),
        _semantic_field("next_header_offset", 12, 8, data, "uint64le", "offset", "offset relative to byte 32", related=("next-header",)),
        _semantic_field("next_header_size", 20, 8, data, "uint64le", "length", "encoded next-header byte size", related=("next-header",)),
        _semantic_field("next_header_crc32", 28, 4, data, "uint32le", "checksum", "CRC32 of next header", related=("next-header",)),
    ]
    maps = [_map("signature-header", 0, data[:32], fields, type="header", block_index=0)]
    if next_start > 32:
        maps.append(_map("packed-streams", 32, data[32:next_start], [_semantic_field("packed_streams", 32, next_start - 32, data, f"bytes[{next_start - 32}]", "payload", "stored file data streams")], type="data", block_index=1))
    maps.append(_map("next-header", next_start, data[next_start : next_start + next_size], [_semantic_field("next_header", next_start, next_size, data, f"bytes[{next_size}]", "payload", "7z encoded header graph", related=("next_header_size", "next_header_crc32"))], type="header", block_index=2))
    validators = (
        ValidatorCommand("format-kb", ("container-diagnose", "7z", "{file}")),
        ValidatorCommand("7z", ("t", "-bd", "-y", "{file}")),
    )
    return _result("7z", data, maps, validators, diagnosis=diagnosis)


def _sevenzip_list(data: bytes, *, include_data: bool) -> list[dict[str, Any]]:
    executable = _sevenzip_executable()
    with tempfile.NamedTemporaryFile(suffix=".7z") as stream:
        stream.write(data)
        stream.flush()
        listed = subprocess.run([executable, "l", "-slt", "-bd", stream.name], capture_output=True, text=True, check=False, timeout=20)
        if listed.returncode != 0:
            raise ValueError("7z parser rejected archive")
        records: list[dict[str, str]] = []
        current: dict[str, str] = {}
        in_entries = False
        for line in listed.stdout.splitlines():
            if line.startswith("----------"):
                in_entries = True
                current = {}
                continue
            if not in_entries:
                continue
            if not line.strip():
                if current.get("Path"):
                    records.append(current)
                current = {}
                continue
            if " = " in line:
                key, value = line.split(" = ", 1)
                current[key] = value
        if current.get("Path"):
            records.append(current)
        result: list[dict[str, Any]] = []
        for record in records:
            name = _safe_name(record["Path"])
            is_dir = record.get("Folder") == "+" or record.get("Attributes", "").startswith("D")
            payload = b""
            if include_data and not is_dir:
                extracted = subprocess.run([executable, "x", "-so", "-bd", "-y", stream.name, name], capture_output=True, check=False, timeout=20)
                if extracted.returncode != 0:
                    raise ValueError(f"7z failed to extract {name!r} for structural mutation")
                payload = extracted.stdout
            result.append({"name": name + ("/" if is_dir and not name.endswith("/") else ""), "data": payload, "is_dir": is_dir})
        return result


def _sevenzip_diagnose(data: bytes, *, include_specs: bool = False) -> dict[str, Any]:
    errors: list[dict[str, Any]] = []
    warnings: list[dict[str, Any]] = []
    blocks: list[dict[str, Any]] = []
    specs: list[dict[str, Any]] = []
    try:
        if len(data) < 32 or data[:6] != SEVEN_Z_SIGNATURE:
            raise ValueError("7z signature/start header is missing")
        declared_start_crc = int.from_bytes(data[8:12], "little")
        actual_start_crc = binascii.crc32(data[12:32]) & 0xFFFFFFFF
        if declared_start_crc != actual_start_crc:
            raise ValueError(f"7z start header CRC32 mismatch: declared 0x{declared_start_crc:08X}, actual 0x{actual_start_crc:08X}")
        next_offset = int.from_bytes(data[12:20], "little")
        next_size = int.from_bytes(data[20:28], "little")
        next_crc = int.from_bytes(data[28:32], "little")
        start = 32 + next_offset
        end = start + next_size
        if start < 32 or end > len(data):
            raise ValueError("7z next header range exceeds file")
        if binascii.crc32(data[start:end]) & 0xFFFFFFFF != next_crc:
            raise ValueError("7z next header CRC32 mismatch")
        blocks.extend(
            [
                {"index": 0, "name": "signature-header", "type": "header", "offset": 0, "length": 32, "status": "ok"},
                {"index": 1, "name": "packed-streams", "type": "data", "offset": 32, "length": next_offset, "status": "ok"},
                {"index": 2, "name": "next-header", "type": "header", "offset": start, "length": next_size, "status": "ok"},
            ]
        )
        specs = _sevenzip_list(data, include_data=include_specs)
    except (OSError, RuntimeError, ValueError) as exc:
        errors.append({"level": "header", "block_index": len(blocks), "offset": 0, "message": str(exc)})
    result: dict[str, Any] = {"format_id": "7z", "valid": not errors, "block_count": len(blocks), "blocks": blocks, "entries": [{"name": item["name"], "is_dir": item["is_dir"], "size": len(item["data"]) if include_specs else None} for item in specs], "errors": errors[:1], "warnings": warnings}
    if include_specs:
        result["specs"] = specs
    return result


def _sevenzip_mutate(data: bytes, mutation: dict[str, Any]) -> ContainerResult:
    diagnosis = _sevenzip_diagnose(data, include_specs=True)
    if not diagnosis["valid"]:
        raise ValueError(f"cannot mutate invalid 7z: {diagnosis['errors'][0]['message']}")
    specs = [dict(item) for item in diagnosis["specs"]]
    index = int(mutation.get("block_idx", -1))
    if not 0 <= index < len(specs):
        raise IndexError("7z block_idx outside entry range")
    field = str(mutation.get("field", ""))
    if field in {"name", "entry.name"}:
        old = specs[index]["name"]
        specs[index]["name"] = _safe_name(mutation.get("value"))
        new = specs[index]["name"]
    elif field in {"data", "entry.data"} and not specs[index]["is_dir"]:
        old = specs[index]["data"]
        specs[index]["data"] = _as_bytes(mutation.get("value"))
        new = specs[index]["data"]
    elif field in {"next_header_offset", "next_header_size", "next_header_crc32"}:
        raise ValueError(f"{field} is derived and recalculated by 7z")
    else:
        raise KeyError(f"7z field is not structurally mutable: {field}")
    rebuilt = _sevenzip_build({"files": specs})
    rebuilt["changed_fields"] = [{"block_idx": index, "field": field, "old": old.hex().upper() if isinstance(old, bytes) else old, "new": new.hex().upper() if isinstance(new, bytes) else new, "offset_shift": 0}]
    return rebuilt


_BUILDERS: dict[str, Callable[[dict[str, Any]], ContainerResult]] = {
    "rar5": _rar5_build,
    "rar4": _rar4_build,
    "zip": _zip_build,
    "cpio-newc": _cpio_build,
    "unix-ar": _ar_build,
    "iso9660": _iso9660_build,
    "elf32-le": _elf32_build,
    "elf64-le": _elf64_build,
    "macho64-le": _macho64_build,
    "7z": _sevenzip_build,
}
_DIAGNOSTICS: dict[str, Callable[[bytes], dict[str, Any]]] = {
    "rar5": _rar5_diagnose,
    "rar4": _rar4_diagnose,
    "zip": _zip_diagnose,
    "cpio-newc": _cpio_diagnose,
    "unix-ar": _ar_diagnose,
    "iso9660": _iso9660_diagnose,
    "elf32-le": _elf_diagnose,
    "elf64-le": _elf_diagnose,
    "macho64-le": _macho64_diagnose,
    "7z": _sevenzip_diagnose,
}
_MUTATORS: dict[str, Callable[[bytes, dict[str, Any]], ContainerResult]] = {
    "rar5": _rar5_mutate,
    "rar4": _rar4_mutate,
    "zip": _zip_mutate,
    "cpio-newc": _cpio_mutate,
    "unix-ar": _ar_mutate,
    "iso9660": _iso9660_mutate,
    "elf32-le": _elf_mutate,
    "elf64-le": _elf_mutate,
    "macho64-le": _macho64_mutate,
    "7z": _sevenzip_mutate,
}

_CONTAINER_SCOPES: dict[str, dict[str, Any]] = {
    "rar5": {"scope": "stored files/directories + compressed entries (block-huffman stream, method 5 via built-in template or supplied raw block); RAR5 vint headers, header CRC32, extra areas preserved on mutate", "external_tool": "7z (optional)"},
    "rar4": {"scope": "stored files/directories; RAR4 main/file/end headers and header/file CRC32", "external_tool": "7z"},
    "zip": {"scope": "stored entries; local headers, central directory and EOCD with CRC32/offset rebuilding", "external_tool": "unzip and 7z"},
    "iso9660": {"scope": "one-level root files and empty directories; primary descriptor, path tables and extents", "external_tool": "7z"},
    "7z": {"scope": "stored files/directories; start/next-header CRC32 and archive rebuilding", "external_tool": "7z (required for build and mutation)"},
    "cpio-newc": {"scope": "newc files/directories; ASCII-hex headers, four-byte alignment and trailer", "external_tool": "bsdtar"},
    "unix-ar": {"scope": "regular members including BSD extended names; deterministic headers and padding", "external_tool": "ar"},
    "elf32-le": {"scope": "little-endian relocatable objects with user sections and generated shstrtab/section table", "external_tool": "objdump"},
    "elf64-le": {"scope": "little-endian relocatable objects with user sections and generated shstrtab/section table", "external_tool": "objdump"},
    "macho64-le": {"scope": "ARM64 little-endian MH_OBJECT with one LC_SEGMENT_64 and generated section_64 layout", "external_tool": "otool"},
}


def _container_id(format_id: str) -> str:
    normalized = format_id.lower().strip().lstrip(".")
    return {"ar": "unix-ar", "cpio": "cpio-newc", "elf": "elf64-le", "macho": "macho64-le", "iso": "iso9660"}.get(normalized, normalized)


def container_capabilities(format_id: str | None = None) -> dict[str, Any] | list[dict[str, Any]]:
    """Return machine-readable support and honest subset boundaries for variable-layout formats."""

    def one(normalized: str) -> dict[str, Any]:
        metadata = _CONTAINER_SCOPES[normalized]
        return {
            "format_id": normalized,
            "build": normalized in _BUILDERS,
            "mutate": normalized in _MUTATORS,
            "diagnose": normalized in _DIAGNOSTICS,
            "sample": normalized in _BUILDERS,
            "deterministic": True,
            **metadata,
        }

    if format_id is not None:
        normalized = _container_id(format_id)
        if normalized not in _CONTAINER_SCOPES:
            raise KeyError(f"container capability is not implemented for {format_id!r}")
        return one(normalized)
    return [one(normalized) for normalized in _CONTAINER_SCOPES]


def build_container(format_id: str, spec: dict[str, Any] | None = None) -> ContainerResult:
    normalized = _container_id(format_id)
    try:
        builder = _BUILDERS[normalized]
    except KeyError as exc:
        raise KeyError(f"container builder is not implemented for {format_id!r}") from exc
    return builder(dict(spec or {}))


def diagnose_container(file_bytes: bytes | bytearray | memoryview, format_id: str) -> dict[str, Any]:
    normalized = _container_id(format_id)
    try:
        diagnose = _DIAGNOSTICS[normalized]
    except KeyError as exc:
        raise KeyError(f"container diagnosis is not implemented for {format_id!r}") from exc
    return diagnose(bytes(file_bytes))


def mutate_field(file_bytes: bytes | bytearray | memoryview, format_id: str, mutation: dict[str, Any]) -> ContainerResult:
    normalized = _container_id(format_id)
    try:
        mutate = _MUTATORS[normalized]
    except KeyError as exc:
        raise KeyError(f"structure-aware mutation is not implemented for {format_id!r}") from exc
    return mutate(bytes(file_bytes), dict(mutation))


def _ttf_sample(options: dict[str, Any]) -> ContainerResult:
    try:
        from fontTools.fontBuilder import FontBuilder
        from fontTools.pens.ttGlyphPen import TTGlyphPen
        from fontTools.ttLib import TTFont
    except ImportError as exc:
        raise RuntimeError("fonttools>=4.62 is required for parameterized TTF samples") from exc

    glyph_count = int(options.get("glyphs", 4))
    if not 1 <= glyph_count <= 256:
        raise ValueError("TTF sample glyphs must be between 1 and 256")
    glyph_order = [".notdef"] + [f"glyph{index}" for index in range(1, glyph_count)]
    metrics = {name: (500, 0) for name in glyph_order}
    cmap = {31 + index: name for index, name in enumerate(glyph_order[1:], start=1)}
    glyphs: dict[str, Any] = {}
    for index, name in enumerate(glyph_order):
        pen = TTGlyphPen(None)
        if index:
            inset = 40 + index % 40
            pen.moveTo((inset, 0))
            pen.lineTo((460 - inset, 0))
            pen.lineTo((460 - inset, 600))
            pen.lineTo((inset, 600))
            pen.closePath()
        glyphs[name] = pen.glyph()
    names = {
        "familyName": "FormatKB Sample",
        "styleName": "Regular",
        "uniqueFontIdentifier": f"FormatKB Sample {glyph_count}",
        "fullName": "FormatKB Sample Regular",
        "psName": "FormatKB-Sample-Regular",
        "version": "Version 1.0",
    }
    builder = FontBuilder(1000, isTTF=True)
    builder.setupGlyphOrder(glyph_order)
    builder.setupCharacterMap(cmap)
    builder.setupGlyf(glyphs)
    builder.setupHorizontalMetrics(metrics)
    builder.setupHorizontalHeader(ascent=800, descent=-200)
    builder.setupOS2(sTypoAscender=800, sTypoDescender=-200, usWinAscent=800, usWinDescent=200)
    builder.setupNameTable(names)
    builder.setupPost()
    builder.setupMaxp()
    builder.font.recalcTimestamp = False
    builder.font["head"].created = 2082844800
    builder.font["head"].modified = 2082844800
    output = io.BytesIO()
    builder.font.save(output, reorderTables=True)
    data = output.getvalue()
    requested = set(options.get("tables", []))
    available = {data[12 + index * 16 : 16 + index * 16].decode("ascii") for index in range(int.from_bytes(data[4:6], "big"))}
    if not requested <= available:
        raise ValueError(f"requested TTF tables are not generated: {sorted(requested - available)}")
    # Re-open through FontTools as the construction-time parser check.
    parsed = TTFont(io.BytesIO(data), lazy=False)
    parsed.getGlyphOrder()
    maps: list[dict[str, Any]] = []
    header_fields = [
        _semantic_field("header.sfnt_version", 0, 4, data, "uint32be", "enum", "TrueType sfnt version 1.0"),
        _semantic_field("header.num_tables", 4, 2, data, "uint16be", "length", "table directory record count", related=("table-directory",)),
        _semantic_field("header.search_parameters", 6, 6, data, "uint16be[3]", "integer", "searchRange/entrySelector/rangeShift derived from numTables", related=("header.num_tables",)),
    ]
    maps.append(_map("sfnt-header", 0, data[:12], header_fields, type="header", block_index=0))
    table_count = int.from_bytes(data[4:6], "big")
    directory_fields: list[TemplateFieldOffset] = []
    for index in range(table_count):
        record_offset = 12 + index * 16
        tag = data[record_offset : record_offset + 4].decode("ascii")
        table_offset = int.from_bytes(data[record_offset + 8 : record_offset + 12], "big")
        table_length = int.from_bytes(data[record_offset + 12 : record_offset + 16], "big")
        directory_fields.extend(
            [
                _semantic_field(f"table[{tag}].tag", record_offset, 4, data, "ascii[4]", "enum", "sfnt table tag"),
                _semantic_field(f"table[{tag}].checksum", record_offset + 4, 4, data, "uint32be", "checksum", "sum of padded big-endian table words", related=(f"table[{tag}].data",)),
                _semantic_field(f"table[{tag}].offset", record_offset + 8, 4, data, "uint32be", "offset", "absolute table offset", related=(f"table[{tag}].data",)),
                _semantic_field(f"table[{tag}].length", record_offset + 12, 4, data, "uint32be", "length", "unpadded table length", related=(f"table[{tag}].data",)),
            ]
        )
        maps.append(_map(f"table:{tag}", table_offset, data[table_offset : table_offset + max(1, table_length)], [_semantic_field(f"table[{tag}].data", table_offset, max(1, table_length), data, f"bytes[{max(1, table_length)}]", "payload", "sfnt table payload", related=(f"table[{tag}].checksum", f"table[{tag}].length"))], type="table", block_index=index + 1))
    maps.insert(1, _map("table-directory", 12, data[12 : 12 + table_count * 16], directory_fields, type="directory"))
    validators = (
        ValidatorCommand("format-kb", ("validate", "ttf", "{file}")),
        ValidatorCommand("ttx", ("-l", "{file}")),
    )
    diagnosis = {"format_id": "ttf", "valid": True, "block_count": len(maps), "blocks": [{"index": index, "name": item["name"], "type": item["type"], "offset": item["offset"], "length": item["length"], "status": "ok"} for index, item in enumerate(maps)], "errors": [], "warnings": []}
    return _result("ttf", data, maps, validators, diagnosis=diagnosis, description=f"Deterministic TrueType font with {glyph_count} glyphs and {table_count} tables ({', '.join(sorted(available))}); table checksums and head.checkSumAdjustment are generated by FontTools.")


def sample(format_id: str, options: dict[str, Any] | None = None) -> ContainerResult:
    normalized = _container_id(format_id)
    options = dict(options or {})
    if normalized == "rar5":
        file_count = int(options.get("files", 2))
        if not 0 <= file_count <= 64:
            raise ValueError("sample files must be between 0 and 64")
        blocks: list[dict[str, Any]] = [{"type": "main", "flags": 0}]
        descriptions: list[str] = []
        if options.get("include_dir", True):
            blocks.append({"type": "file", "name": "docs", "flags": 1, "host_os": 0})
            descriptions.append("1 directory entry 'docs'")
        for index in range(file_count):
            name = f"docs/sample-{index + 1}.txt" if options.get("include_dir", True) else f"sample-{index + 1}.txt"
            payload = f"format-kb sample {index + 1}\n".encode()
            blocks.append({"type": "file", "name": name, "host_os": 0, "data": payload})
        descriptions.append(f"{file_count} stored file entries with deterministic UTF-8 payloads")
        result = _rar5_build({"blocks": blocks})
        result["description"] = "RAR5 archive containing " + " and ".join(descriptions) + "; every header and file CRC32 is generated."
        return result
    if normalized in {"rar4", "zip", "7z", "cpio-newc"}:
        file_count = int(options.get("files", 2))
        if not 0 <= file_count <= 64:
            raise ValueError("sample files must be between 0 and 64")
        entries: list[dict[str, Any]] = []
        if options.get("include_dir", True):
            entries.append({"name": "docs/", "is_dir": True})
        for index in range(file_count):
            prefix = "docs/" if normalized != "iso9660" and options.get("include_dir", True) else ""
            entries.append({"name": f"{prefix}sample-{index + 1}.txt", "data": f"format-kb sample {index + 1}\n".encode()})
        result = build_container(normalized, {"files": entries})
        result["description"] = f"{normalized} container with {1 if options.get('include_dir', True) else 0} directory entry and {file_count} deterministic stored files; all sizes, offsets and checksums are generated."
        return result
    if normalized == "unix-ar":
        file_count = int(options.get("files", 2))
        entries = [{"name": f"sample-{index + 1}.txt", "data": f"format-kb ar sample {index + 1}\n".encode()} for index in range(file_count)]
        result = _ar_build({"files": entries})
        result["description"] = f"Unix ar archive with {file_count} deterministic members and automatically padded member boundaries."
        return result
    if normalized == "iso9660":
        requested = options.get("files")
        if isinstance(requested, list):
            entries = [{"name": name, "is_dir": str(name).endswith("/"), "data": b"" if str(name).endswith("/") else f"ISO sample for {name}\n".encode()} for name in requested]
        else:
            entries = [{"name": "A.TXT", "data": b"format-kb ISO sample\n"}, {"name": "B/", "is_dir": True}]
        label_source = options.get("label", options.get("labels", ["FORMAT_KB"])[0] if options.get("labels") else "FORMAT_KB")
        result = _iso9660_build({"files": entries, "label": label_source})
        result["description"] = f"ISO9660 image labeled {label_source!r} with {sum(not item.get('is_dir', False) for item in entries)} root files and {sum(item.get('is_dir', False) for item in entries)} one-level directories; descriptor, path tables and extents are laid out automatically."
        return result
    if normalized in {"elf32-le", "elf64-le"}:
        sections = options.get("sections") or [
            {"name": ".data", "data": b"\x00\x01\x02\x03", "align": 4},
            {"name": ".note.format_kb", "data": b"format-kb\0", "align": 1},
        ]
        result = _elf_build({"sections": sections}, bits=32 if normalized == "elf32-le" else 64)
        result["description"] = f"Relocatable {normalized} object with {len(sections)} user sections plus an automatically generated .shstrtab and section-header table."
        return result
    if normalized == "macho64-le":
        sections = options.get("sections") or [
            {"name": "__data", "data": b"\x00\x01\x02\x03", "align": 4},
            {"name": "__note", "data": b"format-kb\0", "align": 1},
        ]
        result = _macho64_build({"sections": sections})
        result["description"] = f"ARM64 MH_OBJECT with one LC_SEGMENT_64 command and {len(sections)} automatically laid-out section_64 records."
        return result
    if normalized == "ttf":
        return _ttf_sample(options)
    raise KeyError(f"sample generator is not implemented for {format_id!r}")
