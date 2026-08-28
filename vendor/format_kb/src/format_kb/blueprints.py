from __future__ import annotations

import binascii
import base64
import bz2
import gzip
import hashlib
import io
import lzma
import struct
import zipfile
import zlib

from .catalog import FORMATS, get_format
from .models import DependencyGuide, FieldGuide, FormatBlueprint, FormatSpec, MinimalTemplate, TemplateFieldOffset, ValidatorCommand
from .risk_profiles import mapped_format_ids, warnings_for


def _f(path: str, type_: str, default: str, constraints: str, purpose: str) -> FieldGuide:
    return FieldGuide(path, type_, default, constraints, purpose)


def _d(derived: str, expression: str, inputs: str, update: str) -> DependencyGuide:
    return DependencyGuide(derived, expression, tuple(inputs.split()), update)


def _magic_fields(spec: FormatSpec) -> list[FieldGuide]:
    if not spec.magic:
        return []
    rule = spec.magic[0]
    result: list[FieldGuide] = []
    for index, clause in enumerate(rule.clauses):
        mask = f" under mask {clause.mask.hex().upper()}" if clause.mask else ""
        result.append(
            _f(
                f"header.magic[{index}]@{clause.offset}",
                f"bytes[{len(clause.value)}]",
                clause.value.hex().upper(),
                f"must equal this value{mask}",
                f"Selects {spec.id}; do not silently repair an unknown signature.",
            )
        )
    return result


def _sqlite_fields() -> list[FieldGuide]:
    return [
        _f("header.magic@0", "bytes[16]", "53514C69746520666F726D6174203300", "exact", "SQLite 3 signature."),
        _f("header.page_size@16", "u16be", "512", "power of two 512..32768; encoded 1 means 65536", "Size of every database page."),
        _f("header.write_version@18", "u8", "1", "1=rollback, 2=WAL", "Writer journal mode compatibility."),
        _f("header.read_version@19", "u8", "1", "1 or 2", "Reader format compatibility."),
        _f("header.reserved_bytes@20", "u8", "0", "page_size-reserved_bytes >= 480", "Tail bytes reserved on every page."),
        _f("header.payload_fractions@21", "u8[3]", "64,32,32", "must be exactly 64,32,32", "B-tree local/overflow payload split constants."),
        _f("header.change_counter@24", "u32be", "1", "transaction-maintained", "Invalidates stale page caches."),
        _f("header.page_count@28", "u32be", "1", "must agree with file size when validity counters match", "Declared database size."),
        _f("header.freelist_trunk@32", "u32be", "0", "0 or page number <= page_count", "First freelist trunk."),
        _f("header.freelist_count@36", "u32be", "0", "<= page_count", "Number of freelist pages."),
        _f("header.schema_cookie@40", "u32be", "0", "increment after schema change", "Prepared-statement schema generation."),
        _f("header.schema_format@44", "u32be", "0", "0 for empty DB, otherwise 1..4", "Schema record semantics."),
        _f("header.text_encoding@56", "u32be", "1", "1=UTF-8, 2=UTF-16LE, 3=UTF-16BE", "Encoding of database text."),
        _f("header.incremental_vacuum@64", "u32be", "0", "must be 0 when largest_root_page@52 is 0", "Pointer-map/vacuum mode."),
        _f("header.reserved@72", "bytes[20]", "00*20", "must be zero", "Future expansion."),
        _f("header.version_valid_for@92", "u32be", "1", "equals change_counter when page_count is authoritative", "Validates page_count and writer version."),
        _f("page1.btree.type@100", "u8", "0x0D", "0x02/05/0A/0D; page 1 is table b-tree", "Leaf table b-tree for sqlite_schema."),
        _f("page1.btree.cell_count@103", "u16be", "0", "cell pointer array and cells must fit usable page", "Number of schema rows."),
        _f("page1.btree.cell_content_start@105", "u16be", "512", "within usable page; zero encodes 65536", "Start of packed cell area."),
    ]


def _fields_for(spec: FormatSpec) -> tuple[FieldGuide, ...]:
    if spec.id == "sqlite3":
        return tuple(_sqlite_fields())

    fields = _magic_fields(spec)
    if spec.id == "png":
        fields += [
            _f("IHDR.length", "u32be", "13", "must be 13", "IHDR payload length."),
            _f("IHDR.width", "u32be", "1", "1..2^31-1", "Pixel width."),
            _f("IHDR.height", "u32be", "1", "1..2^31-1", "Pixel height."),
            _f("IHDR.bit_depth", "u8", "8", "legal set depends on color_type", "Bits per sample/index."),
            _f("IHDR.color_type", "u8", "6", "0,2,3,4,6", "RGBA for the supplied template."),
            _f("IHDR.compression/filter/interlace", "u8[3]", "0,0,0", "defined methods only", "Codec and pass selection."),
            _f("chunk.length", "u32be", "derived", "<= 2^31-1 and remaining bytes", "Length of each chunk payload."),
            _f("chunk.crc", "u32be", "derived", "CRC-32(type||data)", "Protects chunk type and data."),
        ]
    elif spec.id == "jpeg":
        fields += [
            _f("SOF.precision", "u8", "8", "normally 8 or 12", "Sample precision."),
            _f("SOF.height", "u16be", "1", "1..65535; DNL rules if zero", "Image height."),
            _f("SOF.width", "u16be", "1", "1..65535", "Image width."),
            _f("SOF.components", "u8", "1", "must match component descriptors", "Component count."),
            _f("segment.length", "u16be", "derived", "includes its two length bytes and stays in file", "Bounds each marker segment."),
            _f("SOS.entropy_data", "bytes", "codec-produced", "byte-stuffed FF00; ends at a marker", "Compressed scan."),
        ]
    elif spec.id in {"gif87a", "gif89a"}:
        fields += [
            _f("logical_screen.width", "u16le", "1", "1..65535", "Canvas width."),
            _f("logical_screen.height", "u16le", "1", "1..65535", "Canvas height."),
            _f("logical_screen.packed", "u8", "0x80", "table flag and size bits must agree", "Declares global color table."),
            _f("image.width/height", "u16le[2]", "1,1", "rectangle inside declared canvas", "Frame dimensions."),
            _f("image.lzw_min_code_size", "u8", "2", "2..8 for normal images", "Initial LZW dictionary width."),
            _f("sub_block.length", "u8", "derived", "0..255; zero terminates chain", "Bounds extension/image chunks."),
        ]
    elif spec.id in {"tiff-le", "tiff-be"}:
        fields += [
            _f("header.first_ifd_offset", "u32", "8", "aligned and inside file", "Locates first directory."),
            _f("ifd.entry_count", "u16", "required tags only", "12*count+6 bytes fit", "Controls directory allocation."),
            _f("tag.ImageWidth", "SHORT/LONG", "1", ">0", "Pixel width."),
            _f("tag.ImageLength", "SHORT/LONG", "1", ">0", "Pixel height."),
            _f("tag.StripOffsets", "SHORT/LONG[]", "derived", "every strip range inside file", "Pixel data locations."),
            _f("tag.StripByteCounts", "SHORT/LONG[]", "derived", "same count as StripOffsets", "Pixel strip lengths."),
        ]
    elif spec.id in {"wav", "avi", "webp"}:
        subtype = {"wav": "WAVE", "avi": "AVI ", "webp": "WEBP"}[spec.id]
        fields += [
            _f("RIFF.size@4", "u32le", "file_size-8", "<= file_size-8", "Bounds the RIFF form."),
            _f("RIFF.form_type@8", "FourCC", subtype, "exact for this format", "Selects the RIFF dialect."),
            _f("chunk.size", "u32le", "derived", "payload fits; odd payload has one pad byte", "Bounds each chunk."),
        ]
    elif spec.id in {"mp4", "quicktime", "m4a", "3gp", "avif", "heif"}:
        fields += [
            _f("box.size", "u32be/u64be", "derived", "0=to EOF; 1 means following u64; >= header", "Bounds every ISO BMFF box."),
            _f("ftyp.major_brand", "FourCC", spec.extensions[0][:4].ljust(4), "registered/compatible brand", "Declares container dialect."),
            _f("ftyp.minor_version", "u32be", "0", "brand-defined", "Brand version."),
            _f("ftyp.compatible_brands", "FourCC[]", "major brand", "payload multiple of 4", "Decoder compatibility set."),
            _f("media.sample_size/offset", "u32/u64", "derived", "sample ranges lie in mdat/idat", "Locates encoded media/items."),
        ]
    elif spec.id in {"zip", "epub", "docx", "xlsx", "pptx"}:
        fields += [
            _f("local.name_length", "u16le", "0", "name bytes fit local record", "Entry name length."),
            _f("local.extra_length", "u16le", "0", "extra TLVs fit", "Local metadata length."),
            _f("local.compressed_size", "u32le/ZIP64", "0", "data range inside file", "Compressed allocation bound."),
            _f("local.uncompressed_size", "u32le/ZIP64", "0", "apply configured decoded-size limit", "Expected decoded bytes."),
            _f("local.crc32", "u32le", "0", "CRC-32 of uncompressed data", "Entry integrity."),
            _f("EOCD.entry_count/central_size/offset", "u16/u32le", "0,0,0", "central directory and counts agree", "Archive index."),
        ]
    elif spec.id in {"rar4", "rar5", "7z", "gzip", "bzip2", "xz", "zstd", "lz4-frame"}:
        fields += [
            _f("block.compressed_size", "format integer", "0", "<= remaining input", "Compressed block boundary."),
            _f("block.uncompressed_size", "format integer", "0", "<= caller output budget", "Decoder allocation/limit."),
            _f("block.checksum", "CRC/hash", "derived", "algorithm and covered range are format-defined", "Corruption detection."),
            _f("block.flags", "bitfield", "0", "reject reserved/unsupported bits", "Selects optional fields and algorithms."),
        ]
    elif spec.id.startswith("elf"):
        word = "u32" if "32" in spec.id else "u64"
        endian = "le" if spec.id.endswith("le") else "be"
        fields += [
            _f("e_type", "u16", "ET_REL(1)", "known ELF object type", "Object/linkage semantics."),
            _f("e_machine", "u16", "0", "target ABI value", "Instruction set; zero only for neutral skeleton."),
            _f("e_entry", f"{word}{endian}", "0", "must point into executable mapped segment if nonzero", "Entry point."),
            _f("e_phoff/e_phnum/e_phentsize", "offset/count/size", "0,0,ABI-size", "checked table multiplication and range", "Program header table."),
            _f("e_shoff/e_shnum/e_shentsize", "offset/count/size", "0,0,ABI-size", "checked table multiplication and range", "Section header table."),
        ]
    elif spec.id in {"pe32", "pe32plus"}:
        fields += [
            _f("DOS.e_lfanew@0x3C", "u32le", "0x80", "PE signature and headers fit at offset", "Locates NT headers."),
            _f("COFF.NumberOfSections", "u16le", "0", "count*40 fits before first section", "Section table length."),
            _f("COFF.SizeOfOptionalHeader", "u16le", "224/240", "fits file and matches variant", "Bounds optional header."),
            _f("Optional.SizeOfImage", "u32le", "derived", "section-aligned max virtual end", "Loader reservation size."),
            _f("Optional.SizeOfHeaders", "u32le", "derived", "file-aligned header end", "First raw section boundary."),
            _f("Section.VirtualSize/RawSize/RawOffset", "u32le", "derived", "checked virtual and file ranges", "Mapped and on-disk section bounds."),
        ]
    elif spec.id in {"pcap-le", "pcap-be", "pcapng"}:
        fields += [
            _f("capture.snaplen", "u32", "65535", "1..configured maximum", "Maximum captured packet bytes."),
            _f("packet.captured_length", "u32", "0", "<= original_length, snaplen and remaining block", "Stored packet allocation/copy size."),
            _f("packet.original_length", "u32", "0", "semantic wire length; do not allocate from it", "Original packet length."),
            _f("packet.timestamp", "u32/u64", "0", "resolution/interface-defined", "Capture time."),
        ]
    elif spec.category == "image":
        fields += [
            _f("image.width", "format integer", "1", ">0 and <= application limit", "Decoded canvas width."),
            _f("image.height", "format integer", "1", ">0 and <= application limit", "Decoded canvas height."),
            _f("image.channels", "enum/count", "3", "format-defined", "Samples per pixel."),
            _f("image.bit_depth", "enum/count", "8", "format-defined", "Bits per sample."),
            _f("block.encoded_length", "format integer", "0", "<= remaining input", "Compressed/pixel block boundary."),
        ]
    elif spec.category == "audio":
        fields += [
            _f("stream.channels", "format integer", "1", "1..application limit", "Channel count."),
            _f("stream.sample_rate", "format integer", "8000", ">0 and codec-defined", "Samples per second."),
            _f("stream.bits_per_sample", "format integer", "16", "codec-defined", "PCM/sample precision."),
            _f("frame.sample_count", "format integer", "0", "decoded budget", "Samples represented by a frame/block."),
            _f("frame.encoded_length", "format integer", "0", "<= remaining input", "Frame boundary."),
        ]
    elif spec.category == "video":
        fields += [
            _f("stream.timebase_num", "format integer", "1", ">0", "Timestamp numerator."),
            _f("stream.timebase_den", "format integer", "1000", ">0", "Timestamp denominator."),
            _f("frame.width/height", "format integer[2]", "1,1", "positive and within decoder limit", "Frame dimensions."),
            _f("frame.encoded_length", "format integer", "0", "<= remaining input", "Packet/frame boundary."),
            _f("stream.frame_count", "format integer", "0", "consistent with available records or unknown sentinel", "Index/iteration bound."),
        ]
    elif spec.category == "archive":
        fields += [
            _f("archive.entry_count", "format integer", "0", "<= metadata and policy limit", "Directory iteration bound."),
            _f("entry.name_length", "format integer", "0", "<= entry header and name policy", "Entry path bytes."),
            _f("entry.data_offset", "format offset", "derived", "inside file", "Entry payload location."),
            _f("entry.compressed_size", "format integer", "0", "<= remaining input", "Compressed input boundary."),
            _f("entry.uncompressed_size", "format integer", "0", "<= extraction budget", "Expected output size."),
        ]
    elif spec.category == "executable":
        fields += [
            _f("header.entry_point", "address/offset", "0", "inside executable mapped region or zero", "Initial code address."),
            _f("header.section_count", "format integer", "0", "table multiplication fits and count is bounded", "Section iteration bound."),
            _f("section.file_offset", "format offset", "0", "inside file", "Raw section location."),
            _f("section.file_size", "format integer", "0", "offset+size inside file", "Raw section length."),
            _f("section.memory_size", "format integer", "0", "bounded mapping size", "Loader allocation size."),
        ]
    elif spec.category == "font":
        fields += [
            _f("header.num_tables", "u16be", "0", "num_tables*record_size fits", "Table directory count."),
            _f("table.offset", "u32be", "derived", "4-byte aligned and inside file", "Table location."),
            _f("table.length", "u32be", "derived", "offset+length inside file", "Table boundary."),
            _f("head.unitsPerEm", "u16be", "1000", "16..16384", "Font design grid."),
            _f("maxp.numGlyphs", "u16be", "1", "agrees with loca/glyf and dependent tables", "Glyph iteration bound."),
        ]
    else:
        fields += [
            _f("record.count", "format integer", "0", "bounded by available bytes and policy", "Iteration/allocation count."),
            _f("record.length", "format integer", "0", "<= remaining input", "Record boundary."),
            _f("record.offset", "format offset", "0", "inside file before pointer arithmetic", "Record location."),
            _f("text.encoding", "enum", "UTF-8", "format-defined", "String decoding."),
        ]
    return tuple(fields)


def _dependencies_for(spec: FormatSpec) -> tuple[DependencyGuide, ...]:
    if spec.id == "sqlite3":
        return (
            _d("file.byte_length", "page_size * page_count", "header.page_size@16 header.page_count@28", "Use checked multiplication; changing either requires resizing by whole pages."),
            _d("page.usable_size", "page_size - reserved_bytes", "header.page_size@16 header.reserved_bytes@20", "Revalidate every cell/freeblock/overflow threshold."),
            _d("header.page_count.authoritative", "change_counter == version_valid_for", "header.change_counter@24 header.version_valid_for@92", "Update both counters atomically when publishing page_count."),
            _d("page1.cell_pointer_end", "108 + 2*cell_count", "page1.btree.cell_count@103", "Must not cross cell_content_start."),
            _d("freelist.valid", "freelist_trunk==0 iff freelist_count==0", "header.freelist_trunk@32 header.freelist_count@36", "Rebuild both values with the freelist chain."),
        )
    if spec.id == "png":
        return (
            _d("row_bytes", "ceil(width * channels(color_type) * bit_depth / 8)", "IHDR.width IHDR.bit_depth IHDR.color_type", "Use checked arithmetic before allocating scanlines."),
            _d("inflated_bytes", "height * (1 + row_bytes), adjusted for Adam7", "IHDR.height row_bytes IHDR.interlace", "Changing geometry requires regenerating filtered IDAT data."),
            _d("chunk.crc", "CRC32(chunk.type || chunk.data)", "chunk.type chunk.data", "Recompute after any type/data edit."),
            _d("chunk.length", "len(chunk.data)", "chunk.data", "Write before data and reject mismatches."),
        )
    if spec.id in {"zip", "epub", "docx", "xlsx", "pptx"}:
        return (
            _d("local.crc32", "CRC32(uncompressed_data)", "entry.uncompressed_data", "Recompute after payload changes unless data-descriptor semantics are used."),
            _d("local.compressed_size", "len(compressed_data)", "entry.compressed_data", "Update local/descriptor and central copies."),
            _d("central.local_offset", "byte offset of corresponding local header", "preceding.records", "Rebuild after any earlier record changes."),
            _d("EOCD.central_size/offset", "serialized central directory range", "central.records", "Recompute archive tail and ZIP64 records when needed."),
        )
    if spec.category == "image":
        return (
            _d("decoded_row_bytes", "ceil(width * channels * bit_depth / 8)", "image.width image.channels image.bit_depth", "Use checked arithmetic and codec-specific packing."),
            _d("decoded_buffer_bytes", "decoded_row_bytes * height", "decoded_row_bytes image.height", "Reject values above a configured memory budget."),
            _d("block.end", "block.offset + block.encoded_length", "block.offset block.encoded_length", "Check without unsigned wrap before reading/copying."),
        )
    if spec.category == "audio":
        return (
            _d("decoded_pcm_bytes", "sample_count * channels * ceil(bits_per_sample/8)", "frame.sample_count stream.channels stream.bits_per_sample", "Checked multiplication before allocation."),
            _d("duration_seconds", "total_samples / sample_rate", "stream.total_samples stream.sample_rate", "Reject zero rate; preserve declared sentinel values."),
            _d("frame.end", "frame.offset + frame.encoded_length", "frame.offset frame.encoded_length", "Validate before parsing frame payload."),
        )
    if spec.category == "video":
        return (
            _d("timestamp_seconds", "timestamp * timebase_num / timebase_den", "frame.timestamp stream.timebase_num stream.timebase_den", "Check zero denominator and integer overflow."),
            _d("frame_buffer_bytes", "stride(width,format) * height", "frame.width frame.height frame.pixel_format", "Use codec/pixel-format limits before allocation."),
            _d("frame.end", "frame.offset + frame.encoded_length", "frame.offset frame.encoded_length", "Validate range before demux/decode."),
        )
    if spec.category == "archive":
        return (
            _d("entry.end", "data_offset + compressed_size", "entry.data_offset entry.compressed_size", "Check against file length without wrap."),
            _d("total_output", "sum(each uncompressed_size)", "archive.entry_count entry.uncompressed_size", "Enforce per-entry and total extraction budgets."),
            _d("integrity", "format checksum over specified header/data range", "entry.header entry.data", "Recompute every affected checksum after edits."),
        )
    if spec.category == "executable":
        return (
            _d("section.file_end", "file_offset + file_size", "section.file_offset section.file_size", "Checked addition; require <= file length."),
            _d("section.memory_end", "virtual_address + memory_size", "section.virtual_address section.memory_size", "Checked address arithmetic and non-overlap policy."),
            _d("table.byte_length", "section_count * entry_size", "header.section_count header.entry_size", "Checked multiplication before table parsing."),
        )
    if spec.category == "font":
        return (
            _d("table.end", "table.offset + table.length", "table.offset table.length", "Checked addition and file bound."),
            _d("directory.search_fields", "largest power-of-two formulas from num_tables", "header.num_tables", "Recompute searchRange, entrySelector and rangeShift."),
            _d("font.checksum", "sum u32be words with head.checkSumAdjustment treated specially", "all.tables", "Recompute table checksums and whole-font adjustment."),
        )
    if spec.category == "network":
        return (
            _d("packet.end", "packet_data_offset + captured_length", "packet.data_offset packet.captured_length", "Require block/file bound before protocol parsing."),
            _d("timestamp", "ticks * interface_resolution", "packet.timestamp interface.tsresol", "Use bounded integer/rational conversion."),
            _d("block.end", "block.offset + block.total_length", "block.offset block.total_length", "Check duplicate trailing length where applicable."),
        )
    return (
        _d("record.end", "record.offset + record.length", "record.offset record.length", "Checked addition before slicing or memcpy."),
        _d("table.byte_length", "record.count * record.entry_size", "record.count record.entry_size", "Checked multiplication and configured count limit."),
    )


def _chunk(kind: bytes, data: bytes) -> bytes:
    return struct.pack(">I", len(data)) + kind + data + struct.pack(">I", binascii.crc32(kind + data) & 0xFFFFFFFF)


def _png_template() -> bytes:
    ihdr = struct.pack(">IIBBBBB", 1, 1, 8, 6, 0, 0, 0)
    raw_scanline = b"\x00\x00\x00\x00\x00"
    return b"\x89PNG\r\n\x1a\n" + _chunk(b"IHDR", ihdr) + _chunk(b"IDAT", zlib.compress(raw_scanline)) + _chunk(b"IEND", b"")


def _sqlite_template() -> bytes:
    page = bytearray(512)
    page[:16] = b"SQLite format 3\x00"
    page[16:18] = struct.pack(">H", 512)
    page[18:24] = bytes((1, 1, 0, 64, 32, 32))
    page[24:28] = struct.pack(">I", 1)
    page[28:32] = struct.pack(">I", 1)
    page[44:48] = struct.pack(">I", 0)
    page[56:60] = struct.pack(">I", 1)
    page[92:96] = struct.pack(">I", 1)
    page[96:100] = struct.pack(">I", 3_046_000)
    page[100] = 0x0D
    page[105:107] = struct.pack(">H", 512)
    return bytes(page)


def _pdf_template() -> bytes:
    header = b"%PDF-1.4\n"
    objects = [
        b"1 0 obj\n<< /Type /Catalog /Pages 2 0 R >>\nendobj\n",
        b"2 0 obj\n<< /Type /Pages /Kids [3 0 R] /Count 1 >>\nendobj\n",
        b"3 0 obj\n<< /Type /Page /Parent 2 0 R /MediaBox [0 0 1 1] /Resources <<>> /Contents 4 0 R >>\nendobj\n",
        b"4 0 obj\n<< /Length 0 >>\nstream\n\nendstream\nendobj\n",
    ]
    body = bytearray(header)
    offsets = [0]
    for item in objects:
        offsets.append(len(body))
        body.extend(item)
    xref_offset = len(body)
    body.extend(b"xref\n0 5\n0000000000 65535 f \n")
    body.extend(b"".join(f"{offset:010d} 00000 n \n".encode() for offset in offsets[1:]))
    body.extend(b"trailer\n<< /Size 5 /Root 1 0 R >>\nstartxref\n")
    body.extend(str(xref_offset).encode() + b"\n%%EOF\n")
    return bytes(body)


def _wav_template() -> bytes:
    return struct.pack("<4sI4s4sIHHIIHH4sI", b"RIFF", 36, b"WAVE", b"fmt ", 16, 1, 1, 8000, 16000, 2, 16, b"data", 0)


def _midi_template() -> bytes:
    track = bytes.fromhex("00FF510307A12000C00000903C4060803C4000FF2F00")
    return b"MThd" + struct.pack(">IHHH", 6, 0, 1, 96) + b"MTrk" + struct.pack(">I", len(track)) + track


def _pcap_template(little: bool) -> bytes:
    magic = b"\xd4\xc3\xb2\xa1" if little else b"\xa1\xb2\xc3\xd4"
    endian = "<" if little else ">"
    return magic + struct.pack(f"{endian}HHIIII", 2, 4, 0, 0, 65535, 1)


def _b64(value: str) -> bytes:
    return base64.b64decode(value)


def _tiff_template(little: bool) -> bytes:
    endian = "<" if little else ">"
    byte_order = b"II" if little else b"MM"
    # Baseline 1x1, 8-bit, uncompressed, single-strip grayscale image.
    tags = (
        (256, 3, 1, 1), (257, 3, 1, 1), (258, 3, 1, 8),
        (259, 3, 1, 1), (262, 3, 1, 1), (273, 4, 1, 122),
        (277, 3, 1, 1), (278, 4, 1, 1), (279, 4, 1, 1),
    )
    data = bytearray(byte_order + struct.pack(f"{endian}H", 42) + struct.pack(f"{endian}I", 8))
    data.extend(struct.pack(f"{endian}H", len(tags)))
    for tag, type_id, count, value in tags:
        data.extend(struct.pack(f"{endian}HHI", tag, type_id, count))
        data.extend(struct.pack(f"{endian}H", value) + b"\0\0" if type_id == 3 else struct.pack(f"{endian}I", value))
    data.extend(struct.pack(f"{endian}I", 0))
    data.append(0)
    return bytes(data)


def _avi_template() -> bytes:
    def chunk(tag: bytes, payload: bytes) -> bytes:
        return tag + struct.pack("<I", len(payload)) + payload + (b"\0" if len(payload) & 1 else b"")

    def list_chunk(kind: bytes, payload: bytes) -> bytes:
        return chunk(b"LIST", kind + payload)

    avih = struct.pack("<IIIIIIIIII4I", 1_000_000, 0, 0, 0x10, 1, 0, 1, 4, 1, 1, 0, 0, 0, 0)
    strh = struct.pack(
        "<4s4sIHHIIIIIIIIhhhh", b"vids", b"DIB ", 0, 0, 0, 0,
        1, 1, 0, 1, 4, 0xFFFFFFFF, 4, 0, 0, 1, 1,
    )
    strf = struct.pack("<IiiHHIIiiII", 40, 1, 1, 1, 24, 0, 4, 0, 0, 0, 0)
    hdrl = list_chunk(b"hdrl", chunk(b"avih", avih) + list_chunk(b"strl", chunk(b"strh", strh) + chunk(b"strf", strf)))
    movi = list_chunk(b"movi", chunk(b"00db", b"\0\0\0\0"))
    index = chunk(b"idx1", struct.pack("<4sIII", b"00db", 0x10, 4, 4))
    body = b"AVI " + hdrl + movi + index
    return b"RIFF" + struct.pack("<I", len(body)) + body


def _elf32_le_template() -> bytes:
    ident = b"\x7fELF" + bytes((1, 1, 1, 0, 0)) + bytes(7)
    header = ident + struct.pack("<HHIIIIIHHHHHH", 1, 3, 1, 0, 0, 52, 0, 52, 0, 0, 40, 1, 0)
    return header + bytes(40)  # The mandatory all-zero section-header-table entry.


def _macho64_le_template() -> bytes:
    # Empty ARM64 MH_OBJECT. ncmds=0 is a complete (though content-free) object.
    return struct.pack("<IiiIIIII", 0xFEEDFACF, 0x0100000C, 0, 1, 0, 0, 0, 0)


def _ogg_crc(data: bytes) -> int:
    value = 0
    for byte in data:
        value ^= byte << 24
        for _ in range(8):
            value = ((value << 1) ^ 0x04C11DB7) & 0xFFFFFFFF if value & 0x80000000 else (value << 1) & 0xFFFFFFFF
    return value


def _ogg_template() -> bytes:
    page = bytearray(b"OggS\0\x06" + struct.pack("<QII", 0, 1, 0) + b"\0\0\0\0" + b"\x01\x00")
    page[22:26] = struct.pack("<I", _ogg_crc(page))
    return bytes(page)


def _smb2_template() -> bytes:
    header = (
        b"\xFESMB" + struct.pack("<HHIHHIIQIIQ", 64, 1, 0, 0, 1, 0, 0, 1, 0, 0, 0) + bytes(16)
    )
    negotiate = struct.pack("<HHHHI16sIHHH", 36, 1, 1, 0, 0, bytes(16), 0, 0, 0, 0x0202)
    return header + negotiate


def _odf_template(kind: str) -> bytes:
    media_type = f"application/vnd.oasis.opendocument.{kind}"
    root_tag = {"text": "office:text", "spreadsheet": "office:spreadsheet", "presentation": "office:presentation"}[kind]
    content = (
        '<?xml version="1.0" encoding="UTF-8"?>'
        '<office:document-content xmlns:office="urn:oasis:names:tc:opendocument:xmlns:office:1.0" '
        'office:version="1.4"><office:body><' + root_tag + '/></office:body></office:document-content>'
    ).encode()
    manifest = (
        '<?xml version="1.0" encoding="UTF-8"?>'
        '<manifest:manifest xmlns:manifest="urn:oasis:names:tc:opendocument:xmlns:manifest:1.0" manifest:version="1.4">'
        f'<manifest:file-entry manifest:full-path="/" manifest:media-type="{media_type}"/>'
        '<manifest:file-entry manifest:full-path="content.xml" manifest:media-type="text/xml"/>'
        '</manifest:manifest>'
    ).encode()
    output = io.BytesIO()
    with zipfile.ZipFile(output, "w") as archive:
        for name, payload, compression in (
            ("mimetype", media_type.encode(), zipfile.ZIP_STORED),
            ("META-INF/manifest.xml", manifest, zipfile.ZIP_DEFLATED),
            ("content.xml", content, zipfile.ZIP_DEFLATED),
        ):
            info = zipfile.ZipInfo(name, (1980, 1, 1, 0, 0, 0))
            info.compress_type = compression
            info.external_attr = 0o600 << 16
            archive.writestr(info, payload)
    return output.getvalue()


_EXACT_TEMPLATES: dict[str, tuple[bytes, str, str]] = {
    "png": (_png_template(), "PNG signature + 1x1 RGBA IHDR + zlib IDAT + IEND", "Complete one-pixel transparent PNG; chunk CRCs and zlib checksum are generated."),
    "jpeg": (_b64("/9j/4AAQSkZJRgABAgAAAQABAAD//gAQTGF2YzYxLjE5LjEwMQD/2wBDAAgEBAQEBAUFBQUFBQYGBgYGBgYGBgYGBgYHBwcICAgHBwcGBgcHCAgICAkJCQgICAgJCQoKCgwMCwsODg4RERT/xABLAAEBAAAAAAAAAAAAAAAAAAAACAEBAAAAAAAAAAAAAAAAAAAAABABAAAAAAAAAAAAAAAAAAAAABEBAAAAAAAAAAAAAAAAAAAAAP/AABEIAAIAAgMBIgACEQADEQD/2gAMAwEAAhEDEQA/AJ/AB//Z"), "SOI + JFIF APP0 + DQT + baseline SOF0 + DHT + SOS + entropy data + EOI", "Complete 2x2 baseline JPEG generated by FFmpeg and decoded by ffprobe."),
    "tiff-le": (_tiff_template(True), "little-endian TIFF header + 9-entry IFD + one 1-byte grayscale strip", "Complete baseline 1x1 uncompressed TIFF."),
    "tiff-be": (_tiff_template(False), "big-endian TIFF header + 9-entry IFD + one 1-byte grayscale strip", "Complete baseline 1x1 uncompressed TIFF."),
    "gif87a": (bytes.fromhex("47494638376101000100800000000000FFFFFF2C00000000010001000002024401003B"), "1x1 global palette + one LZW image + trailer", "Complete minimal GIF87a image."),
    "gif89a": (bytes.fromhex("47494638396101000100800000000000FFFFFF2C00000000010001000002024401003B"), "1x1 global palette + one LZW image + trailer", "Complete minimal GIF89a image."),
    "bmp": (struct.pack("<2sIHHI", b"BM", 58, 0, 0, 54) + struct.pack("<IiiHHIIiiII", 40, 1, 1, 1, 24, 0, 4, 0, 0, 0, 0) + b"\0\0\0\0", "BITMAPFILEHEADER + 40-byte DIB + one padded black pixel", "Complete uncompressed 1x1 24-bit BMP."),
    "wav": (_wav_template(), "RIFF/WAVE + PCM fmt chunk + empty data chunk", "Complete zero-sample mono PCM WAVE container."),
    "flac": (_b64("ZkxhQ4AAACICQAJAAAAMAAAMAfQA8AAAAKAE28ZtjkVZdpuzipLNb32d//hkCACfNwAAAEEt"), "STREAMINFO metadata + one valid silent audio frame", "Complete one-frame FLAC; frame/header CRCs and STREAMINFO are valid."),
    "aac": (_b64("//FsQAOf/N4CAExhdmM2MS4xOS4xMDEAAjBADv/xbEABf/wBGCAH//FsQAF//AEYIAc="), "three self-contained AAC-LC ADTS frames", "Complete short silent ADTS stream; each frame length is internally consistent."),
    "avi": (_avi_template(), "RIFF AVI + hdrl/avih + one DIB video stream + movi frame + idx1", "Complete indexed 1x1 one-frame uncompressed AVI."),
    "webp": (_b64("UklGRhoAAABXRUJQVlA4TA4AAAAvAUAAAAcQEf0PRET/Aw=="), "RIFF WEBP + one VP8L lossless frame", "Complete 2x2 lossless WebP."),
    "ivf": (_b64("REtJRgAAIABWUDgwAgACAAEAAAABAAAAAQAAAAAAAAAeAAAAAAAAAAAAAAAQAgCdASoCAAIAC8cIhYWIhYSIP4IADA1gAP7mtQA="), "32-byte IVF header + one VP8 frame record", "Complete 2x2 one-frame IVF/VP8 stream."),
    "midi": (_midi_template(), "MThd format-0 + tempo/program/note events + End-of-Track", "Complete half-second Standard MIDI File with one note."),
    "zip": (b"PK\x05\x06" + b"\x00" * 18, "empty EOCD record", "Complete empty non-ZIP64 archive."),
    "gzip": (gzip.compress(b"", mtime=0), "gzip member whose deflate stream expands to zero bytes", "Complete empty gzip member with CRC32/ISIZE."),
    "bzip2": (bz2.compress(b""), "bzip2 stream for zero decoded bytes", "Complete empty bzip2 stream."),
    "xz": (lzma.compress(b"", format=lzma.FORMAT_XZ), "XZ stream for zero decoded bytes", "Complete empty XZ stream with footer/checks."),
    "tar": (b"\x00" * 1024, "two zero 512-byte end blocks", "Complete empty tar archive."),
    "unix-ar": (b"!<arch>\n", "global ar signature and zero members", "Complete empty Unix ar archive."),
    "wasm": (b"\x00asm\x01\x00\x00\x00", "WebAssembly magic + version 1 and zero sections", "Complete empty WebAssembly module."),
    "elf32-le": (_elf32_le_template(), "ELF32 little-endian ET_REL header + mandatory null section header", "Complete stripped, content-free i386 relocatable ELF object."),
    "macho64-le": (_macho64_le_template(), "Mach-O 64-bit ARM64 MH_OBJECT header with zero load commands", "Complete content-free Mach-O object."),
    "pdf": (_pdf_template(), "catalog + one 1x1 blank Page + empty content stream + classic xref/trailer", "Complete one-page PDF with computed xref offsets."),
    "rtf": (b"{\\rtf1\\ansi}", "one root RTF group with version and charset", "Complete empty RTF document."),
    "postscript": (b"%!PS-Adobe-3.0\n%%EOF\n", "DSC header + EOF comment and no operators", "Complete empty PostScript program."),
    "sqlite3": (_sqlite_template(), "one 512-byte page: 100-byte database header + empty sqlite_schema leaf b-tree", "Complete minimum-size empty SQLite database; page/count/counter fields agree."),
    "json": (b"{}", "empty JSON object", "Complete RFC 8259 JSON text."),
    "xml": (b"<r/>", "one empty root element", "Complete well-formed UTF-8 XML document."),
    "pcap-le": (_pcap_template(True), "little-endian global header, Ethernet link type, zero packets", "Complete empty classic pcap file."),
    "pcap-be": (_pcap_template(False), "big-endian global header, Ethernet link type, zero packets", "Complete empty classic pcap file."),
    "pcapng": (bytes.fromhex("0A0D0D0A1C0000004D3C2B1A01000000FFFFFFFFFFFFFFFF1C000000010000001400000001000000FFFF000014000000"), "little-endian Section Header Block + Ethernet Interface Description Block", "Complete empty pcapng section with one interface and no packets."),
    "jbig2": (bytes.fromhex("974A42320D0A1A0A030000000133000000000000"), "JBIG2 sequential unknown-page-count header + End-of-File segment", "Complete content-free sequential JBIG2 file."),
    "rtp": (bytes.fromhex("800000010000000000000001"), "RTP v2 fixed header with zero-byte payload", "Complete RTP packet with PT=0, sequence=1 and SSRC=1."),
    "rtcp": (bytes.fromhex("80C9000100000001"), "RTCP Receiver Report with zero report blocks", "Complete one-packet RTCP compound unit under reduced-size framing."),
    "sip": (b"OPTIONS sip:a@example.invalid SIP/2.0\r\nVia: SIP/2.0/UDP host.invalid;branch=z9hG4bK1\r\nFrom: <sip:a@example.invalid>;tag=1\r\nTo: <sip:a@example.invalid>\r\nCall-ID: 1@host.invalid\r\nCSeq: 1 OPTIONS\r\nMax-Forwards: 70\r\nContent-Length: 0\r\n\r\n", "SIP OPTIONS request with mandatory transaction/dialog headers and empty body", "Complete syntactically framed SIP/2.0 request."),
    "smb": (_smb2_template(), "SMB2 NEGOTIATE request header + one SMB 2.0.2 dialect", "Complete unsigned SMB2 NEGOTIATE protocol message without transport prefix."),
    "nfs": (struct.pack(">10I", 1, 0, 2, 100003, 3, 0, 0, 0, 0, 0), "ONC RPC CALL for NFSv3 NULL with AUTH_NONE credential/verifier", "Complete connectionless RPC/NFS NULL call; TCP record marking is transport-specific."),
    "modbus": (bytes.fromhex("000100000006010300000001"), "MBAP header + Read Holding Registers request for one register", "Complete Modbus TCP ADU."),
    "mqtt": (bytes.fromhex("C000"), "MQTT PINGREQ fixed header with zero remaining length", "Complete MQTT PINGREQ control packet."),
    "ogg": (_ogg_template(), "single BOS+EOS Ogg page containing one empty packet", "Complete generic Ogg physical bitstream with a valid page CRC."),
    "msgpack": (bytes.fromhex("80"), "empty fixmap", "Complete MessagePack value."),
    "bson": (bytes.fromhex("0500000000"), "length=5 + document terminator", "Complete empty BSON document."),
    "capnp": (bytes.fromhex("0000000000000000"), "one zero-word segment framing table", "Complete empty Cap'n Proto message with no root word."),
    "odt": (_odf_template("text"), "ODF ZIP with stored mimetype, manifest.xml and empty text content.xml", "Complete minimal OpenDocument Text package."),
    "ods": (_odf_template("spreadsheet"), "ODF ZIP with stored mimetype, manifest.xml and empty spreadsheet content.xml", "Complete minimal OpenDocument Spreadsheet package."),
    "odp": (_odf_template("presentation"), "ODF ZIP with stored mimetype, manifest.xml and empty presentation content.xml", "Complete minimal OpenDocument Presentation package."),
    "ttf": (_b64("AAEAAAAKAIAAAwAgT1MvMkUAQ7AAAAEoAAAAYGNtYXAADABzAAABkAAAADRnbHlmAAAAAAAAAcwAAAABaGVhZCxUtzwAAACsAAAANmhoZWEDIgEuAAAA5AAAACRobXR4AfQAAAAAAYgAAAAGbG9jYQAAAAAAAAHEAAAABm1heHAAAwACAAABCAAAACBuYW1lyv6LewAAAdAAAAGAcG9zdAAHAAAAAANQAAAAJgABAAAAAQAAIpmKzl8PPPUAAwPoAAAAAOafOy4AAAAA5p87LgAAAAAAAAAAAAAAAwACAAAAAAAAAAEAAAMg/zgAAAH0AAAAAAAAAAEAAAAAAAAAAAAAAAAAAAABAAEAAAACAAAAAAAAAAAAAgAAAAAAAAAAAAAAAAAAAAAAAwH0AZAABQAEAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABAAAAAAAAAAAAAAAAPz8/PwAAACAAIAMg/zgAAAMgAMgAAAAAAAAAAAAAAAAAAAAgAAAB9AAAAAAAAAAAAAIAAAADAAAAFAADAAEAAAAUAAQAIAAAAAQABAABAAAAIP//AAAAIP///+EAAQAAAAAAAAAAAAAAAAAAAAAAAAAMAJYAAQAAAAAAAQAIAAAAAQAAAAAAAgAHAAgAAQAAAAAAAwAUAA8AAQAAAAAABAAQACMAAQAAAAAABQALADMAAQAAAAAABgAQAD4AAwABBAkAAQAQAE4AAwABBAkAAgAOAF4AAwABBAkAAwAoAGwAAwABBAkABAAgAJQAAwABBAkABQAWALQAAwABBAkABgAgAMpGb3JtYXRLQlJlZ3VsYXJGb3JtYXRLQiBSZWd1bGFyIDEuMEZvcm1hdEtCIFJlZ3VsYXJWZXJzaW9uIDEuMEZvcm1hdEtCLVJlZ3VsYXIARgBvAHIAbQBhAHQASwBCAFIAZQBnAHUAbABhAHIARgBvAHIAbQBhAHQASwBCACAAUgBlAGcAdQBsAGEAcgAgADEALgAwAEYAbwByAG0AYQB0AEsAQgAgAFIAZQBnAHUAbABhAHIAVgBlAHIAcwBpAG8AbgAgADEALgAwAEYAbwByAG0AYQB0AEsAQgAtAFIAZQBnAHUAbABhAHIAAgAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAACAAAAAwAA"), "sfnt directory + OS/2,cmap,glyf,head,hhea,hmtx,loca,maxp,name,post", "Complete one-glyph TrueType font with valid table and master checksums."),
    "opentype-cff": (_b64("T1RUTwAJAIAAAwAQQ0ZGIJnt4QsAAAM0AAAAYU9TLzJFAEOwAAABAAAAAGBjbWFwAAwAcwAAAuAAAAA0aGVhZCxUtzwAAACcAAAANmhoZWEDIgEuAAAA1AAAACRobXR4AfQAAAAAA5gAAAAGbWF4cAACUAAAAAD4AAAABm5hbWXK/ot7AAABYAAAAYBwb3N0AAMAAAAAAxQAAAAgAAEAAAABAAAwCmjqXw889QADA+gAAAAA5p87LgAAAADmnzsuAAAAAAAAAAAAAAADAAIAAAAAAAAAAQAAAyD/OAAAAfQAAAAAAAAAAQAAAAAAAAAAAAAAAAAAAAEAAFAAAAIAAAADAfQBkAAFAAQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAEAAAAAAAAAAAAAAAA/Pz8/AAAAIAAgAyD/OAAAAyAAyAAAAAAAAAAAAAAAAAAAACAAAAAAAAwAlgABAAAAAAABAAgAAAABAAAAAAACAAcACAABAAAAAAADABQADwABAAAAAAAEABAAIwABAAAAAAAFAAsAMwABAAAAAAAGABAAPgADAAEECQABABAATgADAAEECQACAA4AXgADAAEECQADACgAbAADAAEECQAEACAAlAADAAEECQAFABYAtAADAAEECQAGACAAykZvcm1hdEtCUmVndWxhckZvcm1hdEtCIFJlZ3VsYXIgMS4wRm9ybWF0S0IgUmVndWxhclZlcnNpb24gMS4wRm9ybWF0S0ItUmVndWxhcgBGAG8AcgBtAGEAdABLAEIAUgBlAGcAdQBsAGEAcgBGAG8AcgBtAGEAdABLAEIAIABSAGUAZwB1AGwAYQByACAAMQAuADAARgBvAHIAbQBhAHQASwBCACAAUgBlAGcAdQBsAGEAcgBWAGUAcgBzAGkAbwBuACAAMQAuADAARgBvAHIAbQBhAHQASwBCAC0AUgBlAGcAdQBsAGEAcgAAAAIAAAADAAAAFAADAAEAAAAUAAQAIAAAAAQABAABAAAAIP//AAAAIP///+EAAQAAAAAAAwAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAEABAEAAQEBEUZvcm1hdEtCLVJlZ3VsYXIAAQEBFPgbAPgcAvgdA/gYBIsPi+wS4BEAAwEBBBQcMS4wRm9ybWF0S0IgUmVndWxhckZvcm1hdEtCAAAAAgEBBAf4iA74iA4AAAAB9AAAAAAAAA=="), "sfnt OTTO directory + CFF,OS/2,cmap,head,hhea,hmtx,maxp,name,post", "Complete one-glyph OpenType/CFF font with valid checksums."),
    "woff": (_b64("d09GRgABAAAAAAKUAAoAAAAAA3gAAQAAAAAAAAAAAAAAAAAAAAAAAAAAAABPUy8yAAABXAAAAC4AAABgRQBDsGNtYXAAAAGUAAAAKQAAADQADABzZ2x5ZgAAAcgAAAABAAAAAQAAAABoZWFkAAAA9AAAADYAAAA2LFS3PGhoZWEAAAEsAAAAGwAAACQDIgEuaG10eAAAAYwAAAAGAAAABgH0AABsb2NhAAABwAAAAAYAAAAGAAAAAG1heHAAAAFIAAAAEwAAACAAAwACbmFtZQAAAcwAAAC3AAABgMr+i3twb3N0AAAChAAAAA8AAAAmAAcAAAABAAAAAQAAIpmKzl8PPPUAAwPoAAAAAOafOy4AAAAA5p87LgAAAAAAAAAAAAAAAwACAAAAAAAAeJxjYGRgYFb4b8HAwPiFAQIYGVABIwBAwQJTAHicY2BkYGBgYoABBAsKAACXAAYAeJxjYGb8wjiBgZWBhYEwYETm2AMBkFJgUGBW+G/BwMCswHACTb0CAwMA8fEFNQAAAfQAAAAAAAB4nGNgYGBiYGBgBmIRIMkIplkYFIA0CxCC+Ar//0PI/w/BfAYAT+IGfAAAAAAAAAAAAAAAAAAAAHichY69CoJgFIYf0/4oyiGaP2hpUZT2BoeWoMGhMXCQEDThS+8kupKuoqvqs07QD9EZDs/7c+AAQ85YNGPRu+9mWnSNerDNhLGwg8tMuM2AhXDH+EvTtJy+cVw2wi1G7IRt5uTCDoqTcJspF+GO8a+rUhdJtY7idF/niX5KJVqFfvDpbVN9zMrDa+RJxIoSTUFCxZqImJQ9tfkl4TtVH7kixCf429sapTmSmd7h55X3fnUDebo9mgB4nGNgYsAPQPLMAAB9AAgA"), "WOFF header + 10-table directory + zlib-compressed TrueType tables", "Complete one-glyph WOFF1 font reconstructing a valid sfnt."),
    "woff2": (_b64("d09GMgABAAAAAAFkAAoAAAAAA3gAAAEaAAEAAAAAAAAAAAAAAAAAAAAAAAAAAAAABmAANAoBLAE2AiQDBgsGAAQgBYMAByYb5QIAngfZueIkjTntwtK3eKgfa2//7omCZ9HkUUMjREKiBfFEKZTAkALD9COfzo2R0kOhFIKFZrATmHNT3VDzy1Ax/8Nx4Pm6xXsLdNEbDzTLOLxsMbE/ga82aSCBR7aEgSbQZLdkEIYrBV8/mL1RxizudRRrAur6MdiwkZhHbvgGAGyAhsSqFFhVNlBKYGMOmwUe0EDplS8CwfLHWbj472f+we/n+SEyAKmB4OdFzAhhxOgSaEkWyNirmBd9gKanT1q1QFm0TcfIWUbXoispaiAsukE0U7ekA3eUDc90rPuSrg0/B6FW00tUi0fIJU4Oj+vzYiZtJ/+g4kiLe4yqQvdNzveg98GJQ8ez7SakaxzbL7vkBAvjBgIAAAA="), "WOFF2 header + transformed directory + Brotli stream", "Complete one-glyph WOFF2 font reconstructing a valid sfnt."),
}


_EXTERNAL_VALIDATORS: dict[str, tuple[ValidatorCommand, ...]] = {
    "png": (ValidatorCommand("ffprobe", ("-v", "error", "{file}")),),
    "jpeg": (ValidatorCommand("ffprobe", ("-v", "error", "{file}")),),
    "tiff-le": (ValidatorCommand("tiffinfo", ("{file}",)),),
    "tiff-be": (ValidatorCommand("tiffinfo", ("{file}",)),),
    "gif87a": (ValidatorCommand("ffprobe", ("-v", "error", "{file}")),),
    "gif89a": (ValidatorCommand("ffprobe", ("-v", "error", "{file}")),),
    "bmp": (ValidatorCommand("ffprobe", ("-v", "error", "{file}")),),
    "wav": (ValidatorCommand("ffprobe", ("-v", "error", "{file}")),),
    "flac": (ValidatorCommand("flac", ("-t", "--silent", "{file}")),),
    "aac": (ValidatorCommand("ffprobe", ("-v", "error", "{file}")),),
    "avi": (ValidatorCommand("ffprobe", ("-v", "error", "{file}")),),
    "webp": (ValidatorCommand("ffprobe", ("-v", "error", "{file}")),),
    "ivf": (ValidatorCommand("ffprobe", ("-v", "error", "{file}")),),
    "zip": (ValidatorCommand("unzip", ("-t", "{file}"), 1),),  # empty ZIP is a warning exit on Info-ZIP
    "gzip": (ValidatorCommand("gzip", ("-t", "{file}")),),
    "bzip2": (ValidatorCommand("bzip2", ("-t", "{file}")),),
    "xz": (ValidatorCommand("xz", ("-t", "{file}")),),
    "tar": (ValidatorCommand("tar", ("-tf", "{file}")),),
    "unix-ar": (ValidatorCommand("ar", ("-t", "{file}")),),
    "pdf": (ValidatorCommand("pdfinfo", ("{file}",)),),
    "sqlite3": (ValidatorCommand("sqlite3", ("{file}", "PRAGMA integrity_check;")),),
    "json": (ValidatorCommand("format-kb", ("validate", "json", "{file}")),),
    "xml": (ValidatorCommand("xmllint", ("--noout", "{file}")),),
    "pcap-le": (ValidatorCommand("tcpdump", ("-nr", "{file}")),),
    "pcap-be": (ValidatorCommand("tcpdump", ("-nr", "{file}")),),
    "pcapng": (ValidatorCommand("tcpdump", ("-nr", "{file}")),),
    "ttf": (ValidatorCommand("ttx", ("-l", "{file}")),),
    "opentype-cff": (ValidatorCommand("ttx", ("-l", "{file}")),),
    "woff": (ValidatorCommand("ttx", ("-l", "{file}")),),
    "woff2": (ValidatorCommand("ttx", ("-l", "{file}")),),
    "odt": (ValidatorCommand("unzip", ("-t", "{file}")),),
    "ods": (ValidatorCommand("unzip", ("-t", "{file}")),),
    "odp": (ValidatorCommand("unzip", ("-t", "{file}")),),
}


def _validator_commands(spec: FormatSpec, *, prefix_only: bool = False) -> tuple[ValidatorCommand, ...]:
    internal_args = ("validate", spec.id, "{file}") + (("--prefix-only",) if prefix_only else ())
    return (ValidatorCommand("format-kb", internal_args),) + (() if prefix_only else _EXTERNAL_VALIDATORS.get(spec.id, ()))


def _field_semantics(path: str, length: int, note: str) -> tuple[str, str, tuple[int, int] | None, tuple[str, ...]]:
    text = f"{path} {note}".lower()
    endian = "le" if any(token in text for token in ("little", "u16le", "u32le", "u64le", "i32le", "i64le")) else "be" if any(token in text for token in ("big", "u16be", "u32be", "u64be", "i32be", "i64be")) else ""
    bits = length * 8
    integer_hint = any(token in text for token in ("length", "size", "count", "offset", "width", "height", "version", "rate", "timestamp", "number", "index", "flags", "packed", "crc", "checksum", "align", "depth", "type"))
    signed = any(token in text for token in ("i16", "i32", "i64", "signed"))
    if length in {1, 2, 4, 8} and integer_hint:
        type_name = ("int" if signed else "uint") + str(bits) + endian
        value_range = (-(1 << (bits - 1)), (1 << (bits - 1)) - 1) if signed else (0, (1 << bits) - 1)
    elif "ascii" in text or "fourcc" in text:
        type_name, value_range = f"ascii[{length}]", None
    else:
        type_name, value_range = f"bytes[{length}]", None

    if any(token in text for token in ("crc", "checksum", "adler", "md5")):
        role = "checksum"
        related = ("covered payload bytes",)
    elif "offset" in text:
        role = "offset"
        related = ("referenced region",)
    elif any(token in text for token in ("length", "size", "count")):
        role = "length"
        related = ("bounded region or repeated records",)
    elif any(token in text for token in ("flags", "packed")):
        role = "flags"
        related = ("optional fields selected by bits",)
    elif any(token in text for token in ("magic", "signature", "type", "tag", "version", "codec", "handler")):
        role = "enum"
        related = ()
    elif any(token in text for token in ("data", "payload", "stream", "pixel", "frame", "events", "object", "document")):
        role = "payload"
        related = ("containing length/checksum fields",)
    else:
        role = "integer" if integer_hint else "opaque"
        related = ()
    return type_name, role, value_range, related


def _template_field_offsets(spec: FormatSpec, data: bytes) -> tuple[TemplateFieldOffset, ...]:
    items: list[TemplateFieldOffset] = []

    def add(path: str, offset: int, length: int, note: str = "") -> None:
        if offset < 0 or length <= 0 or offset + length > len(data):
            raise RuntimeError(f"invalid template field range for {spec.id}:{path}")
        type_name, role, value_range, related = _field_semantics(path, length, note)
        items.append(
            TemplateFieldOffset(
                path,
                offset,
                length,
                data[offset : offset + length].hex().upper(),
                note,
                type_name,
                role,
                value_range,
                related,
            )
        )

    if spec.id not in _EXACT_TEMPLATES:
        if spec.magic and data:
            for rule in spec.magic[:1]:
                for index, clause in enumerate(rule.clauses):
                    if clause.offset + len(clause.value) <= len(data):
                        add(f"header.magic[{index}]@{clause.offset}", clause.offset, len(clause.value), "signature self-check")
        return tuple(items)

    if spec.id == "png":
        add("signature", 0, 8, "fixed PNG signature")
        add("IHDR.length", 8, 4, "big-endian u32")
        add("IHDR.type", 12, 4, "fixed ASCII IHDR")
        add("IHDR.width", 16, 4, "big-endian u32")
        add("IHDR.height", 20, 4, "big-endian u32")
        add("IHDR.bit_depth", 24, 1)
        add("IHDR.color_type", 25, 1)
        add("IHDR.compression", 26, 1)
        add("IHDR.filter", 27, 1)
        add("IHDR.interlace", 28, 1)
        add("IHDR.crc", 29, 4, "CRC32(type||data)")
        position = 33
        while position < len(data):
            size = int.from_bytes(data[position : position + 4], "big")
            kind = data[position + 4 : position + 8].decode("ascii")
            add(f"{kind}.length", position, 4, "big-endian u32")
            add(f"{kind}.type", position + 4, 4, "ASCII chunk type")
            if size:
                add(f"{kind}.data", position + 8, size, "chunk payload")
            add(f"{kind}.crc", position + 8 + size, 4, "CRC32(type||data)")
            position += 12 + size
    elif spec.id == "jpeg":
        add("SOI", 0, 2, "fixed FFD8")
        position = 2
        marker_index = 0
        while position < len(data):
            if data[position] != 0xFF:
                raise RuntimeError("invalid static JPEG marker boundary")
            marker_start = position
            while position < len(data) and data[position] == 0xFF:
                position += 1
            marker = data[position]
            position += 1
            marker_name = f"marker[{marker_index}].FF{marker:02X}"
            marker_index += 1
            if marker == 0xD9:
                add("EOI", marker_start, position - marker_start, "fixed FFD9")
                break
            length = int.from_bytes(data[position : position + 2], "big")
            add(f"{marker_name}.marker", marker_start, position - marker_start, "marker prefix and code")
            add(f"{marker_name}.segment.length", position, 2, "u16be including length field")
            payload_start = position + 2
            payload_end = position + length
            if marker == 0xC0:
                add("SOF.precision", payload_start, 1)
                add("SOF.height", payload_start + 1, 2, "u16be")
                add("SOF.width", payload_start + 3, 2, "u16be")
                add("SOF.components", payload_start + 5, 1)
                add("SOF.component_descriptors", payload_start + 6, payload_end - payload_start - 6)
            elif marker == 0xDA:
                add("SOS.header", payload_start, payload_end - payload_start, "scan component selectors")
                entropy_end = data.rfind(b"\xFF\xD9")
                add("SOS.entropy_data", payload_end, entropy_end - payload_end, "byte-stuffed entropy-coded scan")
                position = entropy_end
                continue
            elif payload_end > payload_start:
                add(f"{marker_name}.payload", payload_start, payload_end - payload_start)
            position = payload_end
    elif spec.id in {"tiff-le", "tiff-be"}:
        endian = "little" if spec.id.endswith("le") else "big"
        add("header.byte_order", 0, 2, endian)
        add("header.magic", 2, 2, "u16=42")
        add("header.first_ifd_offset", 4, 4, f"u32{spec.id[-2:]}")
        ifd_offset = int.from_bytes(data[4:8], endian)
        count = int.from_bytes(data[ifd_offset : ifd_offset + 2], endian)
        add("ifd.entry_count", ifd_offset, 2, f"u16{spec.id[-2:]}")
        tag_paths = {
            256: "tag.ImageWidth", 257: "tag.ImageLength", 258: "tag.BitsPerSample",
            259: "tag.Compression", 262: "tag.PhotometricInterpretation",
            273: "tag.StripOffsets", 277: "tag.SamplesPerPixel",
            278: "tag.RowsPerStrip", 279: "tag.StripByteCounts",
        }
        for index in range(count):
            entry = ifd_offset + 2 + index * 12
            tag = int.from_bytes(data[entry : entry + 2], endian)
            path = tag_paths[tag]
            add(f"{path}.tag", entry, 2, "TIFF tag ID")
            add(f"{path}.type", entry + 2, 2, "TIFF field type")
            add(f"{path}.count", entry + 4, 4, "value count")
            add(path, entry + 8, 4, "inline value or offset")
        next_ifd = ifd_offset + 2 + count * 12
        add("ifd.next_offset", next_ifd, 4, "zero terminates IFD chain")
        add("strip[0].data", 122, 1, "one grayscale pixel")
    elif spec.id in {"gif87a", "gif89a"}:
        add("header.signature_version", 0, 6, "GIF87a/GIF89a")
        add("logical_screen.width", 6, 2, "little-endian u16")
        add("logical_screen.height", 8, 2, "little-endian u16")
        add("logical_screen.packed", 10, 1)
        add("logical_screen.background_index", 11, 1)
        add("logical_screen.pixel_aspect", 12, 1)
        add("global_color_table", 13, 6, "two RGB entries")
        add("image.separator", 19, 1, "fixed 0x2C")
        add("image.descriptor", 20, 9, "left/top/width/height/packed")
        add("image.lzw_min_code_size", 29, 1)
        add("image.data_subblocks", 30, len(data) - 31, "length-prefixed LZW bytes ending in zero")
        add("trailer", len(data) - 1, 1, "fixed 0x3B")
    elif spec.id == "bmp":
        for path, offset, length, note in (
            ("header.signature", 0, 2, "BM"), ("header.file_size", 2, 4, "u32le"),
            ("header.pixel_offset", 10, 4, "u32le"), ("dib.header_size", 14, 4, "u32le"),
            ("image.width", 18, 4, "i32le"), ("image.height", 22, 4, "i32le"),
            ("dib.planes", 26, 2, "u16le"), ("image.bit_depth", 28, 2, "u16le"),
            ("dib.compression", 30, 4, "u32le"), ("dib.image_size", 34, 4, "u32le"),
            ("pixel_data", 54, len(data) - 54, "padded BGR row"),
        ):
            add(path, offset, length, note)
    elif spec.id == "wav":
        for path, offset, length, note in (
            ("RIFF.magic", 0, 4, "RIFF"), ("RIFF.size@4", 4, 4, "file_size-8 u32le"),
            ("RIFF.form_type@8", 8, 4, "WAVE"), ("fmt.type", 12, 4, "fmt "),
            ("fmt.size", 16, 4, "u32le"), ("fmt.format_tag", 20, 2, "PCM=1"),
            ("stream.channels", 22, 2, "u16le"), ("stream.sample_rate", 24, 4, "u32le"),
            ("fmt.byte_rate", 28, 4, "u32le"), ("fmt.block_align", 32, 2, "u16le"),
            ("stream.bits_per_sample", 34, 2, "u16le"), ("data.type", 36, 4, "data"),
            ("data.size", 40, 4, "u32le"),
        ):
            add(path, offset, length, note)
    elif spec.id == "flac":
        add("header.magic", 0, 4, "fLaC")
        add("metadata[0].header", 4, 4, "last/type + u24be length")
        add("STREAMINFO.block_sizes", 8, 4, "min/max u16be")
        add("STREAMINFO.frame_sizes", 12, 6, "min/max u24be")
        add("STREAMINFO.sample_description", 18, 8, "sample rate/channels/bps/total samples packed")
        add("STREAMINFO.md5", 26, 16, "decoded PCM MD5")
        add("frame[0]", 42, len(data) - 42, "frame header, subframe, padding, CRC16")
    elif spec.id == "aac":
        position = 0
        frame_index = 0
        while position < len(data):
            frame_length = ((data[position + 3] & 0x03) << 11) | (data[position + 4] << 3) | (data[position + 5] >> 5)
            add(f"frame[{frame_index}].sync_and_config", position, 4, "ADTS fixed+variable header prefix")
            add(f"frame[{frame_index}].frame_length", position + 3, 3, "13-bit field spanning these bytes")
            add(f"frame[{frame_index}].buffer_fullness_blocks", position + 6, 1, "buffer fullness tail + raw block count")
            add(f"frame[{frame_index}].payload", position + 7, frame_length - 7, "AAC raw_data_block")
            position += frame_length
            frame_index += 1
    elif spec.id == "avi":
        for path, offset, length, note in (
            ("RIFF.magic", 0, 4, "RIFF"), ("RIFF.size@4", 4, 4, "file_size-8 u32le"),
            ("RIFF.form_type@8", 8, 4, "AVI "), ("hdrl.list", 12, 12, "LIST size + hdrl"),
            ("avih.chunk", 24, 8, "avih + size"), ("avih.microseconds_per_frame", 32, 4, "u32le"),
            ("avih.flags", 44, 4, "AVIF_HASINDEX"), ("avih.total_frames", 48, 4, "u32le"),
            ("avih.streams", 56, 4, "u32le"), ("avih.width", 64, 4, "u32le"),
            ("avih.height", 68, 4, "u32le"), ("strl.list", 88, 12, "LIST size + strl"),
            ("strh.chunk", 100, 8, "strh + size"), ("strh.type", 108, 4, "vids"),
            ("strh.handler", 112, 4, "DIB "), ("strh.scale", 128, 4, "u32le"),
            ("strh.rate", 132, 4, "u32le"), ("strh.length", 140, 4, "u32le"),
            ("strf.chunk", 164, 8, "strf + size"), ("strf.bitmap_info", 172, 40, "BITMAPINFOHEADER"),
            ("movi.list", 212, 12, "LIST size + movi"), ("movi.frame[0]", 224, 12, "00db size + padded BGR"),
            ("idx1.chunk", 236, 8, "idx1 + size"), ("idx1.entry[0]", 244, 16, "chunk ID/flags/offset/size"),
        ):
            add(path, offset, length, note)
    elif spec.id == "webp":
        add("RIFF.magic", 0, 4, "RIFF")
        add("RIFF.size@4", 4, 4, "file_size-8 u32le")
        add("RIFF.form_type@8", 8, 4, "WEBP")
        add("chunk.type", 12, 4, "VP8L")
        size = int.from_bytes(data[16:20], "little")
        add("chunk.size", 16, 4, "u32le")
        add("chunk.data", 20, size, "VP8L bitstream")
    elif spec.id == "ivf":
        for path, offset, length, note in (
            ("header.signature", 0, 4, "DKIF"), ("header.version", 4, 2, "u16le"),
            ("header.length", 6, 2, "u16le=32"), ("header.codec", 8, 4, "VP80"),
            ("header.width", 12, 2, "u16le"), ("header.height", 14, 2, "u16le"),
            ("header.timebase_den", 16, 4, "u32le"), ("header.timebase_num", 20, 4, "u32le"),
            ("header.frame_count", 24, 4, "u32le"), ("header.reserved", 28, 4, "zero"),
            ("frame[0].size", 32, 4, "u32le"), ("frame[0].timestamp", 36, 8, "u64le"),
            ("frame[0].payload", 44, len(data) - 44, "VP8 keyframe"),
        ):
            add(path, offset, length, note)
    elif spec.id == "midi":
        add("header.magic", 0, 4, "MThd")
        add("header.length", 4, 4, "u32be=6")
        add("header.format", 8, 2, "u16be")
        add("header.track_count", 10, 2, "u16be")
        add("header.division", 12, 2, "u16be ticks/quarter")
        add("track.magic", 14, 4, "MTrk")
        add("track.length", 18, 4, "u32be")
        add("track.events", 22, len(data) - 22, "delta-time + MIDI/meta events")
    elif spec.id == "zip":
        add("EOCD.signature", 0, 4, "PK0506")
        add("EOCD.disk_numbers", 4, 4, "two u16le")
        add("EOCD.entry_counts", 8, 4, "two u16le")
        add("EOCD.central_size/offset", 12, 8, "two u32le")
        add("EOCD.comment_length", 20, 2, "u16le")
    elif spec.id == "gzip":
        add("header.magic", 0, 2, "1F8B")
        add("header.compression_method", 2, 1, "deflate=8")
        add("header.flags", 3, 1)
        add("header.mtime", 4, 4, "u32le")
        add("header.xfl", 8, 1)
        add("header.os", 9, 1)
        add("deflate.stream", 10, len(data) - 18, "raw DEFLATE")
        add("trailer.crc32", len(data) - 8, 4, "decoded bytes CRC32")
        add("trailer.isize", len(data) - 4, 4, "decoded size modulo 2^32")
    elif spec.id == "bzip2":
        add("header.magic", 0, 3, "BZh")
        add("header.block_size", 3, 1, "ASCII 1..9")
        add("stream.bitstream", 4, len(data) - 4, "block/EOS markers and CRCs")
    elif spec.id == "xz":
        add("stream_header", 0, 12, "magic + flags + CRC32")
        add("block_and_index", 12, len(data) - 24, "block payload and index")
        add("stream_footer", len(data) - 12, 12, "CRC32 + backward size + flags + YZ")
    elif spec.id == "tar":
        add("end_block[0]", 0, 512, "all zero")
        add("end_block[1]", 512, 512, "all zero")
    elif spec.id == "unix-ar":
        add("global.signature", 0, 8, "!<arch>\\n")
    elif spec.id == "wasm":
        add("header.magic", 0, 4, "0061736D")
        add("header.version", 4, 4, "u32le=1")
    elif spec.id == "elf32-le":
        for path, offset, length, note in (
            ("e_ident.magic", 0, 4, "7FELF"), ("e_ident.class", 4, 1, "ELFCLASS32"),
            ("e_ident.data", 5, 1, "ELFDATA2LSB"), ("e_ident.version", 6, 1, "EV_CURRENT"),
            ("e_ident.osabi", 7, 1, "System V"), ("e_type", 16, 2, "ET_REL u16le"),
            ("e_machine", 18, 2, "EM_386 u16le"), ("e_version", 20, 4, "u32le"),
            ("e_entry", 24, 4, "u32le"), ("e_phoff", 28, 4, "u32le"),
            ("e_shoff", 32, 4, "u32le=52"), ("e_flags", 36, 4, "u32le"),
            ("e_ehsize", 40, 2, "u16le=52"), ("e_phentsize", 42, 2, "u16le"),
            ("e_phnum", 44, 2, "u16le"), ("e_shentsize", 46, 2, "u16le=40"),
            ("e_shnum", 48, 2, "u16le=1"), ("e_shstrndx", 50, 2, "SHN_UNDEF"),
            ("section_header[0]", 52, 40, "mandatory all-zero null section"),
        ):
            add(path, offset, length, note)
    elif spec.id == "macho64-le":
        for path, offset, length, note in (
            ("header.magic", 0, 4, "MH_MAGIC_64 stored little-endian"),
            ("header.cputype", 4, 4, "CPU_TYPE_ARM64"), ("header.cpusubtype", 8, 4, "generic"),
            ("header.filetype", 12, 4, "MH_OBJECT"), ("header.ncmds", 16, 4, "zero"),
            ("header.sizeofcmds", 20, 4, "zero"), ("header.flags", 24, 4, "zero"),
            ("header.reserved", 28, 4, "zero"),
        ):
            add(path, offset, length, note)
    elif spec.id == "pdf":
        header_end = data.index(b"\n") + 1
        add("header.version", 0, header_end, "ASCII PDF header")
        for number in range(1, 5):
            start = data.index(f"{number} 0 obj".encode())
            end = data.index(b"endobj\n", start) + len(b"endobj\n")
            add(f"object[{number}]", start, end - start, "indirect object")
        xref = data.index(b"xref\n")
        trailer = data.index(b"trailer\n", xref)
        add("xref.table", xref, trailer - xref, "fixed-width object offsets")
        startxref = data.index(b"startxref\n", trailer)
        add("trailer.dictionary", trailer, startxref - trailer, "Size/Root")
        add("startxref", startxref, len(data) - startxref, "xref byte offset + EOF")
    elif spec.id == "rtf":
        add("document.group", 0, len(data), "balanced RTF root group")
    elif spec.id == "postscript":
        split = data.index(b"\n") + 1
        add("header.version", 0, split, "DSC header")
        add("trailer.eof", split, len(data) - split, "%%EOF")
    elif spec.id == "sqlite3":
        for path, offset, length, note in (
            ("header.magic@0", 0, 16, "fixed"), ("header.page_size@16", 16, 2, "u16be"),
            ("header.write_version@18", 18, 1, "u8"), ("header.read_version@19", 19, 1, "u8"),
            ("header.reserved_bytes@20", 20, 1, "u8"), ("header.payload_fractions@21", 21, 3, "64/32/32"),
            ("header.change_counter@24", 24, 4, "u32be"), ("header.page_count@28", 28, 4, "u32be"),
            ("header.freelist_trunk@32", 32, 4, "u32be"), ("header.freelist_count@36", 36, 4, "u32be"),
            ("header.schema_cookie@40", 40, 4, "u32be"), ("header.schema_format@44", 44, 4, "u32be"),
            ("header.text_encoding@56", 56, 4, "u32be"), ("header.incremental_vacuum@64", 64, 4, "u32be"),
            ("header.reserved@72", 72, 20, "zero"), ("header.version_valid_for@92", 92, 4, "u32be"),
            ("header.sqlite_version@96", 96, 4, "u32be"), ("page1.btree.type@100", 100, 1, "0D leaf table"),
            ("page1.btree.cell_count@103", 103, 2, "u16be"), ("page1.btree.cell_content_start@105", 105, 2, "u16be"),
            ("page1.free_space", 108, len(data) - 108, "zero-filled unused bytes"),
        ):
            add(path, offset, length, note)
    elif spec.id == "json":
        add("document.root", 0, len(data), "UTF-8 JSON value")
    elif spec.id == "xml":
        add("document.root", 0, len(data), "UTF-8 XML root element")
    elif spec.id in {"pcap-le", "pcap-be"}:
        for path, offset, length, note in (
            ("header.magic", 0, 4, "byte order/time unit"), ("header.version", 4, 4, "major/minor u16"),
            ("header.thiszone", 8, 4, "i32"), ("header.sigfigs", 12, 4, "u32"),
            ("capture.snaplen", 16, 4, "u32"), ("header.linktype", 20, 4, "u32"),
        ):
            add(path, offset, length, note)
    elif spec.id == "pcapng":
        add("SHB.block_type", 0, 4, "0A0D0D0A")
        add("SHB.total_length", 4, 4, "u32le")
        add("SHB.byte_order_magic", 8, 4, "4D3C2B1A")
        add("SHB.version", 12, 4, "major/minor")
        add("SHB.section_length", 16, 8, "i64le=-1")
        add("SHB.trailing_length", 24, 4, "u32le")
        add("IDB.block_type", 28, 4, "u32le=1")
        add("IDB.total_length", 32, 4, "u32le")
        add("IDB.linktype", 36, 2, "u16le Ethernet")
        add("IDB.reserved", 38, 2, "zero")
        add("IDB.snaplen", 40, 4, "u32le")
        add("IDB.trailing_length", 44, 4, "u32le")
    elif spec.id == "jbig2":
        add("header.signature", 0, 8, "fixed file signature")
        add("header.flags", 8, 1, "sequential + unknown page count")
        add("segment[0].number", 9, 4, "u32be")
        add("segment[0].flags", 13, 1, "type=EndOfFile")
        add("segment[0].references", 14, 1, "zero referred segments")
        add("segment[0].page_association", 15, 1, "zero")
        add("segment[0].data_length", 16, 4, "u32be=0")
    elif spec.id == "rtp":
        add("header.flags_and_csrc_count", 0, 1, "V=2,P=0,X=0,CC=0")
        add("header.marker_payload_type", 1, 1, "M=0,PT=0")
        add("header.sequence", 2, 2, "u16be")
        add("header.timestamp", 4, 4, "u32be")
        add("header.ssrc", 8, 4, "u32be")
    elif spec.id == "rtcp":
        add("header.version_padding_count", 0, 1, "V=2,P=0,RC=0")
        add("header.packet_type", 1, 1, "RR=201")
        add("header.length_words_minus_one", 2, 2, "u16be=1")
        add("receiver.ssrc", 4, 4, "u32be")
    elif spec.id == "sip":
        line_end = data.index(b"\r\n") + 2
        add("start_line", 0, line_end, "ASCII request line ending CRLF")
        position = line_end
        while data[position : position + 2] != b"\r\n":
            end = data.index(b"\r\n", position) + 2
            name = data[position : data.index(b":", position, end)].decode("ascii").lower()
            add(f"header.{name}", position, end - position, "header line including CRLF")
            position = end
        add("header_body_separator", position, 2, "empty CRLF")
    elif spec.id == "smb":
        for path, offset, length, note in (
            ("header.protocol_id", 0, 4, "FE SMB"), ("header.structure_size", 4, 2, "u16le=64"),
            ("header.credit_charge", 6, 2, "u16le"), ("header.status_or_channel", 8, 4, "zero request field"),
            ("header.command", 12, 2, "NEGOTIATE=0"), ("header.credit_request", 14, 2, "u16le"),
            ("header.flags", 16, 4, "u32le"), ("header.next_command", 20, 4, "u32le"),
            ("header.message_id", 24, 8, "u64le"), ("header.process_tree_ids", 32, 8, "two u32le"),
            ("header.session_id", 40, 8, "u64le"), ("header.signature", 48, 16, "unsigned zero signature"),
            ("negotiate.fixed", 64, 36, "fixed request fields"), ("negotiate.dialect[0]", 100, 2, "SMB 2.0.2"),
        ):
            add(path, offset, length, note)
    elif spec.id == "nfs":
        paths = ("rpc.xid", "rpc.message_type", "rpc.version", "rpc.program", "nfs.version", "rpc.procedure", "credential.flavor", "credential.length", "verifier.flavor", "verifier.length")
        for index, path in enumerate(paths):
            add(path, index * 4, 4, "u32be")
    elif spec.id == "modbus":
        for path, offset, length, note in (
            ("MBAP.transaction_id", 0, 2, "u16be"), ("MBAP.protocol_id", 2, 2, "zero"),
            ("MBAP.length", 4, 2, "u16be counts unit+PDU"), ("MBAP.unit_id", 6, 1, "u8"),
            ("PDU.function", 7, 1, "Read Holding Registers=3"), ("PDU.start_address", 8, 2, "u16be"),
            ("PDU.quantity", 10, 2, "u16be"),
        ):
            add(path, offset, length, note)
    elif spec.id == "mqtt":
        add("fixed_header.type_flags", 0, 1, "PINGREQ=C0")
        add("fixed_header.remaining_length", 1, 1, "canonical base128 zero")
    elif spec.id == "ogg":
        for path, offset, length, note in (
            ("page.capture_pattern", 0, 4, "OggS"), ("page.version", 4, 1, "zero"),
            ("page.header_type", 5, 1, "BOS+EOS"), ("page.granule_position", 6, 8, "i64le"),
            ("page.serial", 14, 4, "u32le"), ("page.sequence", 18, 4, "u32le"),
            ("page.crc32", 22, 4, "Ogg CRC with this field zeroed"), ("page.segment_count", 26, 1, "one"),
            ("page.lacing[0]", 27, 1, "zero-length packet"),
        ):
            add(path, offset, length, note)
    elif spec.id == "msgpack":
        add("document.root", 0, 1, "empty fixmap")
    elif spec.id == "bson":
        add("document.byte_length", 0, 4, "i32le=5")
        add("document.terminator", 4, 1, "zero")
    elif spec.id == "capnp":
        add("framing.segment_count_minus_one", 0, 4, "u32le=0")
        add("framing.segment[0].word_count", 4, 4, "u32le=0")
    elif spec.id in {"odt", "ods", "odp"}:
        position = 0
        record_index = 0
        while position + 4 <= len(data) and data[position : position + 4] == b"PK\x03\x04":
            compressed_size = int.from_bytes(data[position + 18 : position + 22], "little")
            name_length = int.from_bytes(data[position + 26 : position + 28], "little")
            extra_length = int.from_bytes(data[position + 28 : position + 30], "little")
            name = data[position + 30 : position + 30 + name_length].decode("utf-8")
            payload_start = position + 30 + name_length + extra_length
            add(f"local[{record_index}].header", position, 30, "ZIP local header")
            add(f"local[{record_index}].name:{name}", position + 30, name_length, "UTF-8 entry name")
            add(f"local[{record_index}].payload", payload_start, compressed_size, "stored/deflated entry bytes")
            position = payload_start + compressed_size
            record_index += 1
        add("central_directory_and_eocd", position, len(data) - position, "ZIP central directory + EOCD")
    elif spec.id in {"ttf", "opentype-cff"}:
        add("header.sfnt_version", 0, 4, "00010000 or OTTO")
        add("header.num_tables", 4, 2, "u16be")
        add("header.search_range", 6, 2, "u16be")
        add("header.entry_selector", 8, 2, "u16be")
        add("header.range_shift", 10, 2, "u16be")
        table_count = int.from_bytes(data[4:6], "big")
        for index in range(table_count):
            offset = 12 + index * 16
            tag = data[offset : offset + 4].decode("ascii")
            add(f"table[{tag}].tag", offset, 4, "ASCII tag")
            add(f"table[{tag}].checksum", offset + 4, 4, "sum of padded u32be words")
            add(f"table[{tag}].offset", offset + 8, 4, "u32be")
            add(f"table[{tag}].length", offset + 12, 4, "u32be")
            table_offset = int.from_bytes(data[offset + 8 : offset + 12], "big")
            table_length = int.from_bytes(data[offset + 12 : offset + 16], "big")
            add(f"table[{tag}].data", table_offset, table_length, "table payload")
            if tag == "head":
                add("head.checkSumAdjustment", table_offset + 8, 4, "master checksum adjustment")
                add("head.unitsPerEm", table_offset + 18, 2, "u16be")
            elif tag == "maxp":
                add("maxp.numGlyphs", table_offset + 4, 2, "u16be")
    elif spec.id == "woff":
        for path, offset, length, note in (
            ("header.signature", 0, 4, "wOFF"), ("header.flavor", 4, 4, "sfnt flavor"),
            ("header.length", 8, 4, "u32be"), ("header.num_tables", 12, 2, "u16be"),
            ("header.reserved", 14, 2, "zero"), ("header.total_sfnt_size", 16, 4, "u32be"),
            ("header.version", 20, 4, "major/minor u16be"), ("header.metadata", 24, 12, "offset/length/original length"),
            ("header.private_data", 36, 8, "offset/length"),
        ):
            add(path, offset, length, note)
        table_count = int.from_bytes(data[12:14], "big")
        for index in range(table_count):
            offset = 44 + index * 20
            tag = data[offset : offset + 4].decode("ascii")
            table_offset = int.from_bytes(data[offset + 4 : offset + 8], "big")
            compressed_length = int.from_bytes(data[offset + 8 : offset + 12], "big")
            add(f"table[{tag}].record", offset, 20, "tag/offset/compressed/original length/checksum")
            add(f"table[{tag}].data", table_offset, compressed_length, "raw or zlib-compressed table")
    elif spec.id == "woff2":
        for path, offset, length, note in (
            ("header.signature", 0, 4, "wOF2"), ("header.flavor", 4, 4, "sfnt flavor"),
            ("header.length", 8, 4, "u32be"), ("header.num_tables", 12, 2, "u16be"),
            ("header.reserved", 14, 2, "zero"), ("header.total_sfnt_size", 16, 4, "u32be"),
            ("header.total_compressed_size", 20, 4, "u32be"), ("header.version", 24, 4, "major/minor"),
            ("header.metadata", 28, 12, "offset/length/original length"), ("header.private_data", 40, 8, "offset/length"),
            ("directory_and_brotli_stream", 48, len(data) - 48, "variable directory followed by one Brotli stream"),
        ):
            add(path, offset, length, note)
    elif spec.magic and data:
        for rule in spec.magic[:1]:
            for index, clause in enumerate(rule.clauses):
                if clause.offset + len(clause.value) <= len(data):
                    add(f"header.magic[{index}]@{clause.offset}", clause.offset, len(clause.value), "signature self-check")
    return tuple(items)


def _minimal_template(spec: FormatSpec) -> MinimalTemplate:
    exact = _EXACT_TEMPLATES.get(spec.id)
    if exact:
        data, structure, validation = exact
        return MinimalTemplate(
            "complete",
            structure,
            data.hex().upper(),
            validation,
            "verified",
            _validator_commands(spec),
            "command",
            _template_field_offsets(spec, data),
        )

    if spec.magic:
        rule = min(spec.magic, key=lambda item: item.required_length)
        data = bytearray(rule.required_length)
        for clause in rule.clauses:
            data[clause.offset : clause.offset + len(clause.value)] = clause.value
        return MinimalTemplate(
            "signature_prefix",
            f"Smallest byte prefix satisfying magic rule '{rule.name}'; append the required records from COMPACT.",
            bytes(data).hex().upper(),
            "Identification-valid prefix only, deliberately not claimed as a complete legal file; nested payload/tables/checksums are still required.",
            "not_complete",
            _validator_commands(spec, prefix_only=True),
            "self_check",
            _template_field_offsets(spec, bytes(data)),
        )
    return MinimalTemplate(
        "structural_only",
        "No invariant binary signature; construct fields and records from COMPACT/FIELD_DEFAULTS.",
        "",
        "No universal HEX prefix exists for this text or container-dependent format.",
        "not_available",
        (),
        "none",
        (),
    )


def build_blueprint(spec: FormatSpec) -> FormatBlueprint:
    template = _minimal_template(spec)
    fields = list(_fields_for(spec))
    known_paths = {item.path for item in fields}
    for item in template.field_offsets:
        if item.path not in known_paths:
            fields.append(
                _f(
                    item.path,
                    f"bytes[{item.length}]",
                    item.value_hex,
                    f"template offset {item.offset}; preserve declared byte order/encoding",
                    item.note or "Static-template field or region.",
                )
            )
            known_paths.add(item.path)
    return FormatBlueprint(spec, tuple(fields), _dependencies_for(spec), template, warnings_for(spec))


if mapped_format_ids() != frozenset(spec.id for spec in FORMATS):
    raise RuntimeError("risk profiles must cover exactly the 100-format catalog")


BLUEPRINTS: tuple[FormatBlueprint, ...] = tuple(build_blueprint(spec) for spec in FORMATS)
_BY_ID = {item.spec.id: item for item in BLUEPRINTS}


def get_blueprint(name: str) -> FormatBlueprint:
    spec = get_format(name)
    return _BY_ID[spec.id]


def render_blueprint(name: str) -> str:
    return get_blueprint(name).render()


def get_template_bytes(
    name: str,
    *,
    allow_incomplete: bool = False,
    allow_unverified: bool = False,
) -> bytes:
    blueprint = get_blueprint(name)
    template = blueprint.minimal_template
    if not template.hex:
        raise ValueError(f"{blueprint.spec.id} has no universal HEX template")
    if template.status != "complete" and not allow_incomplete:
        raise ValueError(
            f"{blueprint.spec.id} only has a {template.status}; pass allow_incomplete=True only for identification/skeleton use"
        )
    if template.status == "complete" and template.validation_status != "verified" and not allow_unverified:
        raise ValueError(
            f"{blueprint.spec.id} template is only {template.validation_status}; pass allow_unverified=True to accept that boundary"
        )
    return bytes.fromhex(template.hex)


def export_template(
    format_id: str,
    *,
    encoding: str = "raw",
    allow_incomplete: bool = False,
    allow_unverified: bool = False,
) -> dict[str, object]:
    if encoding not in {"raw", "hex"}:
        raise ValueError("encoding must be 'raw' or 'hex'")
    blueprint = get_blueprint(format_id)
    data = get_template_bytes(
        blueprint.spec.id,
        allow_incomplete=allow_incomplete,
        allow_unverified=allow_unverified,
    )
    template = blueprint.minimal_template
    payload: dict[str, object] = {
        "format_id": blueprint.spec.id,
        "status": template.status,
        "validation_status": template.validation_status,
        "validated_by": template.validated_by,
        "byte_length": len(data),
        "sha256": hashlib.sha256(data).hexdigest(),
        "validators": [item.to_dict() for item in template.validators],
        "template_field_offsets": [item.to_dict() for item in template.field_offsets],
        "encoding": encoding,
    }
    payload["bytes" if encoding == "raw" else "hex"] = data if encoding == "raw" else data.hex().upper()
    return payload
