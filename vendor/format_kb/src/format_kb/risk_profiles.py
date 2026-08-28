from __future__ import annotations

from .models import FormatSpec, WarningGuide


def _warning(
    profile: str,
    risk_id: str,
    fields: str,
    severity: str,
    trigger: str,
    failure: str,
    guard: str,
    cwes: str,
) -> WarningGuide:
    return WarningGuide(
        tuple(fields.split()),
        severity,
        failure,
        guard,
        risk_id,
        trigger,
        tuple(cwes.split()),
        profile,
    )


def _primary(profile: str, fields: str, trigger: str) -> WarningGuide:
    return _warning(
        profile,
        f"{profile}.derived-range",
        fields,
        "CRITICAL",
        trigger,
        "untrusted integer arithmetic can wrap/truncate, under-allocate, then drive an out-of-bounds read/write or memcpy",
        "decode into one sufficiently wide unsigned type; validate each domain; checked add/multiply; compare the final range with input length and a caller budget before allocation or pointer arithmetic",
        "CWE-190 CWE-125 CWE-787 CWE-789",
    )


def _extra(profile: str, kind: str, fields: str, trigger: str) -> WarningGuide:
    definitions = {
        "expansion": (
            "HIGH",
            "small encoded input can consume unbounded memory, disk, CPU or recursion depth during decoding",
            "stream output; enforce decoded-byte, ratio, object-count, nesting and time budgets; abort before materializing oversized output",
            "CWE-409 CWE-400 CWE-789",
        ),
        "integrity": (
            "HIGH",
            "accepting mismatched or incorrectly scoped checksums can expose corrupted data to later unsafe parsers",
            "calculate the specified algorithm over the exact covered bytes; compare before use; never treat a checksum as authenticity",
            "CWE-345 CWE-354",
        ),
        "recursion": (
            "HIGH",
            "cyclic references or attacker-controlled nesting can exhaust stack/CPU or repeatedly revisit objects",
            "use iterative traversal where possible; cap depth/object count; maintain a visited set keyed by validated object identity",
            "CWE-674 CWE-400",
        ),
        "path": (
            "CRITICAL",
            "absolute paths, parent traversal, symlinks or special files can escape the extraction root",
            "normalize without following links; reject absolute/parent/device paths; create files beneath a trusted directory using race-resistant APIs",
            "CWE-22 CWE-59",
        ),
        "execute": (
            "CRITICAL",
            "embedded code, actions or interpreter tokens can cross from data parsing into code execution",
            "parse in a sandbox; disable active content by default; allowlist operations; never pass embedded text to a shell or interpreter implicitly",
            "CWE-94 CWE-78 CWE-829",
        ),
        "external": (
            "HIGH",
            "external references can disclose local data, trigger SSRF, or fetch attacker-controlled content",
            "disable resolution by default; allowlist schemes/hosts; block local, private and link-local targets; apply byte/time limits",
            "CWE-611 CWE-918 CWE-829",
        ),
        "mapping": (
            "CRITICAL",
            "overlapping or wrapping file/virtual ranges can overwrite loader state or redirect control flow",
            "checked range arithmetic; enforce alignment, permissions, non-overlap and containment before mapping or jumping",
            "CWE-190 CWE-119 CWE-787",
        ),
        "table": (
            "HIGH",
            "inconsistent index/count tables can select records outside the validated region or create cycles",
            "validate the whole table range first; bound every index; enforce cross-table count equality and monotonic/non-overlap invariants",
            "CWE-125 CWE-129 CWE-400",
        ),
        "timestamp": (
            "MEDIUM",
            "zero denominators or timestamp scaling overflow can corrupt duration, seek and allocation decisions",
            "reject zero/invalid timebases; use checked rational conversion; cap converted duration before indexing",
            "CWE-369 CWE-190",
        ),
        "entity": (
            "CRITICAL",
            "entity expansion or external entity resolution can exhaust resources, read local files or issue network requests",
            "disable DTD/external entities; cap depth, expanded characters and total nodes; use a hardened XML parser",
            "CWE-611 CWE-776 CWE-918",
        ),
    }
    severity, failure, guard, cwes = definitions[kind]
    return _warning(profile, f"{profile}.{kind}", fields, severity, trigger, failure, guard, cwes)


# profile, ids, arithmetic/range fields, trigger, additional risk tuples(kind, fields, trigger)
_PROFILE_SPECS = (
    ("png", "png", "IHDR.width IHDR.height IHDR.bit_depth chunk.length", "geometry or chunk length determines filtered/zlib output and chunk boundaries", (("expansion", "IDAT inflated_bytes interlace", "compressed scanlines expand beyond the declared geometry"), ("integrity", "chunk.crc zlib.adler32", "CRC or Adler-32 does not cover the bytes actually consumed"))),
    ("jpeg", "jpeg", "SOF.width SOF.height SOF.components segment.length", "marker lengths or MCU geometry control segment reads and coefficient buffers", (("expansion", "SOS.entropy_data restart_interval", "entropy stream causes excessive work or progressive scan state"), ("table", "DQT.index DHT.index component.selector", "component selectors reference missing/oversized quantization or Huffman tables"))),
    ("gif", "gif87a gif89a", "screen.width screen.height image.width image.height sub_block.length", "canvas/frame dimensions and sub-block chains control allocation and LZW input", (("expansion", "lzw_min_code_size dictionary_size frame_count", "LZW/code-table growth or many frames exceeds output budget"), ("table", "packed.color_table_size palette_index", "packed flags and palette indices disagree with available table bytes"))),
    ("bmp", "bmp", "file.size pixel_offset dib.width dib.height bits_per_pixel row_stride", "signed dimensions, stride rounding and pixel offset determine the decode buffer and row reads", (("table", "dib.header_size colors_used palette_entries", "DIB variant or palette count selects fields outside the header"),)),
    ("tiff", "tiff-le tiff-be", "ifd.offset ifd.entry_count tag.count tag.value_offset StripByteCounts TileByteCounts", "IFD counts and indirect values form attacker-controlled offset/length arrays", (("recursion", "next_ifd SubIFDs ExifIFD GPSIFD", "IFD pointers form cycles or excessive directory depth"), ("expansion", "ImageWidth ImageLength SamplesPerPixel BitsPerSample Compression", "strip/tile decoding exceeds calculated raster budget"))),
    ("webp", "webp", "RIFF.size chunk.size VP8X.canvas_width VP8X.canvas_height", "RIFF/chunk lengths and canvas dimensions control chunk traversal and image allocation", (("expansion", "ANMF.frame_count ALPH VP8 VP8L", "animation frames or compressed image data exceed decode budget"),)),
    ("icon", "ico cursor", "directory.count entry.width entry.height entry.bytes_in_resource entry.image_offset", "directory records select embedded BMP/PNG ranges and decoded surfaces", (("table", "entry.bit_count entry.color_count hotspot", "entry metadata disagrees with the selected embedded image type"),)),
    ("psd", "psd", "header.channels header.height header.width header.depth section.length", "channel geometry and length-prefixed resource/layer sections determine allocations", (("expansion", "compression row_byte_counts layer_count", "RLE/ZIP channels or many layers expand beyond budget"), ("table", "layer.channel_count channel.length", "nested layer/channel counts disagree with section bounds"))),
    ("dds", "dds", "header.width header.height header.depth mip_count array_size pitch_or_linear_size", "mip/array geometry and block-compression rounding determine surface ranges", (("table", "pixel_format.fourcc dx10.format caps", "legacy and DX10 headers select incompatible block sizes or dimensions"),)),
    ("openexr", "openexr", "dataWindow displayWindow channels sampling chunk_count chunk.offset chunk.packed_size", "signed windows, channel sampling and chunk tables determine large image/tile buffers", (("expansion", "compression unpacked_size deep_sample_count", "compressed/deep samples expand beyond per-chunk or total limits"), ("table", "attribute.name attribute.type attribute.size", "attribute length/type parsing escapes the header terminator"))),
    ("radiance", "radiance-hdr", "resolution.width resolution.height scanline.run_length", "resolution orientation and RLE runs determine scanline/canvas writes", (("expansion", "RLE.marker run_count", "run counts exceed the remaining scanline or repeat excessive work"),)),
    ("qoi", "qoi", "header.width header.height header.channels pixel_count run_length", "pixel_count and QOI_OP_RUN determine output writes", (("table", "index.hash index.slot", "malformed opcode/index state reads an uninitialized or invalid pixel entry"),)),
    ("pcx", "pcx", "xmin ymin xmax ymax planes bytesPerLine run_length", "inclusive coordinates, per-plane stride and RLE runs determine decoded rows", (("table", "palette_marker palette_entries", "palette lookup is attempted without the required trailing palette bytes"),)),
    ("jpeg2000", "jpeg2000-jp2 jpeg2000-j2k", "box.length marker.segment_length SIZ.width SIZ.height tile_count component_count", "box/marker lengths and tile/component geometry control codestream state", (("expansion", "decomposition_levels precincts codeblocks", "wavelet decomposition and tile/component counts exceed memory/CPU budgets"), ("table", "JP2C.offset XLBox", "nested box ranges or extended lengths escape the containing box"))),
    ("heif", "avif heif", "box.size item.extent_offset item.extent_length ispe.width ispe.height", "item extents and image properties select data ranges and decoded surfaces", (("table", "iloc.item_count iref ipma.property_index", "cross-box IDs/indices reference missing items or properties"), ("expansion", "grid.rows grid.columns auxiliary_images", "grid/sequence/auxiliary items multiply decode work"))),
    ("riff-audio", "wav", "RIFF.size chunk.size fmt.channels fmt.sample_rate fmt.block_align data.size", "RIFF/chunk sizes and PCM geometry determine sample reads and buffers", (("table", "fmt.format_tag fmt.cbSize fact.sample_length", "extension length or format-specific fields disagree with the fmt chunk"),)),
    ("iff-audio", "aiff aifc", "FORM.size chunk.size COMM.channels COMM.frames sample_size", "big-endian chunk lengths and sample geometry determine audio ranges", (("table", "SSND.offset SSND.blockSize compressionType", "sound-data offset/block settings point outside SSND or select unsupported codecs"),)),
    ("flac", "flac", "metadata.length STREAMINFO.block_size frame.block_size channels bits_per_sample", "metadata/frame sizes and PCM geometry determine frame and output allocation", (("integrity", "frame.crc8 frame.crc16 streaminfo.md5", "CRC/MD5 is checked over the wrong header/frame/decoded PCM range"), ("table", "SEEKTABLE.sample_number stream_offset", "seek points are unsorted or outside the audio stream"))),
    ("ogg-audio", "ogg-vorbis ogg-opus", "page_segments lacing_value page_sequence granule_position packet_length", "lacing sums and continued packets determine packet-buffer growth across pages", (("integrity", "page.crc32", "Ogg page CRC is not validated before packet reconstruction"), ("expansion", "comment_count comment_length setup_tables", "metadata/setup packets allocate unbounded arrays or strings"))),
    ("mp3", "mp3", "frame.bitrate frame.sample_rate frame.padding frame_length ID3.synchsafe_size", "frame formulas and ID3 sizes determine frame/tag boundaries", (("table", "side_info main_data_begin reservoir", "bit reservoir points before retained main data"), ("expansion", "ID3.frame_count APIC.size", "large or nested metadata consumes excessive memory"))),
    ("isobmff-audio", "m4a", "box.size sample_count stsz.sample_size stco.offset duration timescale", "sample tables and box sizes select encoded audio ranges and duration arrays", (("table", "stsc.first_chunk stts.count stsz.count", "sample/chunk/time tables have inconsistent counts or indices"), ("timestamp", "duration timescale edit_list", "time scaling or edits overflow/underflow"))),
    ("midi", "midi", "header.length track.length delta_time vlq_length", "chunk lengths and variable-length quantities control event parsing", (("table", "running_status event_type data_length", "running status or event-specific data length consumes bytes from the next event"), ("timestamp", "division tempo delta_time", "tempo/division conversion overflows or division is invalid"))),
    ("au", "au", "data_offset data_size encoding sample_rate channels", "header offsets and sample geometry determine PCM/compressed data ranges", (("expansion", "encoding data_size", "encoded data expands beyond the audio output budget"),)),
    ("amr", "amr-nb amr-wb", "TOC.F TOC.FT frame_payload_bits frame_count", "frame type selects an exact bit count and frame boundary", (("table", "TOC.FT TOC.Q padding_bits", "reserved mode or nonzero padding desynchronizes subsequent frames"),)),
    ("ape", "ape", "descriptorBytes headerBytes seekTableBytes audioDataBytes totalFrames blocksPerFrame", "descriptor section sizes and frame counts determine offsets and PCM allocation", (("integrity", "descriptor.md5 frame.crc", "hash/CRC is omitted or scoped to the wrong encoded/decoded bytes"),)),
    ("wavpack", "wavpack", "block.ckSize block_samples total_samples channels bits_per_sample", "block size/sample counts determine block traversal and PCM output", (("integrity", "block.crc metadata.length", "block CRC or metadata length is accepted after partial parsing"),)),
    ("caf", "caf", "chunk.size desc.channels_per_frame desc.bits_per_channel packet_count", "signed 64-bit chunk sizes and packet descriptions determine data arrays", (("table", "pakt.packet_count packet_table data_offset", "packet table counts/offsets disagree with the data chunk"),)),
    ("isobmff-video", "mp4 quicktime 3gp", "box.size duration timescale sample_count sample_size chunk_offset width height", "nested boxes and sample tables determine media ranges, frame buffers and timestamps", (("table", "stsc stsz stco/co64 stts ctts", "sample/chunk/offset/time tables have inconsistent cardinality or ranges"), ("timestamp", "duration timescale edit_list composition_offset", "time conversion overflows or uses a zero/unsupported timescale"))),
    ("ebml", "matroska webm", "element.id element.size Segment.size TrackNumber Block.size", "EBML variable integers and unknown sizes control recursive element ranges", (("recursion", "SeekHead Cues Tags Chapters Attachments", "nested/master elements or references form deep/cyclic traversals"), ("expansion", "lace_count frame_size attachment_size", "lacing or attachments allocate excessive packet/object buffers"))),
    ("riff-video", "avi", "RIFF.size LIST.size chunk.size avih.total_frames stream.width stream.height", "nested RIFF lists, frame counts and geometry determine indexes and decode buffers", (("table", "idx1.offset OpenDML.index stream_number", "index offsets/counts point outside movi or select absent streams"),)),
    ("flv", "flv", "data_offset tag.data_size previous_tag_size timestamp", "24-bit tag sizes and previous-size links determine tag traversal", (("timestamp", "timestamp timestamp_extended", "timestamp reconstruction or ordering wraps"), ("table", "script.array_length AMF.depth", "AMF metadata counts/depth cause recursion or oversized allocation"))),
    ("mpeg-ps", "mpeg-ps", "PES.packet_length pack_header_length stuffing_length", "start-code packet lengths and stuffing control parser advancement", (("timestamp", "PTS DTS SCR mux_rate", "timestamp bitfields or scaling overflow"),)),
    ("mpeg-ts", "mpeg-ts", "adaptation_field_length section_length PES_packet_length continuity_counter", "fixed packet sub-lengths and PSI/PES lengths select bytes inside 188-byte packets", (("integrity", "PSI.crc32", "PAT/PMT section CRC is ignored before trusting PIDs and lengths"), ("table", "PID continuity_counter pointer_field", "discontinuity or pointer fields desynchronize section reassembly"))),
    ("ivf", "ivf", "header_size frame_count frame.size width height timebase_num timebase_den", "frame size/count and geometry determine packet ranges and decoder setup", (("timestamp", "frame.timestamp timebase_num timebase_den", "invalid timebase or timestamp scaling corrupts duration/indexing"),)),
    ("asf", "asf", "object.size object_count packet_size packet_count preroll", "GUID object sizes and packet counts determine nested object traversal and allocation", (("table", "stream_number index_entry payload_count", "indices or stream IDs reference absent objects/packets"),)),
    ("ogg-video", "ogg-theora", "page_segments lacing_value frame_width frame_height fps_num fps_den", "Ogg packet reconstruction and Theora frame geometry determine packet/frame buffers", (("integrity", "page.crc32", "page CRC is ignored before codec headers are trusted"), ("timestamp", "granule_position keyframe_shift fps_den", "granule decoding or frame-rate division overflows"))),
    ("mxf", "mxf", "KLV.ber_length partition.offset body_offset index_count essence_length", "BER lengths and partition/index offsets determine KLV ranges", (("table", "strong_reference primer_tag bodySID indexSID", "metadata references or SIDs point to missing sets/streams"), ("recursion", "metadata.references", "strong-reference graph cycles or expands without bounds"))),
    ("realmedia", "realmedia", "object.size header_count packet.length stream_number timestamp", "object and packet sizes determine traversal and stream buffers", (("table", "index.offset packet_count stream_number", "index entries point outside data or to missing streams"),)),
    ("swf", "swf", "file_length RECT.nbits tag.length frame_count", "declared file length, bit-packed RECT and extended tag lengths control decompression/tag traversal", (("expansion", "CWS.ZLIB ZWS.LZMA file_length", "compressed body expands beyond the declared or configured limit"), ("execute", "DoAction DoABC PlaceObject", "active script/action tags execute when handed to a player"))),
    ("zip", "zip", "entry_count name_length extra_length compressed_size uncompressed_size local_offset central_size", "local/central records and ZIP64 sizes determine extraction ranges and output", (("expansion", "compressed_size uncompressed_size nested_archive", "entries or nested archives exceed output/ratio/depth budgets"), ("path", "entry.name symlink.target external_attributes", "entry path or link metadata escapes the destination"), ("integrity", "entry.crc32", "CRC is checked over the wrong stream or after unsafe consumption"))),
    ("rar", "rar4 rar5", "header_size data_size unpacked_size file_count extra_size", "variable header/data sizes and archive counts determine block traversal and extraction buffers", (("expansion", "unpacked_size dictionary_size solid_state", "solid/dictionary decode exceeds memory/output budgets"), ("path", "file.name redirection.target symlink.target", "stored path or redirection escapes extraction root"), ("integrity", "header.crc file.hash", "header/file integrity is not checked before metadata or output use"))),
    ("7z", "7z", "next_header_offset next_header_size pack_size unpack_size folder_count coder_count", "64-bit offsets and nested folder/coder tables determine archive graph and buffers", (("expansion", "dictionary_size unpack_size folder_count", "coder chains or dictionary sizes exhaust memory/CPU"), ("path", "file.name anti_item symlink", "stored path/link escapes extraction root"), ("integrity", "start_header_crc next_header_crc stream.crc", "CRC scope/order is incorrect"))),
    ("gzip", "gzip", "XLEN optional_field_length compressed_size ISIZE", "optional header fields and deflate stream determine input traversal and modulo-32-bit output size", (("expansion", "deflate.output ISIZE concatenated_members", "member expansion or concatenation exceeds total output budget"), ("integrity", "FHCRC CRC32 ISIZE", "header/data checks are ignored or ISIZE is trusted as an allocation bound"))),
    ("bzip2", "bzip2", "block_size selectors_count groups_count decoded_count", "entropy tables, selectors and run lengths determine decode state/output", (("expansion", "RUNA RUNB block_size concatenated_streams", "run expansion or many streams exceeds output/CPU budget"), ("integrity", "block_crc stream_crc", "combined/block CRC is not verified before output use"))),
    ("xz", "xz", "header.flags block.header_size compressed_size uncompressed_size backward_size", "VLI sizes and footer index determine block ranges and filter memory", (("expansion", "LZMA2.dictionary_size uncompressed_size", "filter dictionary/output exceeds budget"), ("integrity", "header_crc block_check index_crc footer_crc", "one of the layered checks is skipped or scoped incorrectly"))),
    ("zstd", "zstd", "window_size frame_content_size block_size dictionary_id", "frame header and block sizes determine window allocation and output", (("expansion", "window_size frame_content_size skippable_size", "large window/content or concatenated frames exceed resource budget"), ("integrity", "content_checksum", "optional checksum is ignored or treated as authentication"))),
    ("lz4", "lz4-frame", "block_max_size content_size block.size dictionary_id", "descriptor and block sizes determine history/output buffers", (("expansion", "dependent_blocks content_size concatenated_frames", "dependent block history or output exceeds budget"), ("integrity", "header_checksum block_checksum content_checksum", "XXH32 checks are omitted or calculated over wrong bytes"))),
    ("tar", "tar", "header.size header.checksum pax.length sparse.map", "octal/base-256 sizes and 512-byte rounding determine entry ranges", (("path", "name prefix linkname typeflag", "entry path, hardlink, symlink or device escapes extraction policy"), ("expansion", "sparse.logical_size entry_count nested_archive", "sparse/nested entries consume unbounded disk or objects"))),
    ("cpio", "cpio-newc", "namesize filesize check header_count alignment", "ASCII-hex sizes and 4-byte padding determine name/data ranges", (("path", "name mode symlink_data", "entry path, symlink or special-file mode escapes extraction policy"), ("integrity", "070702.check", "sum checksum is trusted as authenticity or computed over wrong bytes"))),
    ("ar", "unix-ar", "member.size name_table_offset symbol_count", "ASCII member sizes and even-byte padding determine member traversal", (("path", "member.name extended_name", "archive member names are used as filesystem paths without containment"), ("table", "symbol.offset long_name.offset", "symbol/name offsets point outside the corresponding table"))),
    ("cab", "cab", "cabinet_size folder_count file_count data_block_count compressed_size uncompressed_size", "cabinet/folder/file tables determine compressed block and extraction ranges", (("expansion", "folder.compression window_size uncompressed_size", "folder decode expands beyond output/memory budget"), ("path", "file.name attributes", "stored path escapes extraction destination"))),
    ("iso9660", "iso9660", "volume_space_size logical_block_size extent_location data_length directory_length", "logical block multiplication and directory records select extents", (("path", "file_identifier RockRidge.symlink Joliet.name", "alternate names or symlinks escape extraction root"), ("recursion", "directory.extent parent child", "cyclic/repeated directory extents exhaust traversal"))),
    ("rpm", "rpm", "index_count data_size entry.offset entry.count payload_size", "header stores and entry arrays determine metadata/payload ranges", (("integrity", "signature.digest payload.digest", "package digests/signatures are skipped or applied to wrong regions"), ("path", "payload.cpio.name scriptlet", "payload paths escape root or scriptlets execute during install"))),
    ("elf", "elf32-le elf64-le elf32-be elf64-be", "e_phoff e_phnum e_phentsize e_shoff e_shnum e_shentsize", "header table count multiplication and offsets determine loader/parser tables", (("mapping", "p_offset p_filesz p_vaddr p_memsz p_align e_entry", "segment file/virtual ranges wrap, overlap or violate alignment"), ("table", "sh_link sh_info symbol.index relocation.offset", "cross-section indices reference absent sections/symbols"))),
    ("pe", "pe32 pe32plus", "e_lfanew NumberOfSections SizeOfOptionalHeader SizeOfHeaders SizeOfImage", "DOS/COFF counts and offsets determine NT and section tables", (("mapping", "VirtualAddress VirtualSize PointerToRawData SizeOfRawData AddressOfEntryPoint", "section/file/image ranges wrap, overlap or map with unsafe permissions"), ("table", "DataDirectory.RVA DataDirectory.Size relocation.import.count", "RVA/size pairs or nested tables escape mapped sections"))),
    ("macho", "macho32-le macho64-le macho32-be macho64-be macho-fat", "ncmds sizeofcmds cmdsize nfat_arch slice.offset slice.size", "load-command/fat-slice counts and sizes determine parser ranges", (("mapping", "segment.vmaddr segment.vmsize segment.fileoff segment.filesize entryoff", "segment/slice ranges wrap, overlap or point outside file"), ("table", "symoff nsyms stroff strsize indirectsymoff", "link-edit table offsets/counts disagree"))),
    ("wasm", "wasm", "section.payload_len vector.count code.body_size memory.limits", "LEB128 lengths and vector counts determine module arrays and code bodies", (("table", "function_count code_count type_index function_index", "indices or function/code counts disagree"), ("recursion", "block_depth type_depth element_segments", "nested expressions/types exhaust stack or validation work"))),
    ("dex", "dex", "file_size header_size map_off *_ids_size *_ids_off data_size data_off", "header table counts/offsets determine every ID/data region", (("integrity", "signature.sha1 checksum.adler32", "header signature/checksum is skipped or scoped incorrectly"), ("table", "string_idx type_idx method_idx class_data_off", "cross-table indices or encoded offsets reference invalid items"))),
    ("java", "java-class", "constant_pool_count attribute_length interfaces_count fields_count methods_count", "class counts and attribute lengths determine arrays and nested attributes", (("table", "constant_pool.index this_class super_class name_index descriptor_index", "constant-pool tags/indices reference wrong or absent entry types"), ("recursion", "descriptor_depth annotation_depth StackMapTable", "nested descriptors/annotations/frames exhaust validation resources"))),
    ("llvm", "llvm-bitcode", "block_length record_count abbrev_count operand_count", "bitstream block/record lengths and abbreviations determine bit-level traversal", (("table", "abbrev_id block_id value_id type_id", "IDs select undefined abbreviations/values/types"), ("recursion", "subblock_depth metadata_graph", "nested blocks or cyclic metadata exhaust resources"))),
    ("pdf", "pdf", "xref.offset object_stream.N object_stream.First stream.Length xref.Size", "xref/object/stream sizes and offsets determine random access and decompression", (("recursion", "Prev Parent Kids object.references", "xref/object/page graphs cycle or grow without bound"), ("expansion", "Filter DecodeParms stream.Length", "filter chains or object streams expand beyond budget"), ("execute", "OpenAction AA JavaScript Launch EmbeddedFile", "active actions or embedded content execute in a viewer"), ("external", "URI GoToR SubmitForm XObject.reference", "external actions fetch local/network resources"))),
    ("rtf", "rtf", "group_depth control_parameter bin_length object_size", "group nesting and numeric control words determine parser stack and binary reads", (("recursion", "group_depth stylesheet listtable", "deep groups or destination nesting exhaust stack/CPU"), ("execute", "object objdata field instruction", "embedded OLE objects or field instructions invoke external handlers"))),
    ("postscript", "postscript", "token_length array_length string_length procedure_depth", "language objects and procedures allocate VM and drive interpreter recursion", (("execute", "operator file run deletefile setpagedevice", "PostScript is executable content and can access dangerous operators in an unsandboxed interpreter"), ("recursion", "procedure recursion operand_stack dictionary_stack", "program exhausts stacks, VM or CPU"))),
    ("zip-doc", "epub docx xlsx pptx odt ods odp", "entry_count compressed_size uncompressed_size relationship_count xml_part_size", "ZIP records and package relationships determine decompressed parts and graph size", (("expansion", "nested_zip XML.part_count shared_strings", "package parts expand beyond memory/disk/object budgets"), ("path", "entry.name relationship.Target", "ZIP names or internal targets escape package/extraction boundaries"), ("external", "relationship.TargetMode external_link hyperlink", "external relationships fetch local/network resources"), ("entity", "XML.DTD XML.entity", "XML parts enable DTD/entity expansion"))),
    ("cfb", "ole-cfb", "sector_shift mini_sector_shift FAT_sector_count directory_count stream_size start_sector", "sector arithmetic and FAT chains determine stream ranges", (("recursion", "FAT DIFAT miniFAT directory.sibling", "sector/directory chains cycle or revisit nodes"), ("execute", "VBA.macros ObjectPool embedded_object", "compound streams contain macros or executable embedded objects"))),
    ("sqlite", "sqlite3", "page_size page_count reserved_bytes cell_count payload_length", "page arithmetic, cell pointers and varints determine page/cache/cell ranges", (("recursion", "overflow_page freelist_trunk btree_child", "page chains or b-tree links cycle or exceed page_count"), ("table", "cell_pointer serial_type schema_rootpage", "cell/record/schema indices escape the usable page or database"))),
    ("json", "json", "input_length nesting_depth string_length array_count object_count", "text length and container/member counts determine parser allocations", (("recursion", "array object nesting_depth", "deep arrays/objects exhaust stack or CPU"), ("table", "duplicate_key number_exponent unicode_escape", "duplicate names or extreme numbers produce inconsistent downstream semantics"))),
    ("xml", "xml", "input_length nesting_depth attribute_count text_length", "element/attribute/text counts determine tree allocation", (("entity", "DOCTYPE ENTITY SYSTEM PUBLIC", "DTD/entity declarations expand or fetch external resources"), ("recursion", "element_depth namespace_depth", "deep elements/namespaces exhaust stack or CPU"))),
    ("sfnt", "ttf opentype-cff sfnt-collection color-font", "numTables table.offset table.length numGlyphs loca.offset glyph.point_count", "table/glyph counts and offsets determine directory and outline ranges", (("integrity", "table.checksum head.checkSumAdjustment", "table or whole-font checksum is ignored/scoped incorrectly"), ("recursion", "composite_glyph component_glyph COLR.paint_graph", "composite glyph or color-paint references cycle or exceed depth"), ("table", "loca glyf hmtx cmap maxp CPAL COLR", "dependent table counts, glyph/palette indices or offsets disagree"))),
    ("woff", "woff", "numTables totalSfntSize table.offset compLength origLength", "table lengths and reconstructed SFNT size determine decompression/output", (("expansion", "compLength origLength totalSfntSize", "compressed tables expand beyond font budget"), ("integrity", "table.origChecksum head.checkSumAdjustment", "reconstructed table checks are skipped"))),
    ("woff2", "woff2", "numTables totalSfntSize totalCompressedSize transformLength", "base128 lengths and transformed tables determine Brotli/reconstruction output", (("expansion", "Brotli.output totalSfntSize transformLength", "compressed/transformed tables exceed output/CPU budget"), ("table", "glyf loca hmtx transform_version", "transformed table dependencies/counts disagree"))),
    ("pcap", "pcap-le pcap-be", "snaplen incl_len orig_len packet_offset", "packet lengths determine captured-data reads", (("table", "linktype protocol.length", "protocol parser trusts wire length rather than incl_len/captured boundary"), ("timestamp", "ts_sec ts_usec/ts_nsec", "timestamp unit/range conversion overflows"))),
    ("pcapng", "pcapng", "block.total_length captured_length original_length interface_id option.length", "duplicated block lengths and packet lengths determine block/packet ranges", (("table", "interface_id IDB.snaplen option.code", "packet references a missing interface or malformed option list"), ("timestamp", "timestamp_high timestamp_low if_tsresol", "resolution conversion overflows or uses an absent interface"))),
    ("parquet", "parquet", "footer_length row_group_count column_count page.compressed_size page.uncompressed_size value_count", "footer Thrift counts and page sizes determine metadata/data ranges", (("expansion", "dictionary_size page.uncompressed_size nested_levels", "compressed pages, dictionaries or nested levels exceed memory/CPU budget"), ("table", "column_chunk.file_offset schema_path encodings", "column metadata points outside file or disagrees with schema"))),
    ("avro", "avro-ocf", "metadata.block_count metadata.block_size data.block_count data.block_size schema_depth", "zigzag varints and block counts/sizes determine map and record decoding", (("recursion", "schema.record schema.array schema.union", "recursive schema or nested values exhaust stack/CPU"), ("integrity", "sync_marker codec", "sync markers/codecs are trusted without block-bound validation"))),
    ("eot", "eot", "EOTSize FontDataSize name.length name.offset compressed_size", "header and name lengths select embedded font and metadata ranges", (("expansion", "compressed_font FontDataSize", "compressed embedded font expands beyond the font budget"), ("integrity", "CheckSumAdjustment embedded.table.checksum", "embedded sfnt checksums are skipped"))),
    ("bitmap-font", "bitmap-font", "dfSize firstChar lastChar glyph.offset glyph.width bitmap.stride", "character counts and bitmap offsets determine glyph table and raster reads", (("table", "glyph.offset bitsOffset faceOffset deviceOffset", "version-specific offsets point outside the FNT resource"), ("mapping", "FON.NE.resource_offset resource_length", "NE resource arithmetic selects an unrelated executable region"))),
    ("jbig2", "jbig2", "segment.data_length referred_count page_association region.width region.height symbol_count", "segment graph, symbol counts and region geometry determine reads and bitmap writes", (("recursion", "referred_segments symbol_dictionary", "segment references cycle or repeatedly expand dictionaries"), ("expansion", "region.width region.height symbol_count arithmetic_state", "tiny coded data expands into oversized bitmaps or excessive arithmetic-decoder work"))),
    ("aac", "aac", "frame_length sampling_index channel_configuration raw_block_count", "ADTS frame length and audio geometry determine packet and PCM bounds", (("table", "profile sampling_index channel_configuration program_config", "header configuration selects missing or inconsistent raw-data syntax"), ("integrity", "adts.crc16", "optional frame CRC is ignored or scoped incorrectly"))),
    ("opus-raw", "opus-raw", "packet.length frame_count padding_length frame_duration channels", "TOC and packet framing determine frame boundaries and decoded sample allocation", (("expansion", "frame_count frame_duration decoded_samples", "packet framing exceeds the 120ms limit or caller PCM budget"), ("table", "TOC.code frame_lengths padding", "self-delimited frame lengths do not sum to the packet"))),
    ("rtp", "rtp rtcp", "CC extension.length padding.count packet.length report_count", "header counts, extension words and padding determine packet subranges", (("table", "payload_type SSRC CSRC RTCP.packet_type", "profile-dependent identifiers select absent or wrong payload/control parsers"), ("timestamp", "sequence timestamp NTP RTP_timestamp", "wraparound or clock conversion corrupts ordering and buffer indexes"))),
    ("sip", "sip", "line.length header.count Content-Length body.length uri.length", "text and declared body lengths determine message framing and parser allocations", (("external", "Request-URI Contact Route Record-Route body.URI", "parsing or handling the message triggers untrusted network targets"), ("recursion", "Via Route multipart.depth", "header chains or nested MIME bodies exhaust parsing work"))),
    ("smb", "smb", "transport.length NextCommand command.offset command.length data.offset data.length", "compound-command offsets and command-specific ranges drive memory copies", (("table", "Command StructureSize dialect context.offset", "command/dialect-specific structure sizes disagree with the negotiated parser"), ("integrity", "Signature transform.signature nonce", "signing/encryption verification is skipped before command processing"))),
    ("nfs", "nfs", "rpc.fragment_length opaque.length compound.count operation.length", "record fragments and XDR lengths/counts determine RPC and operation allocations", (("table", "program version procedure opcode result_count", "RPC or COMPOUND discriminants select incompatible union arms"), ("path", "component pathname symlink", "NFS names or links escape the intended export/path policy"))),
    ("modbus", "modbus", "MBAP.length function.address quantity byte_count", "MBAP and function-specific counts determine request/response ranges", (("table", "function byte_count quantity", "function-specific byte count disagrees with register/coil quantity"),)),
    ("mqtt", "mqtt", "remaining_length property_length payload.length topic.length", "base128 packet/property lengths determine buffer boundaries and allocations", (("table", "packet_type flags QoS packet_id property_id", "packet flags or property multiplicity select invalid parser states"), ("external", "server_reference response_topic topic", "broker/client handling follows attacker-controlled routing or server references"))),
    ("ogg-generic", "ogg", "page_segments lacing_value packet_length page_sequence granule_position", "lacing sums and continued pages determine packet buffer growth", (("integrity", "page.crc32", "page CRC is ignored before packet reconstruction"), ("expansion", "packet_count packet_length logical_stream_count", "continued packets or many logical streams exceed resource budgets"))),
    ("msgpack", "msgpack", "encoded_length string_length array_count map_count nesting_depth", "length/count prefixes determine recursive value allocation", (("recursion", "array map nesting_depth", "deep containers exhaust stack or CPU"), ("table", "extension.type map.key", "extension types or duplicate/noncanonical keys produce unsafe downstream interpretation"))),
    ("bson", "bson", "document.byte_length string.length binary.length array.count nesting_depth", "signed lengths and nested documents determine element ranges and allocation", (("recursion", "document array code_with_scope", "nested values or code-with-scope documents exhaust traversal"), ("execute", "javascript code_with_scope", "BSON JavaScript types cross into execution when automatically evaluated"))),
    ("capnp", "capnp", "segment_count segment_words pointer.offset struct.data_words struct.pointer_count list.element_count", "segment table and pointer arithmetic select graph ranges", (("recursion", "pointer_graph nesting_depth far_pointer", "cyclic/deep pointer graphs exhaust traversal"), ("table", "far_pointer landing_pad capability_index", "pointer discriminants or landing pads select invalid segment words"))),
)


_PROFILE_BY_ID: dict[str, str] = {}
_WARNINGS_BY_PROFILE: dict[str, tuple[WarningGuide, ...]] = {}
for profile, id_text, fields, trigger, extras in _PROFILE_SPECS:
    if profile in _WARNINGS_BY_PROFILE:
        raise RuntimeError(f"duplicate risk profile: {profile}")
    _WARNINGS_BY_PROFILE[profile] = (_primary(profile, fields, trigger),) + tuple(
        _extra(profile, kind, extra_fields, extra_trigger) for kind, extra_fields, extra_trigger in extras
    )
    for format_id in id_text.split():
        if format_id in _PROFILE_BY_ID:
            raise RuntimeError(f"duplicate risk mapping: {format_id}")
        _PROFILE_BY_ID[format_id] = profile


def warnings_for(spec: FormatSpec) -> tuple[WarningGuide, ...]:
    try:
        return _WARNINGS_BY_PROFILE[_PROFILE_BY_ID[spec.id]]
    except KeyError as exc:
        raise RuntimeError(f"missing risk profile for {spec.id}") from exc


def risk_profile_name(spec: FormatSpec) -> str:
    try:
        return _PROFILE_BY_ID[spec.id]
    except KeyError as exc:
        raise RuntimeError(f"missing risk profile for {spec.id}") from exc


def mapped_format_ids() -> frozenset[str]:
    return frozenset(_PROFILE_BY_ID)
