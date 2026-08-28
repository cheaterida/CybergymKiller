from __future__ import annotations

from .models import FormatSpec, MagicClause, MagicRule
from .sources import SOURCES


def _c(hex_value: str, offset: int = 0, mask: str | None = None) -> MagicClause:
    value = bytes.fromhex(hex_value)
    mask_bytes = bytes.fromhex(mask) if mask else None
    if mask_bytes is not None and len(mask_bytes) != len(value):
        raise ValueError("magic mask length mismatch")
    return MagicClause(offset, value, mask_bytes)


def _r(name: str, *clauses: MagicClause) -> MagicRule:
    return MagicRule(name, tuple(clauses))


def _f(
    id: str,
    name: str,
    category: str,
    extensions: str,
    magic: tuple[MagicRule, ...],
    structure: str,
    sources: str,
    *,
    media: str = "",
    probe: str | None = None,
    notes: str = "",
) -> FormatSpec:
    return FormatSpec(
        id=id,
        name=name,
        category=category,
        extensions=tuple(item for item in extensions.lower().split() if item),
        media_types=tuple(item for item in media.split() if item),
        magic=magic,
        probe=probe,
        structure=structure,
        sources=tuple(SOURCES[key] for key in sources.split()),
        notes=notes,
    )


FORMATS: tuple[FormatSpec, ...] = (
    # Images: 1-20
    _f("png", "Portable Network Graphics", "image", "png", (_r("PNG signature", _c("89504E470D0A1A0A")),),
       "LAYOUT: signature[8] | repeated Chunk{length:u32be,type:ascii4,data[length],crc:u32be} from IHDR to IEND. IHDR{width:u32be,height:u32be,depth:u8,color:u8,compression=0,filter=0,interlace:u8}. IDAT data concatenate into one zlib stream; decoded rows are filter_byte + packed samples. CHECK: each chunk CRC32(type||data); zlib Adler-32; enforce legal depth/color pairs and chunk order.", "png", media="image/png"),
    _f("jpeg", "JPEG/JFIF image", "image", "jpg jpeg jpe jfif", (_r("JPEG SOI", _c("FFD8FF")),),
       "LAYOUT: SOI=FFD8 | marker segments | SOS{length,selectors,...} | byte-stuffed entropy scan | EOI=FFD9. Length-coded segment{FF marker:u8,length:u16be including length field,payload[length-2]}; SOF carries precision,height,width,components. CHECK: every segment stays in-file; FF in scan is followed by 00/restart/marker; quantization/Huffman references exist; no global checksum.", "jpeg", media="image/jpeg"),
    _f("gif87a", "GIF87a image", "image", "gif", (_r("GIF87a", _c("474946383761")),),
       "LAYOUT: Header='GIF87a' | LogicalScreen{width:u16le,height:u16le,packed,bg,aspect} | optional global RGB table | image/extension blocks | Trailer=3B. Image{2C,left,top,width,height,packed,optional local table,LZW-min-code-size,subblocks}. CHECK: color-table count=2^(size_code+1); every data-subblock chain ends with size 0; LZW clear/end codes and <=12-bit dictionary.", "gif", media="image/gif"),
    _f("gif89a", "GIF89a image", "image", "gif", (_r("GIF89a", _c("474946383961")),),
       "LAYOUT: Header='GIF89a' | LogicalScreen | optional global palette | blocks. Standard extensions: GraphicControl=21F904{packed,delay:u16le,transparent-index}00; Application=21FF0B{id[8],auth[3],subblocks}; Comment=21FE{subblocks}; image as GIF87a; Trailer=3B. CHECK: block sizes/terminators, palette bounds, LZW stream, frame rectangles.", "gif", media="image/gif"),
    _f("bmp", "Windows Bitmap", "image", "bmp dib", (_r("BMP file header", _c("424D")),),
       "LAYOUT: BITMAPFILEHEADER{BM,size:u32le,reserved[4],pixelOffset:u32le} | DIB selected by headerSize (12 CORE,40 INFO,52/56 masks,108 V4,124 V5) | masks/palette | pixels. INFO{width:i32le,height:i32le,planes=1,bpp:u16le,compression:u32le,imageSize:u32le,...}. CHECK: rowStride=floor((bpp*abs(width)+31)/32)*4; rows bottom-up if height>0; offsets/ranges valid; masks nonoverlap; no checksum.", "bmp", media="image/bmp"),
    _f("tiff-le", "TIFF little-endian", "image", "tif tiff", (_r("TIFF II", _c("49492A00")),),
       "LAYOUT: Header{'II',magic=42:u16le,firstIFD:u32le} | IFD{count:u16le,Entry[count],nextIFD:u32le}; Entry{tag:u16,type:u16,count:u32,value-or-offset[4]}; out-of-line values and strips/tiles. CHECK: typeSize*count decides inline<=4 vs offset; all IFD/value/strip ranges valid; StripOffsets count equals StripByteCounts; no global checksum.", "tiff", media="image/tiff"),
    _f("tiff-be", "TIFF big-endian", "image", "tif tiff", (_r("TIFF MM", _c("4D4D002A")),),
       "LAYOUT: Header{'MM',magic=42:u16be,firstIFD:u32be} | IFD{count:u16be,Entry[count],nextIFD:u32be}; Entry{tag:u16,type:u16,count:u32,value-or-offset[4]}; referenced values/strips/tiles. CHECK: selected big-endian applies throughout; bounds and strip/tile offset-count pairing; no global checksum.", "tiff", media="image/tiff"),
    _f("webp", "WebP image", "image", "webp", (_r("RIFF WEBP", _c("52494646"), _c("57454250", 8)),),
       "LAYOUT: RIFF{'RIFF',size:u32le,'WEBP'} | chunks{id[4],size:u32le,data[size],pad if odd}. Primary VP8 /VP8L/VP8X; VP8X flags + canvasMinusOne[24le] fields; optional ANIM/ANMF, ALPH, ICCP, EXIF, XMP. CHECK: RIFF size=fileSize-8; chunk padding; VP8X feature flags agree with chunks; canvas/frame bounds.", "webp riff", media="image/webp"),
    _f("ico", "Windows icon", "image", "ico", (_r("ICO directory", _c("00000100")),),
       "LAYOUT: ICONDIR{reserved=0:u16le,type=1:u16le,count:u16le} | ICONDIRENTRY[count]{width:u8(0=256),height:u8,colors,reserved,planes:u16,bpp:u16,bytes:u32le,offset:u32le} | image blobs (PNG or DIB with XOR+AND masks). CHECK: every entry range valid/nonoverlapping as required; DIB icon stored height commonly doubles XOR height; embedded PNG validates independently.", "ico png bmp", media="image/x-icon"),
    _f("cursor", "Windows cursor", "image", "cur", (_r("CUR directory", _c("00000200")),),
       "LAYOUT: ICONDIR{reserved=0,type=2,count} | CURSORDIRENTRY[count]{width,height,colors,reserved,hotspotX:u16le,hotspotY:u16le,bytes:u32le,offset:u32le} | PNG/DIB image blobs. CHECK: hotspot lies in image; ranges valid; embedded payload structure validates.", "ico png bmp", media="image/x-icon"),
    _f("psd", "Adobe Photoshop PSD/PSB document", "image", "psd psb", (_r("PSD v1", _c("384250530001")), _r("PSB v2", _c("384250530002"))),
       "LAYOUT: FileHeader{'8BPS',version:u16be=1 PSD|2 PSB,reserved[6]=0,channels:u16be,height:u32be,width:u32be,depth:u16be,colorMode:u16be} | ColorModeData | ImageResources | LayerMask | ImageData{compression:u16be,payload}; PSB uses 64-bit lengths for specified large sections/records. CHECK: version-specific section lengths and even padding; dimensions/channels/depth; RLE row counts (u16 PSD/u32 PSB), ZIP streams; no global checksum.", "psd", media="image/vnd.adobe.photoshop"),
    _f("dds", "DirectDraw Surface", "image", "dds", (_r("DDS", _c("44445320")),),
       "LAYOUT: magic='DDS ' | DDS_HEADER[124]{size=124,flags,height,width,pitchOrLinear,depth,mips,reserved,pixelFormat[32],caps...} | optional DDS_HEADER_DXT10[20] when fourCC='DX10' | subresources ordered array/mip/face/depth. CHECK: required flags/sizes; compute block-compressed mip bytes=max(1,ceil(w/4))*max(1,ceil(h/4))*blockBytes; payload covers all subresources; no checksum.", "dds", media="image/vnd-ms.dds"),
    _f("openexr", "OpenEXR image", "image", "exr", (_r("OpenEXR magic", _c("762F3101")),),
       "LAYOUT: magic:u32le=0x01312F76 | versionField:u32le(flags in high bits) | header attributes repeated{name\0,type\0,size:u32le,value[size]} terminated by zero name | chunk offset table | scanline/tile/deep chunks. CHECK: required channels/compression/dataWindow/displayWindow attributes; offset count derived from mode; per-chunk unpacked sizes and optional ZIP/PIZ/DWA checks; no whole-file checksum.", "exr", media="image/x-exr"),
    _f("radiance-hdr", "Radiance HDR/RGBE", "image", "hdr rgbe", (_r("RADIANCE", _c("233F52414449414E43450A")), _r("RGBE", _c("233F524742450A"))),
       "LAYOUT: signature line '#?RADIANCE' or '#?RGBE' | ASCII header key=value lines | blank line | resolution/orientation line (for example '-Y h +X w') | RGBE scanlines, commonly new RLE marker 02 02 widthHi widthLo then 4 channel runs. CHECK: declared resolution equals decoded pixels; RLE run/literal counts exactly fill each channel row; no checksum.", "radiance", media="image/vnd.radiance"),
    _f("qoi", "Quite OK Image", "image", "qoi", (_r("QOI", _c("716F6966")),),
       "LAYOUT: Header{'qoif',width:u32be,height:u32be,channels:u8=3|4,colorspace:u8} | opcode stream (RGB=FE,RGBA=FF,INDEX=00xxxxxx,DIFF=01xxxxxx,LUMA=10xxxxxx,RUN=11xxxxxx) | endMarker=0000000000000001. State starts rgba(0,0,0,255), index[64]=0. CHECK: exactly width*height pixels; hash=(r*3+g*5+b*7+a*11)%64; run<=62; exact end marker.", "qoi", media="image/qoi"),
    _f("pcx", "ZSoft PCX", "image", "pcx", (),
       "LAYOUT: Header[128]{manufacturer=0A,version,encoding=1,bitsPerPlane,xmin/ymin/xmax/ymax:u16le,dpi,palette16[48],reserved=0,planes,bytesPerLine:u16le,paletteInfo,...} | scanline RLE | optional 0C + RGB[256]. CHECK: probe validates header fields; RLE byte>=C0 means run=(byte&3F),next=value; decoded row=planes*bytesPerLine; 8-bit indexed palette is final 769 bytes.", "pcx", probe="pcx", media="image/vnd.zbrush.pcx"),
    _f("jpeg2000-jp2", "JPEG 2000 JP2", "image", "jp2 jpx", (_r("JP2 signature box", _c("0000000C6A5020200D0A870A")),),
       "LAYOUT: ISO-style boxes{LBox:u32be,TBox[4],optional XLBox:u64be,data}; required signature box{jP  ,0D0A870A}, ftyp, jp2h(superbox containing ihdr and colr), then contiguous jp2c codestream(s). CHECK: box sizes/bounds; signature exact; ihdr dimensions/components agree with codestream SIZ; codestream begins FF4F and ends FFD9; marker-segment lengths.", "jp2", media="image/jp2"),
    _f("jpeg2000-j2k", "JPEG 2000 codestream", "image", "j2k j2c jpc", (_r("J2K SOC+SIZ", _c("FF4FFF51")),),
       "LAYOUT: SOC=FF4F | main-header marker segments beginning SIZ=FF51{Lsiz:u16be,...} | tile-parts SOT=FF90...SOD=FF93 compressed packets | EOC=FFD9. CHECK: marker lengths include length field; SIZ geometry/component sampling valid; tile-part Psot boundaries; packet bit-stuffing and coding-segment rules; no global checksum.", "jp2", media="image/j2c"),
    _f("avif", "AV1 Image File Format", "image", "avif avifs", (),
       "LAYOUT: ISO BMFF boxes; ftyp major/compatible brand 'avif' or 'avis' | meta FullBox containing hdlr,pitm,iloc,iinf/iprp/ipco(ipma), optional grid | mdat/idat item extents with AV1 image items. CHECK: probe reads ftyp brands; all box/extent ranges; item-property associations; ispe dimensions and AV1 sequence header agreement; no global checksum.", "isobmff", probe="isobmff_avif", media="image/avif"),
    _f("heif", "High Efficiency Image File", "image", "heif heic heifs heics hif", (),
       "LAYOUT: ISO BMFF boxes; ftyp brand heic/heix/hevc/hevx/mif1/msf1 | meta{hdlr,pitm,iloc,iinf,iref,iprp} | image item extents in idat/mdat; HEVC variants use hvc1 item + hvcC property. CHECK: probe checks brand; box/extent bounds; primary item exists; property associations and dimensions match coded item; no global checksum.", "isobmff", probe="isobmff_heif", media="image/heif image/heic"),

    # Audio: 21-35
    _f("wav", "RIFF/WAVE audio", "audio", "wav wave", (_r("RIFF WAVE", _c("52494646"), _c("57415645", 8)),),
       "LAYOUT: RIFF{'RIFF',size:u32le,'WAVE'} | chunks{id[4],size:u32le,data[size],pad if odd}; required fmt {format:u16le,channels:u16le,rate:u32le,byteRate:u32le,blockAlign:u16le,bits:u16le,...} before data. CHECK: RIFF size=fileSize-8; chunk bounds/padding; PCM blockAlign=channels*ceil(bits/8), byteRate=rate*blockAlign, dataSize%blockAlign=0; no checksum.", "riff", media="audio/wav"),
    _f("aiff", "Audio Interchange File Format", "audio", "aiff aif", (_r("FORM AIFF", _c("464F524D"), _c("41494646", 8)),),
       "LAYOUT: FORM{'FORM',size:u32be,'AIFF'} | chunks{id[4],size:u32be,data,pad}; COMM{channels:u16be,frames:u32be,sampleBits:u16be,sampleRate:80-bit extended} | SSND{offset:u32be,blockSize:u32be,samples}. CHECK: FORM/chunk bounds and even padding; SSND offset; frame byte count from COMM; no checksum.", "aiff", media="audio/aiff"),
    _f("aifc", "Compressed AIFF", "audio", "aifc aiff aif", (_r("FORM AIFC", _c("464F524D"), _c("41494643", 8)),),
       "LAYOUT: FORM ... 'AIFC' | FVER timestamp | COMM base AIFF fields + compressionType[4] + Pascal compressionName | SSND and optional codec chunks. CHECK: big-endian sizes/even padding; FVER/COMM required; compression payload matches type; frame/sample counts; no checksum.", "aiff", media="audio/aiff"),
    _f("flac", "Free Lossless Audio Codec", "audio", "flac fla", (_r("FLAC", _c("664C6143")),),
       "LAYOUT: 'fLaC' | metadata blocks{last:1,type:7,length:u24be,data}; first STREAMINFO[34]{min/max block, min/max frame, sampleRate:20,channels-1:3,bps-1:5,totalSamples:36,MD5[16]} | audio frames{sync/header,subframes,CRC16}. CHECK: metadata lengths/order; header CRC8 poly07; frame CRC16 poly8005; STREAMINFO MD5 of decoded interleaved PCM; frame/sample counts.", "flac", media="audio/flac"),
    _f("ogg-vorbis", "Ogg Vorbis audio", "audio", "ogg oga", (_r("Ogg", _c("4F67675300")),),
       "LAYOUT: Ogg pages{'OggS',version=0,headerType,granule:i64le,serial:u32le,sequence:u32le,crc:u32le,segments:u8,lacing[segments],payload}; first packet begins 01+'vorbis', then comment 03, setup 05. CHECK: probe finds Vorbis packet; page CRC32 with checksum zero using Ogg polynomial; lacing reconstructs packets; sequence/serial/granule continuity; Vorbis setup references.", "ogg vorbis", probe="ogg_vorbis", media="audio/ogg"),
    _f("ogg-opus", "Ogg Opus audio", "audio", "opus ogg oga", (_r("Ogg", _c("4F67675300")),),
       "LAYOUT: Ogg pages as RFC3533; first packet OpusHead{magic[8],version,channels,preSkip:u16le,inputRate:u32le,gain:i16le,mappingFamily,...}; second OpusTags; audio packets. CHECK: probe finds OpusHead in first page; Ogg page CRC/sequence/lacing; channel mapping lengths; final granule minus preSkip determines PCM duration.", "ogg opus", probe="ogg_opus", media="audio/ogg audio/opus"),
    _f("mp3", "MPEG Layer III audio", "audio", "mp3", (_r("ID3-prefixed MP3", _c("494433")), _r("MPEG audio sync", _c("FFE0", mask="FFE0"))),
       "LAYOUT: optional ID3v2{ID3,version,flags,syncsafeSize,frames} | MPEG frames{sync:11,version:2,layer:2,protection,bitrateIndex:4,sampleIndex:2,padding,channelMode,...,optionalCRC,payload}. CHECK: syncsafe bytes high bit zero; frameLength=floor(coefficient*bitrate/sampleRate)+padding (144 for MPEG1 LayerIII); optional CRC16; consecutive frames agree; optional ID3v1 at tail.", "mp3", media="audio/mpeg"),
    _f("m4a", "MPEG-4 audio container", "audio", "m4a m4b m4p", (),
       "LAYOUT: ISO BMFF boxes; ftyp brand M4A /M4B /isom | moov{mvhd,trak{tkhd,mdia{mdhd,hdlr='soun',minf{stbl{stsd,stts,stsc,stsz,stco/co64}}}}} | mdat. CHECK: probe checks ftyp audio brand; recursive box sizes; sample tables produce valid offsets/sizes/timestamps; codec config (esds/alac) matches samples; no global checksum.", "isobmff", probe="isobmff_m4a", media="audio/mp4"),
    _f("midi", "Standard MIDI File", "audio", "mid midi kar", (_r("MIDI header", _c("4D54686400000006")),),
       "LAYOUT: MThd{length:u32be=6,format:u16be,nTracks:u16be,division:u16be} | n MTrk{length:u32be,eventBytes[length]}; events use delta-time VLQ then MIDI/status-running-status, SysEx, or FF meta type + VLQ length. CHECK: track lengths exact; VLQ<=4 bytes for SMF delta; running status only channel messages; each track ends FF2F00; no checksum.", "midi", media="audio/midi"),
    _f("au", "Sun/NeXT AU audio", "audio", "au snd", (_r("AU .snd", _c("2E736E64")),),
       "LAYOUT: Header{magic='.snd',dataOffset:u32be,dataSize:u32be(FFFFFFFF unknown),encoding:u32be,sampleRate:u32be,channels:u32be} | annotation[dataOffset-24] | audio. CHECK: offset>=24 and aligned as required; known size in-file; sample frames compatible with encoding/channels; no checksum.", "au", media="audio/basic"),
    _f("amr-nb", "AMR narrowband storage", "audio", "amr", (_r("AMR-NB", _c("2321414D520A")),),
       "LAYOUT: magic '#!AMR\n' | frames{toc:u8(F:1,FT:4,Q:1,P:2),speechBytes[sizeByFT]}; storage files normally F=0. CHECK: reserved bits zero; FT valid and payload length exact; Q indicates frame quality; no checksum in storage framing.", "amr", media="audio/amr"),
    _f("amr-wb", "AMR wideband storage", "audio", "awb amr", (_r("AMR-WB", _c("2321414D522D57420A")),),
       "LAYOUT: magic '#!AMR-WB\n' | repeated frame{TOC:u8 with F:1,FT:4,Q:1,padding:2; speech payload length selected by FT according to 3GPP TS 26.101}. Single-channel storage normally has F=0. CHECK: FT is speech/SID/no-data mode with its exact bit count, unused final bits and TOC padding are zero, every frame is complete; Q reports quality; no container checksum.", "amr", media="audio/amr-wb"),
    _f("ape", "Monkey's Audio", "audio", "ape", (_r("Monkey's Audio", _c("4D414320")),),
       "LAYOUT: 'MAC ' + version:u16le; modern >=3980: descriptor{padding,descriptorBytes,headerBytes,seekTableBytes,wavHeaderBytes,audioDataBytes:u32/u64,wavTailBytes,MD5[16]} | header{compression,flags,blocksPerFrame,finalBlocks,totalFrames,bits,channels,rate} | seek table | frames. CHECK: section sizes/offsets; total PCM blocks; descriptor MD5 where defined; frame CRC fields.", "ape", media="audio/ape"),
    _f("wavpack", "WavPack", "audio", "wv", (_r("WavPack block", _c("7776706B")),),
       "LAYOUT: repeated blocks{ckID='wvpk',ckSize:u32le,version:u16le,track,index,totalSamples:u32le,blockIndex:u32le,blockSamples:u32le,flags:u32le,crc:u32le,metadata subblocks}. CHECK: ckSize+8 block boundary; block sample ranges contiguous; metadata word sizes; CRC is rolling checksum of decoded samples; optional correction .wvc pairs by block.", "wavpack", media="audio/wavpack"),
    _f("caf", "Apple Core Audio Format", "audio", "caf", (_r("CAF v1", _c("6361666600010000")),),
       "LAYOUT: FileHeader{'caff',version:u16be=1,flags:u16be} | chunks{type[4],size:i64be,data}; first desc[32]{sampleRate:f64be,formatID[4],flags:u32be,bytesPerPacket:u32be,framesPerPacket:u32be,channels:u32be,bits:u32be}; data chunk begins editCount:u32be. CHECK: chunk bounds; desc and data required; size=-1 only for final data; packet table required for VBR/VFR; no global checksum.", "caf", media="audio/x-caf"),

    # Video and containers: 36-50
    _f("mp4", "MPEG-4 / ISO BMFF", "video", "mp4 m4v f4v", (),
       "LAYOUT: boxes{size:u32be,type[4],optional largeSize:u64be,payload}; ftyp identifies brand | moov{mvhd,trak... sample tables} | mdat media. FullBox begins version:u8+flags:u24. CHECK: probe checks ftyp MP4 brands; every nested size; stts/stsc/stsz/stco or co64 jointly map all samples; durations/timescales; no global checksum.", "isobmff", probe="isobmff_mp4", media="video/mp4"),
    _f("quicktime", "QuickTime movie", "video", "mov qt", (),
       "LAYOUT: ISO BMFF/QuickTime atoms{size:u32be,type,optional extended}; ftyp brand 'qt  ' or legacy files begin wide/moov/mdat; moov contains mvhd and tracks. CHECK: probe recognizes qt brand/atom sequence; recursive atom bounds; sample tables and chunk offsets; no global checksum.", "isobmff", probe="isobmff_quicktime", media="video/quicktime"),
    _f("matroska", "Matroska container", "video", "mkv mka mks mk3d", (_r("EBML", _c("1A45DFA3")),),
       "LAYOUT: EBML elements{ID-VINT,size-VINT,data}; EBML header DocType='matroska' | Segment{SeekHead,Info,Tracks,Cluster,Cues,Attachments,Chapters,Tags}. Cluster contains Timecode and SimpleBlock/BlockGroup; block has track VINT,timecode:i16be,flags,lacing,frames. CHECK: probe parses DocType; VINT canonical widths/parent bounds; optional CRC-32 element covers parent excluding itself; lacing sizes sum exactly.", "ebml matroska", probe="ebml_matroska", media="video/x-matroska"),
    _f("webm", "WebM container", "video", "webm weba", (_r("EBML", _c("1A45DFA3")),),
       "LAYOUT: EBML header DocType='webm' | Matroska-derived Segment with restricted codec/features; Tracks + Clusters + Cues. CHECK: probe parses DocType; EBML boundaries/CRC; WebM codec IDs and feature restrictions; block lacing/timecodes.", "ebml matroska", probe="ebml_webm", media="video/webm"),
    _f("avi", "Audio Video Interleave", "video", "avi", (_r("RIFF AVI", _c("52494646"), _c("41564920", 8)),),
       "LAYOUT: RIFF{'RIFF',size,'AVI '} | LIST hdrl{avih,LIST strl{strh,strf,...}} | LIST movi{##dc/##db/##wb chunks} | optional idx1/OpenDML indexes. CHECK: RIFF/list/chunk sizes and even padding; stream counts/scale-rate/sample sizes; indexes point to matching movi chunks; no checksum.", "riff", media="video/x-msvideo"),
    _f("flv", "Flash Video", "video", "flv", (_r("FLV", _c("464C5601")),),
       "LAYOUT: Header{'FLV',version=1,flags,dataOffset:u32be} | PreviousTagSize0:u32be=0 | tags{type:u8,dataSize:u24be,timestamp:u24be+ext,streamID:u24=0,data,previousSize:u32be}. Audio/video payload begins codec flags; script uses AMF. CHECK: every PreviousTagSize=11+dataSize; timestamps and payload sizes; codec packet headers; no global checksum.", "flv", media="video/x-flv"),
    _f("mpeg-ps", "MPEG Program Stream", "video", "mpg mpeg vob ps", (_r("Pack start", _c("000001BA")),),
       "LAYOUT: pack header 000001BA{SCR,muxRate,stuffing} | optional system header 000001BB | PES packets{000001,streamID,length:u16be,flags/header,timestamps,payload} | program end 000001B9. CHECK: start-code scanning; marker bits; PTS/DTS 33-bit marker layout; packet lengths and pack stuffing; optional CRC in program stream map.", "mpeg", media="video/mpeg"),
    _f("mpeg-ts", "MPEG Transport Stream", "video", "ts m2ts mts", (),
       "LAYOUT: fixed packets 188 bytes (or 192 M2TS with 4-byte prefix), each{sync=47,TEI/PUSI/priority/PID:13,scrambling:2,adaptationControl:2,continuity:4,adaptation?,payload}; PSI sections PAT/PMT use sectionLength. CHECK: probe sees sync cadence; continuity counters per PID; adaptation lengths; PSI MPEG-2 CRC32 poly04C11DB7; section/PES boundaries.", "mpeg", probe="mpeg_ts", media="video/mp2t"),
    _f("ivf", "IVF video container", "video", "ivf", (_r("IVF", _c("444B4946")),),
       "LAYOUT: Header{'DKIF',version:u16le=0,headerSize:u16le=32,fourcc[4],width:u16le,height:u16le,timebaseDen:u32le,timebaseNum:u32le,frameCount:u32le,unused:u32le} | frames{size:u32le,timestamp:u64le,data[size]}. CHECK: header size/version; frame bounds/count; timestamps in timebase; codec payload validates separately; no checksum.", "ivf", media="video/x-ivf"),
    _f("asf", "Advanced Systems Format", "video", "asf wmv wma", (_r("ASF header GUID", _c("3026B2758E66CF11A6D900AA0062CE6C")),),
       "LAYOUT: objects{GUID[16],size:u64le including header,data}; Header Object includes objectCount:u32le,reserved[2] then FileProperties,StreamProperties,...; Data Object contains packets; optional indexes. CHECK: GUID object sizes >=24/in-file; header count; packet size/timing; file ID consistency; no global checksum.", "asf", media="video/x-ms-asf"),
    _f("ogg-theora", "Ogg Theora video", "video", "ogv ogg", (_r("Ogg", _c("4F67675300")),),
       "LAYOUT: Ogg pages; first Theora packet begins 80+'theora' identification, then 81 comment, 82 setup; video data packets follow. CHECK: probe finds Theora signature; Ogg page CRC/lacing/sequence/granule; header dimensions/fps; granule keyframe shift semantics.", "ogg", probe="ogg_theora", media="video/ogg"),
    _f("3gp", "3GPP multimedia container", "video", "3gp 3gpp 3g2", (),
       "LAYOUT: ISO BMFF boxes with ftyp brands 3gp*/3g2* | moov tracks | mdat samples; mobile-specific codecs/config boxes. CHECK: probe checks brand; nested box/sample-table bounds; timescales/durations; codec configuration and samples; no global checksum.", "isobmff", probe="isobmff_3gp", media="video/3gpp video/3gpp2"),
    _f("mxf", "Material Exchange Format", "video", "mxf", (_r("SMPTE UL prefix", _c("060E2B34")),),
       "LAYOUT: KLV triplets{key:UL[16],length:BER,data[length]}; partitions start SMPTE partition-pack UL and contain header metadata, index tables, essence containers; Random Index Pack near end. CHECK: UL/BER canonical parsing; KLV bounds; partition offsets/bodySID/indexSID; metadata strong references; RIP length; optional essence checks codec-defined.", "mxf", media="application/mxf"),
    _f("realmedia", "RealMedia", "video", "rm rmvb ra", (_r("RealMedia", _c("2E524D46")),),
       "LAYOUT: .RMF object{size:u32be,version:u16be,fileVersion:u32be,numHeaders:u32be} | PROP,MDPR,CONT,DATA,INDX objects, each id[4]+size:u32be+version:u16be; DATA packets carry stream,time,flags,payload. CHECK: object/packet sizes; header count; data/index offsets and timestamps; no global checksum.", "real", media="application/vnd.rn-realmedia"),
    _f("swf", "Shockwave Flash", "video", "swf", (_r("SWF uncompressed", _c("465753")), _r("SWF zlib", _c("435753")), _r("SWF LZMA", _c("5A5753"))),
       "LAYOUT: signature FWS/CWS/ZWS + version:u8 + uncompressedFileLength:u32le | RECT bitfield | frameRate:u16le fixed8.8 | frameCount:u16le | tags{code:10,length:6 or 3F+u32le,data}. CWS compresses bytes after first 8 with zlib; ZWS uses LZMA framing. CHECK: decompressed length; tag bounds; End tag; codec checksum from zlib/LZMA where applicable.", "swf", media="application/x-shockwave-flash"),

    # Archives and compression: 51-65
    _f("zip", "ZIP/ZIP64 archive", "archive", "zip zipx jar apk ipa cbz whl xpi vsix odt ods odp", (_r("ZIP local", _c("504B0304")), _r("ZIP empty", _c("504B0506")), _r("ZIP spanned", _c("504B0708"))),
       "LAYOUT: local records 504B0304{version,flags,method,time,date,crc32,cSize,uSize,nameLen,extraLen,name,extra,data,optional descriptor} | central records 504B0102 | optional ZIP64 EOCD/locator | EOCD 504B0506. CHECK: CRC32 over uncompressed member; central/local metadata and offsets agree; ZIP64 saturated fields resolved from extra 0001; DEFLATE validates; directory bounds/counts.", "zip", media="application/zip"),
    _f("rar4", "RAR 1.5-4.x archive", "archive", "rar cbr", (_r("RAR4", _c("526172211A0700")),),
       "LAYOUT: signature[7] | blocks{headCRC:u16le,type:u8,flags:u16le,headSize:u16le,optional addSize:u32le,typeHeader,data}; main type=73, file=74, end=7B. CHECK: HeadCRC=CRC32(bytes type through end header)&FFFF; head/data sizes; file CRC32 of unpacked data; encrypted/compressed data algorithm-specific.", "rar", media="application/vnd.rar"),
    _f("rar5", "RAR 5.x archive", "archive", "rar cbr", (_r("RAR5", _c("526172211A070100")),),
       "LAYOUT: signature[8] | blocks{headerCRC32:u32le,headerSize:vint,type:vint,flags:vint,optional extraSize:vint,optional dataSize:vint,typeFields,extraRecords,data}; type 1 main,2 file,3 service,4 encryption,5 end. CHECK: CRC32 from HeaderSize through extra-area end; vint LSB-first 7-bit groups <=10 bytes; headerSize<=2MiB current; data/extras bounds; optional BLAKE2sp/file hashes.", "rar", media="application/vnd.rar"),
    _f("7z", "7-Zip archive", "archive", "7z cb7", (_r("7z", _c("377ABCAF271C")),),
       "LAYOUT: SignatureHeader{magic[6],major,minor,startHeaderCRC:u32le,nextHeaderOffset:u64le,nextHeaderSize:u64le,nextHeaderCRC:u32le} | packed streams | next header encoded as 7z property-ID/value trees. CHECK: StartHeaderCRC over nextOffset/size/CRC fields; NextHeaderCRC; folder coder/bind graph; packed/unpacked sizes; optional per-stream CRC.", "7z", media="application/x-7z-compressed"),
    _f("gzip", "gzip member stream", "archive", "gz tgz svgz", (_r("gzip", _c("1F8B08")),),
       "LAYOUT: repeated member{Header{1F8B,CM=8,FLG,MTIME:u32le,XFL,OS,optional XLEN+extra,name0,comment0,FHCRC:u16le},DEFLATE stream,Trailer{CRC32:u32le,ISIZE:u32le}}. CHECK: reserved flags zero; FHCRC=low16(CRC32 header); DEFLATE final block; CRC32 uncompressed member; ISIZE=size mod 2^32.", "gzip", media="application/gzip"),
    _f("bzip2", "bzip2 stream", "archive", "bz2 tbz tbz2", (_r("bzip2", _c("425A68")),),
       "LAYOUT: 'BZh'+blockSizeChar '1'..'9' | blocks magic 314159265359 + blockCRC + randomized + origPtr + BWT/MTF/Huffman data | end magic 177245385090 + combinedCRC. CHECK: per-block CRC32 bzip polynomial; combinedCRC=rotate-left(prev,1) XOR blockCRC; selectors/tables/runs bounds; declared block size.", "bzip2", media="application/x-bzip2"),
    _f("xz", "XZ compressed stream", "archive", "xz txz", (_r("XZ", _c("FD377A585A00")),),
       "LAYOUT: StreamHeader{magic[6],flags[2],CRC32[4]} | Blocks{headerSize,flags,optional sizes,filter chain,headerCRC,padding,compressed data,check} | Index{00,records VLI,padding,CRC32} | Footer{CRC32,backwardSize,flags,'YZ'}. CHECK: header/footer flag match; CRC32 fields; VLI canonical; block padding; selected Check (none/CRC32/CRC64/SHA256); index sums/sizes.", "xz", media="application/x-xz"),
    _f("zstd", "Zstandard frame", "archive", "zst zstd", (_r("Zstandard", _c("28B52FFD")),),
       "LAYOUT: magic 28B52FFD | FrameHeader{descriptor,optional window,dictID,contentSize} | blocks{last:1,type:2,size:21,payload} | optional checksum:u32le; skippable frames use magic 184D2A50..5F + size. CHECK: block sizes/window; entropy tables; content size; checksum=low32(XXH64 decoded content) when flag set.", "zstd", media="application/zstd"),
    _f("lz4-frame", "LZ4 frame", "archive", "lz4", (_r("LZ4 frame", _c("04224D18")),),
       "LAYOUT: magic | FLG | BD | optional contentSize:u64le | optional dictID:u32le | HC:u8 | blocks{size:u32le(high bit=raw),data} | zero endMark | optional contentChecksum. CHECK: HC=(XXH32(descriptor)>>8)&FF; optional block/content XXH32; max block size from BD; content size; block dependency flag.", "lz4", media="application/vnd.lz4"),
    _f("tar", "POSIX tar archive", "archive", "tar", (_r("ustar header", _c("7573746172", 257)),),
       "LAYOUT: 512-byte headers{name[100],mode[8],uid[8],gid[8],size[12] octal,mtime[12],checksum[8],typeflag,linkname[100],magic='ustar',version,...} | file data padded to 512 | ... | two zero blocks. CHECK: header checksum=sum all 512 unsigned bytes with checksum field treated as spaces; numeric fields; size padding; PAX/GNU extension records; end markers.", "tar", probe="tar", media="application/x-tar"),
    _f("cpio-newc", "cpio new ASCII archive", "archive", "cpio", (_r("newc", _c("303730373031")), _r("newc CRC", _c("303730373032"))),
       "LAYOUT: repeated ASCII header[110]{magic='070701'|'070702',13 fields each 8 hex including namesize/filesize/check} | name including NUL | pad to 4 | data | pad to 4; ends name 'TRAILER!!!'. CHECK: field hex widths; alignment/ranges; for 070702 check=sum of file-data bytes modulo 2^32.", "cpio", media="application/x-cpio"),
    _f("unix-ar", "Unix ar archive", "archive", "a ar deb", (_r("ar", _c("213C617263683E0A")),),
       "LAYOUT: global '!<arch>\n' | members Header[60]{name[16],date[12],uid[6],gid[6],mode[8],size[10],end='`\n'} + data[size] + '\n' pad if odd; GNU/BSD long-name tables extend names. CHECK: decimal/octal ASCII parsing; 60-byte header marker; member bounds/even alignment; symbol table offsets; no checksum.", "ar", media="application/x-archive"),
    _f("cab", "Microsoft Cabinet", "archive", "cab", (_r("MSCF", _c("4D534346")),),
       "LAYOUT: CFHEADER{'MSCF',reserved,cbCabinet:u32le,reserved,coffFiles:u32le,reserved,versionMinor,Major,cFolders:u16le,cFiles:u16le,flags,setID,iCabinet,optional} | CFFOLDER[] | CFFILE[] | CFDATA blocks. CHECK: cabinet/folder/file offsets; CFDATA checksum (XOR-folded 32-bit over size fields and data) when nonzero; compressed/uncompressed block sizes; folder codec state.", "cab", media="application/vnd.ms-cab-compressed"),
    _f("iso9660", "ISO 9660 filesystem image", "archive", "iso", (_r("ISO PVD", _c("4344303031", 32769)),),
       "LAYOUT: system area sectors 0..15 | volume descriptors from sector16, each{type:u8,id='CD001',version=1,data[2041]} until type255 | path tables | directory records{length,extent both-endian,size both-endian,time,flags,...name}. CHECK: probe needs >=32774 header bytes; LE/BE duplicate values agree; extents within volume; directory record lengths/padding; optional descriptor checks.", "iso9660", media="application/x-iso9660-image"),
    _f("rpm", "RPM package", "archive", "rpm", (_r("RPM lead", _c("EDABEEDB")),),
       "LAYOUT: Lead[96]{magic,major,minor,type,arch,name[66],os,signatureType,reserved} | Signature Header{8EAD E801,version,reserved,indexCount:u32be,dataSize:u32be,index[],store} padded to 8 | Main Header same | compressed cpio payload. CHECK: header index offset/type/count bounds; signature digests over defined regions; decompressed cpio checks; payload compressor framing.", "rpm", media="application/x-rpm"),

    # Executables and binary modules: 66-80
    _f("elf32-le", "ELF 32-bit little-endian", "executable", "elf o so ko", (_r("ELF32 LE", _c("7F454C46010101")),),
       "LAYOUT: e_ident[16]{magic,class=1,data=1,version=1,ABI,...} | Elf32_Ehdr body{type:u16le,machine:u16le,version:u32le,entry:u32le,phoff:u32le,shoff:u32le,flags:u32le,ehsize=52,phentsize,phnum,shentsize,shnum,shstrndx} | program/section tables. CHECK: table arithmetic/bounds/alignment; segment fileSize<=memSize; section/string/symbol links; no global checksum.", "elf", media="application/x-elf"),
    _f("elf64-le", "ELF 64-bit little-endian", "executable", "elf o so ko", (_r("ELF64 LE", _c("7F454C46020101")),),
       "LAYOUT: e_ident class=2,data=1 | Elf64_Ehdr{type:u16le,machine:u16le,version:u32le,entry/phoff/shoff:u64le,flags:u32le,ehsize=64,...} | Elf64_Phdr[phnum] | sections/Elf64_Shdr[shnum]. CHECK: offsets/counts/entry sizes; load segments and sections within file; link/info indices; no global checksum.", "elf", media="application/x-elf"),
    _f("elf32-be", "ELF 32-bit big-endian", "executable", "elf o so ko", (_r("ELF32 BE", _c("7F454C46010201")),),
       "LAYOUT: e_ident class=1,data=2 | 52-byte Elf32 header and all multibyte program/section/symbol/relocation fields big-endian. CHECK: same ELF table/segment/section invariants; no global checksum.", "elf", media="application/x-elf"),
    _f("elf64-be", "ELF 64-bit big-endian", "executable", "elf o so ko", (_r("ELF64 BE", _c("7F454C46020201")),),
       "LAYOUT: e_ident class=2,data=2 | 64-byte Elf64 header and all table fields big-endian | program headers | section data/headers. CHECK: offsets/counts/alignments/ranges and linked-table indices; no global checksum.", "elf", media="application/x-elf"),
    _f("pe32", "Windows PE32 image", "executable", "exe dll sys ocx scr efi", (_r("MZ", _c("4D5A")),),
       "LAYOUT: DOS header MZ with e_lfanew:u32le@3C | 'PE\0\0' | COFF[20] | OptionalHeader magic=010B bytes (value 0x10B), standard+Windows fields, DataDirectory[NumberOfRvaAndSizes] | SectionHeader[40]*N | sections/overlay. CHECK: probe follows e_lfanew; header/table/range/alignment; RVA mapping; PE checksum; Authenticode excludes checksum/security directory/certificate bytes.", "pe", probe="pe32", media="application/vnd.microsoft.portable-executable"),
    _f("pe32plus", "Windows PE32+ image", "executable", "exe dll sys ocx scr efi", (_r("MZ", _c("4D5A")),),
       "LAYOUT: DOS MZ/e_lfanew | PE signature | COFF | OptionalHeader magic=020B bytes (value 0x20B), no BaseOfData, ImageBase/stack/heap sizes u64le, directories begin offset112 | section table/data. CHECK: dynamic probe; COFF/optional-size agreement; alignments/RVA ranges; PE checksum and Authenticode coverage.", "pe", probe="pe32plus", media="application/vnd.microsoft.portable-executable"),
    _f("macho32-le", "Mach-O 32-bit little-endian", "executable", "macho dylib bundle", (_r("Mach-O 32 LE", _c("CEFAEDFE")),),
       "LAYOUT: mach_header{magic=FEEDFACE stored LE,cputype:i32le,cpusubtype:i32le,filetype:u32,ncmds:u32,sizeofcmds:u32,flags:u32} | load_command[ncmds]{cmd,cmdsize,...} | segments/sections/linkedit. CHECK: command sizes aligned and sum sizeofcmds; file ranges/VM ranges; symbol/string tables; no global checksum (code signature is a load-command blob).", "macho", media="application/x-mach-binary"),
    _f("macho64-le", "Mach-O 64-bit little-endian", "executable", "macho dylib bundle", (_r("Mach-O 64 LE", _c("CFFAEDFE")),),
       "LAYOUT: mach_header_64[32]{magic=FEEDFACF stored LE,cputype,cpusubtype,filetype,ncmds,sizeofcmds,flags,reserved} | load commands | segment_command_64 with section_64 arrays | linkedit. CHECK: command alignment=8, sum/bounds; section offsets; relocations/symbols; optional LC_CODE_SIGNATURE superblob integrity.", "macho", media="application/x-mach-binary"),
    _f("macho32-be", "Mach-O 32-bit big-endian", "executable", "macho", (_r("Mach-O 32 BE", _c("FEEDFACE")),),
       "LAYOUT: 28-byte mach_header and load-command graph in big-endian; 32-bit segment/section records. CHECK: ncmds/sizeofcmds, command alignment/ranges, section and linkedit tables; no whole-file checksum.", "macho", media="application/x-mach-binary"),
    _f("macho64-be", "Mach-O 64-bit big-endian", "executable", "macho", (_r("Mach-O 64 BE", _c("FEEDFACF")),),
       "LAYOUT: 32-byte mach_header_64 and 64-bit load commands/segments in big-endian. CHECK: command/range/alignment and linked-table invariants; optional code-signature blob; no general checksum.", "macho", media="application/x-mach-binary"),
    _f("macho-fat", "Mach-O universal/fat binary", "executable", "macho fat", (_r("Fat32 BE", _c("CAFEBABE")), _r("Fat32 swapped", _c("BEBAFECA")), _r("Fat64 BE", _c("CAFEBABF")), _r("Fat64 swapped", _c("BFBAFECA"))),
       "LAYOUT: fat_header{magic,nfat_arch:u32 selected-endian} | fat_arch[n]{cputype,cpusubtype,offset:u32/64,size:u32/64,align:u32[,reserved]} | embedded Mach-O slices. CHECK: probe distinguishes Java CAFEBABE using plausible arch table; slice offsets aligned to 2^align, nonoverlap/in-file; each embedded Mach-O validates.", "macho", probe="macho_fat", media="application/x-mach-binary"),
    _f("wasm", "WebAssembly binary module", "executable", "wasm", (_r("Wasm v1", _c("0061736D01000000")),),
       "LAYOUT: magic 0061736D + version:u32le=1 | sections{id:u8,payloadLen:ULEB128,payload}; custom id0 anywhere, standard ids 1..13 ordered at most once. Vectors are ULEB count + items; code bodies size-prefixed. CHECK: canonical LEB128/ranges; section order/lengths; type/function/code counts; index bounds; expression termination/type validation.", "wasm", media="application/wasm"),
    _f("dex", "Android DEX", "executable", "dex", (_r("DEX", _c("6465780A")),),
       "LAYOUT: Header[112]{magic 'dex\nNNN\0',checksum:u32le,SHA1[20],fileSize,headerSize=70h,endianTag=12345678h,link,map,string/type/proto/field/method/class sizes+offsets,dataSize,dataOff} | ID tables | class/data/map. CHECK: Adler32 bytes[12..EOF]; SHA-1 bytes[32..EOF]; all tables sorted where required/aligned/in-file; map agrees; ULEB/SLEB and encoded-item bounds.", "dex", media="application/vnd.android.dex"),
    _f("java-class", "Java class file", "executable", "class", (_r("Class magic", _c("CAFEBABE")),),
       "LAYOUT: magic CAFEBABE | minor:u16be,major:u16be | constant_pool_count:u16be + variable cp entries (Long/Double consume two slots) | access,this,super,interfaces | fields | methods | attributes{nameIndex:u16,length:u32be,info}. CHECK: probe rejects plausible Mach fat header; cp tags/indices/types; attribute lengths; bytecode instruction/branch/stack-map verification; no checksum.", "jvm", probe="java_class", media="application/java-vm"),
    _f("llvm-bitcode", "LLVM bitcode", "executable", "bc", (_r("Raw bitcode", _c("4243C0DE")), _r("Bitcode wrapper", _c("DEC0170B"))),
       "LAYOUT: raw magic 'BC C0 DE' then bitstream of 32-bit words with ENTER_SUBBLOCK/END_BLOCK/DEFINE_ABBREV/UNABBREV_RECORD codes and VBR fields; optional wrapper{magic,version,offset,size,cpuType} points to raw bitcode. CHECK: wrapper bounds; bit alignment; block lengths/IDs/abbreviations; module record references; no global checksum.", "llvm", media="application/x-llvm"),

    # Documents, structured data, fonts and captures: 81-100
    _f("pdf", "Portable Document Format", "document", "pdf", (_r("PDF header", _c("255044462D")),),
       "LAYOUT: %PDF-x.y line | indirect objects 'n g obj value endobj'; stream=dict then 'stream' EOL exactly /Length bytes 'endstream' | classic xref+trailer or /Type/XRef stream | startxref byte offset | %%EOF. CHECK: token/string grammar; stream lengths; xref offsets or /W entries; /Prev chain; trailer /Size,/Root; startxref target; filter checksums codec-defined.", "pdf", media="application/pdf"),
    _f("rtf", "Rich Text Format", "document", "rtf", (_r("RTF", _c("7B5C727466")),),
       "LAYOUT: ASCII/ANSI control stream begins '{\\rtfN'; groups {...}; control word='\\'+letters+optional signed decimal+optional delimiter; control symbol two bytes; '\\binN' consumes exactly N raw bytes; text encoding from ansicpg/font tables. CHECK: balanced braces excluding escaped/bin bytes; numeric bounds; destination skipping via \\*; no checksum.", "rtf", media="application/rtf"),
    _f("postscript", "PostScript/EPS", "document", "ps eps", (_r("PostScript", _c("25215053")),),
       "LAYOUT: starts '%!PS-Adobe-' commonly; DSC comments '%%Key: value'; token stream of names,numbers,strings,arrays,dictionaries,procedures; EPS BoundingBox and one-page constraints; optional binary sections declared by DSC. CHECK: lexical string/comment nesting, declared BeginBinary/BeginData lengths, DSC trailer consistency; executable language has no global checksum.", "postscript", media="application/postscript"),
    _f("epub", "EPUB publication", "document", "epub", (_r("ZIP", _c("504B0304")),),
       "LAYOUT: ZIP container; first local entry must be uncompressed 'mimetype' with exact data 'application/epub+zip'; META-INF/container.xml points to package document; OPF manifest/spine links XHTML/CSS/assets; EPUB3 navigation document. CHECK: probe scans ZIP prefix; ZIP CRC/central directory; mimetype position/method/content; XML well-formedness; every referenced resource and media type.", "epub zip", probe="zip_epub", media="application/epub+zip"),
    _f("docx", "Office Open XML Word document", "document", "docx docm dotx dotm", (_r("ZIP", _c("504B0304")),),
       "LAYOUT: OPC ZIP package with [Content_Types].xml, _rels/.rels and word/document.xml; parts use relationship files; styles, numbering, media, headers, VBA optional. CHECK: probe sees word/ markers; ZIP CRC/directory; OPC part-name/content-type rules; relationship targets; XML schemas; macro extension/content consistency.", "ooxml zip", probe="zip_docx", media="application/vnd.openxmlformats-officedocument.wordprocessingml.document"),
    _f("xlsx", "Office Open XML spreadsheet", "document", "xlsx xlsm xltx xltm", (_r("ZIP", _c("504B0304")),),
       "LAYOUT: OPC ZIP with [Content_Types].xml, xl/workbook.xml, worksheets/sheet*.xml, sharedStrings/styles and relationships; cell values keyed by type/style. CHECK: probe sees xl/; ZIP/OPC integrity; workbook-sheet relationship IDs; cell refs/order/dimensions; shared-string/style indices; macro consistency.", "ooxml zip", probe="zip_xlsx", media="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"),
    _f("pptx", "Office Open XML presentation", "document", "pptx pptm potx potm ppsx ppsm", (_r("ZIP", _c("504B0304")),),
       "LAYOUT: OPC ZIP with ppt/presentation.xml, slide masters/layouts, slides/slideN.xml, notes/media and relationships. CHECK: probe sees ppt/; ZIP CRC/directory; OPC content types/relationships; slide ID/order and target parts; XML schemas; macro consistency.", "ooxml zip", probe="zip_pptx", media="application/vnd.openxmlformats-officedocument.presentationml.presentation"),
    _f("ole-cfb", "Microsoft Compound File Binary", "document", "doc xls ppt msi msg vsd cfb", (_r("CFB", _c("D0CF11E0A1B11AE1")),),
       "LAYOUT: Header[512/4096]{signature,CLSID,minor,major,byteOrder=FFFE,sectorShift,miniShift,FAT counts,firstDir,transactionSig,miniCutoff,firstMiniFAT,count,firstDIFAT,count,DIFAT[109]} | sectors linked by FAT/DIFAT | directory red-black tree | mini stream. CHECK: sector IDs/ranges; FAT chains terminate/no cycles; counts; directory tree/color/order; stream sizes/chains; no global checksum.", "cfb", media="application/x-ole-storage"),
    _f("sqlite3", "SQLite 3 database", "database", "sqlite sqlite3 db3 db", (_r("SQLite", _c("53514C69746520666F726D6174203300")),),
       "LAYOUT: Header[100]{magic,pageSize:u16be,read/write versions,reserved,payload fractions,change counter,pageCount,freelist,schemaCookie/format,encoding,...} | fixed pages; page1 btree header at100, others at0; btree cells use varints/records/overflow. CHECK: page size power2 512..65536; page/file counts; btree/freeblock/cell bounds; serial-type payload sizes; overflow/freelist chains; no database-wide checksum.", "sqlite", media="application/vnd.sqlite3"),
    _f("json", "JSON text", "data", "json jsonl ndjson", (),
       "LAYOUT: UTF-8 text (RFC8259 interoperable form) containing one value: object, array, string, number, true, false, or null; object members string ':' value separated by commas; JSONL/NDJSON uses one value per line by convention. CHECK: probe skips UTF-8 BOM/whitespace and checks leading token; complete grammar/escapes/surrogate pairs/number form; duplicate-name policy is application-defined; no checksum.", "json", probe="json", media="application/json application/x-ndjson"),
    _f("xml", "Extensible Markup Language", "data", "xml xsd xsl xslt plist", (),
       "LAYOUT: optional BOM + optional XML declaration '<?xml version=... encoding=...?>' | prolog/DOCTYPE | exactly one document element with nested start/end/empty tags, attributes, text, CDATA, comments, PI | trailing misc. CHECK: probe recognizes BOM/whitespace + '<?xml' or element; well-formed names/nesting; entity/character refs; declared encoding; DTD/schema validation optional; no checksum.", "xml", probe="xml", media="application/xml text/xml"),
    _f("ttf", "TrueType font", "font", "ttf ttc", (_r("TrueType 1.0", _c("00010000")), _r("TrueType true", _c("74727565")), _r("TTC", _c("74746366"))),
       "LAYOUT: sfnt OffsetTable{version,numTables,searchRange,entrySelector,rangeShift} | TableRecord[num]{tag,checksum:u32be,offset:u32be,length:u32be} | 4-byte-aligned tables; TTF requires head,maxp,cmap,glyf,loca,hhea,hmtx,name,post. TTC starts ttcf + version + fontOffsets. CHECK: table checksum=sum u32be padded; head.checkSumAdjustment=0xB1B0AFBA-wholeFontSum; loca/glyf and glyph-count bounds.", "opentype", media="font/ttf"),
    _f("opentype-cff", "OpenType CFF font", "font", "otf", (_r("OTTO", _c("4F54544F")),),
       "LAYOUT: sfnt directory with version 'OTTO'; required head,maxp,cmap,hhea,hmtx,name,post and CFF /CFF2 table. CFF has header + INDEX structures (count,offSize,1-based offsets,data), DICT operands/operators, charstrings/subroutines. CHECK: sfnt table and master checksums; INDEX offsets monotonic/in-range; glyph/charset/encoding counts; Type2 charstring stack/subroutine limits.", "opentype", media="font/otf"),
    _f("woff", "Web Open Font Format 1", "font", "woff", (_r("wOFF", _c("774F4646")),),
       "LAYOUT: Header[44]{signature='wOFF',flavor,length,numTables,reserved,totalSfntSize,major,minor,metaOffset/Length/OrigLength,privOffset/Length} | TableDirectory[20]*N{tag,offset,compLength,origLength,origChecksum} | zlib-compressed/raw tables | metadata/private. CHECK: offsets 4-aligned; compLength<=origLength; inflate exact; original sfnt checksums/head adjustment; totalSfntSize.", "woff", media="font/woff"),
    _f("woff2", "Web Open Font Format 2", "font", "woff2", (_r("wOF2", _c("774F4632")),),
       "LAYOUT: Header[48]{signature,flavor,length,numTables,reserved,totalSfntSize,totalCompressedSize,version,meta/private fields} | variable table directory with flags/base128 lengths/transform lengths | one Brotli stream | optional metadata/private. CHECK: UIntBase128 canonical <=5 bytes; directory order/ranges; Brotli exact size; inverse glyf/loca/hmtx transforms; reconstructed sfnt checksums.", "woff2", media="font/woff2"),
    _f("pcap-le", "pcap little-endian capture", "network", "pcap cap", (_r("pcap LE micro", _c("D4C3B2A1")), _r("pcap LE nano", _c("4D3CB2A1"))),
       "LAYOUT: GlobalHeader{magic,major:u16le,minor:u16le,thiszone:i32le,sigfigs:u32le,snaplen:u32le,linktype:u32le} | packets{seconds:u32le,fraction:u32le,capturedLen:u32le,originalLen:u32le,data[capturedLen]}. CHECK: capturedLen<=originalLen and snaplen; packet bounds; fraction <1e6 or1e9 by magic; no checksum.", "pcap", media="application/vnd.tcpdump.pcap"),
    _f("pcap-be", "pcap big-endian capture", "network", "pcap cap", (_r("pcap BE micro", _c("A1B2C3D4")), _r("pcap BE nano", _c("A1B23C4D"))),
       "LAYOUT: same 24-byte global and 16-byte packet headers as pcap, all multibyte values big-endian; magic selects micro/nanosecond fraction. CHECK: lengths/snaplen/timestamp fraction and record bounds; no checksum.", "pcap", media="application/vnd.tcpdump.pcap"),
    _f("pcapng", "pcap Next Generation", "network", "pcapng ntar", (_r("Section Header Block", _c("0A0D0D0A")),),
       "LAYOUT: blocks{type:u32, totalLength:u32,body,totalLengthAgain:u32}; SHB body begins BOM 1A2B3C4D selecting endian,version,sectionLength; IDB defines linktype/snaplen/options; EPB contains interface,timestamp high/low,captured/original lengths,packet padded4,options. CHECK: both lengths equal/multiple4/in-file; BOM/endian per section; interface IDs; captured<=original/snaplen; option TLVs/padding.", "pcapng", media="application/x-pcapng"),
    _f("parquet", "Apache Parquet", "data", "parquet", (_r("Parquet", _c("50415231")),),
       "LAYOUT: leading 'PAR1' | column-chunk pages (PageHeader Thrift compact + compressed data) grouped into row groups | FileMetaData serialized with Thrift compact | footerLength:u32le | trailing 'PAR1'. CHECK: trailing magic; footerLength locates exact metadata; schema/column paths; row/value counts; page compressed/uncompressed sizes; optional page CRC32; codec checks.", "parquet", media="application/vnd.apache.parquet"),
    _f("avro-ocf", "Apache Avro Object Container File", "data", "avro", (_r("Avro OCF", _c("4F626A01")),),
       "LAYOUT: magic 'Obj'+01 | metadata map blocks (long count via zigzag varint, string key, bytes value; avro.schema required, avro.codec optional) | sync[16] | data blocks{count:long,size:long,compressedObjects[size],sync[16]}. CHECK: varint/zigzag canonical bounds; schema-driven binary decoding; block count/size; every sync equals header marker; codec stream validation; no extra global checksum.", "avro", media="application/avro"),

    # Additional format families required by the v0.4 knowledge expansion.
    _f("eot", "Embedded OpenType", "font", "eot", (_r("EOT magic", _c("4C50", 34)),),
       "LAYOUT: EOTHeader{EOTSize:u32le,FontDataSize:u32le,Version:u32le,Flags:u32le,Panose[10],Charset,Italic,Weight:u32le,fsType:u16le,MagicNumber=504Ch,UnicodeRange[4],CodePageRange[2],CheckSumAdjustment:u32le,...name records...} | embedded/compressed font data. CHECK: header version selects optional fields; every UTF-16 name length/range fits; EOTSize equals file; FontDataSize and compression flags agree; embedded sfnt tables/checksums validate.", "eot opentype", media="application/vnd.ms-fontobject"),
    _f("sfnt-collection", "TrueType/OpenType Collection", "font", "ttc otc", (_r("TTC", _c("74746366")),),
       "LAYOUT: TTCHeader{'ttcf',major:u16be,minor:u16be,numFonts:u32be,offsetTable[numFonts]:u32be[,DSIG fields for v2]} | shared sfnt table directories/data. CHECK: offsets are aligned/in-file and start valid sfnt directories; each directory/table range and checksum validates; shared tables may overlap exactly; DSIG range is bounded.", "opentype", media="font/collection"),
    _f("color-font", "OpenType color font (COLR/CPAL)", "font", "ttf otf", (),
       "LAYOUT: normal TrueType/OpenType sfnt plus CPAL palette table and COLR v0 BaseGlyph/Layer records or COLR v1 BaseGlyphList+LayerList+ClipList+paint graph; optional SVG/CBDT/CBLC/sbix are alternate color mechanisms. CHECK: sfnt checksums first; glyph/palette/layer indices in range; sorted base records; v1 offsets stay in COLR and paint graph is acyclic/depth-bounded.", "opentype", probe="sfnt_color", media="font/ttf font/otf"),
    _f("bitmap-font", "Windows bitmap font FNT/FON", "font", "fnt fon", (_r("FNT v2", _c("0002")), _r("FNT v3", _c("0003"))),
       "LAYOUT: FNT header begins dfVersion:u16le and dfSize:u32le, copyright[60], type/points/resolution/ascent/charset, first/last/default/break chars, width/height, face/device offsets, bitsOffset; version-specific glyph table entries point to packed bitmap columns. FON embeds FNT resources in an NE executable. CHECK: dfSize/ranges, char count=last-first+1, glyph widths/offsets and bitmap stride; validate NE resource table for FON.", "fnt", probe="bitmap_font", media="application/x-font-fnt"),
    _f("jbig2", "JBIG2 bi-level image", "image", "jb2 jbig2", (_r("JBIG2 file signature", _c("974A42320D0A1A0A")),),
       "LAYOUT: optional sequential/random-access file header{signature,flags,pageCount?} | segment headers{number:u32be,flags,type,referred-count+numbers,pageAssociation,dataLength:u32be} | segment data; EOF segment type51. CHECK: referred segment numbers precede/resolve as mode requires; page association and data lengths fit; arithmetic/MMR regions obey bitmap bounds; cap symbol dictionaries, references and decoded pixels.", "jbig2", media="image/jbig2"),
    _f("aac", "AAC in ADTS transport", "audio", "aac adts", (_r("ADTS sync", _c("FFF0", mask="FFF6")),),
       "LAYOUT: frames{sync=FFF:12,ID:1,layer=0:2,protectionAbsent:1,profile:2,samplingIndex:4,private:1,channelConfig:3,...frameLength:13,bufferFullness:11,numRawBlocks:2[,CRC16],raw_data_blocks}. CHECK: frameLength includes header/CRC and stays in input; sampling index/channel configuration legal; buffer fullness semantics; CRC when present; raw AAC syntax must parse exactly.", "aac", media="audio/aac"),
    _f("opus-raw", "Raw Opus packet stream", "audio", "opusraw opuspkt", (),
       "LAYOUT: there is no standardized self-identifying raw-file wrapper; each packet starts TOC{config:5,stereo:1,code:2} followed by code-dependent frame count/length fields and one or more Opus frames. CHECK: packet length and padding parse exactly; frame count<=48 and duration<=120ms; configuration/frame sizes legal. Identification requires out-of-band framing—prefer Ogg Opus for files.", "opus", media="audio/opus"),
    _f("rtp", "Real-time Transport Protocol packet", "network", "rtp", (),
       "LAYOUT: fixed header{V=2:2,P:1,X:1,CC:4,M:1,PT:7,sequence:u16be,timestamp:u32be,SSRC:u32be,CSRC[CC]} | optional extension{profile:u16be,lengthWords:u16be,data[4*length]} | payload | optional padding ending in padCount. CHECK: header/CSRC/extension/padding ranges; PT is profile-bound; sequence/timestamp interpreted modulo width; authentication belongs to SRTP, not RTP.", "rtp", probe="rtp", media="application/rtp"),
    _f("rtcp", "RTP Control Protocol compound packet", "network", "rtcp", (),
       "LAYOUT: repeated packets{V=2:2,P:1,count:5,packetType:u8,lengthWordsMinus1:u16be,body[4*(length+1)-4]}; common SR=200,RR=201,SDES=202,BYE=203,APP=204,feedback=205/206. CHECK: each packet length multiple4/in-buffer; padding only last packet; count matches report/source chunks; classic compound starts SR/RR and includes CNAME SDES unless reduced-size rules apply.", "rtp", probe="rtcp", media="application/rtcp"),
    _f("sip", "Session Initiation Protocol message", "network", "sip", (),
       "LAYOUT: request-line{METHOD SP request-target SP SIP/2.0 CRLF} or status-line{SIP/2.0 SP code SP reason CRLF} | header fields with compact-name variants | CRLF | body[Content-Length]. CHECK: strict line and header limits; Content-Length duplicates must agree; Via branch/CSeq/Call-ID syntax; parse URIs without automatic resolution; body media type validated separately.", "sip", probe="sip", media="message/sip"),
    _f("smb", "Server Message Block 2/3 packet", "network", "smb smb2 smb3", (_r("SMB2 protocol ID", _c("FE534D42")), _r("SMB1 protocol ID", _c("FF534D42"))),
       "LAYOUT: transport framing (often NetBIOS Session length) | SMB2Header[64]{ProtocolId=FE534D42,StructureSize=64,CreditCharge,Status/ChannelSequence,Command,Credit,Flags,NextCommand,MessageId,tree/session IDs,Signature[16]} | command request/response; compound commands chain by NextCommand. CHECK: StructureSize and command-specific sizes; NextCommand 8-aligned/in-message/noncyclic; offsets+lengths bounded; dialect/signing/encryption negotiated state consistent.", "smb", media="application/vnd.smb"),
    _f("nfs", "Network File System v4 RPC message", "network", "nfs xdr", (),
       "LAYOUT: ONC RPC record marking over TCP{last:1,fragmentLength:31} | XDR CALL/REPLY{XID,msgType,rpcVersion=2,program=100003,version,procedure,credentials,verifier,...}; NFSv4 COMPOUND carries UTF-8 tag, minorversion, operation count and XDR operations. CHECK: fragment/XDR 4-byte padding; auth and opaque lengths bounded; operation/result counts agree; filehandles/stateids are opaque; cap compound count and decoded allocation.", "nfs", probe="nfs", media="application/x-nfs"),
    _f("modbus", "Modbus TCP ADU", "network", "modbus mbap", (),
       "LAYOUT: MBAP{transactionId:u16be,protocolId:u16be=0,length:u16be,unitId:u8} | PDU{function:u8,data[length-2]}; exception response function has high bit and one exception byte. CHECK: MBAP length counts unitId+PDU (normally 2..254), total bytes=6+length, protocolId=0; function-specific address/count/byte-count equations; RTU uses CRC16 instead of MBAP.", "modbus", probe="modbus_tcp"),
    _f("mqtt", "MQTT control packet", "network", "mqtt", (),
       "LAYOUT: FixedHeader{type:4,flags:4,remainingLength:base128 up to4 bytes} | type-specific variable header | payload. CONNECT begins protocol name UTF-8, level, flags, keepalive and properties(v5); PUBLISH includes topic, optional packet ID, properties and application payload. CHECK: type-specific fixed flags; canonical remaining length<=268435455 and exact packet boundary; UTF-8/length-prefixed fields; property multiplicity; packet IDs when QoS>0.", "mqtt", probe="mqtt"),
    _f("ogg", "Ogg generic container", "video", "ogx ogg", (_r("Ogg capture pattern", _c("4F67675300")),),
       "LAYOUT: pages{'OggS',version=0,headerType,granule:i64le,serial:u32le,sequence:u32le,checksum:u32le,pageSegments:u8,lacing[pageSegments],payload[sum(lacing)]}; packets span pages when final lace=255. CHECK: page CRC32 polynomial 04C11DB7 with checksum field zero; page length=27+segments+laceSum; serial/sequence and continued/BOS/EOS flags; codec packet semantics are separate.", "ogg", media="application/ogg"),
    _f("msgpack", "MessagePack object", "data", "msgpack mpk", (),
       "LAYOUT: one self-delimiting value selected by first byte: positive/negative fixint, fixmap/fixarray/fixstr, nil/bool, bin/str/ext with u8/u16/u32 length, array/map with u16/u32 count, numeric scalars and timestamps/ext. CHECK: declared byte/count ranges fit; map has 2*count values; UTF-8 only for str; cap nesting/count/decoded bytes; no checksum or canonical ordering by base spec.", "msgpack", media="application/msgpack"),
    _f("bson", "Binary JSON (BSON)", "data", "bson", (),
       "LAYOUT: Document{byteLength:i32le,elements...,terminator=00}; element{type:u8,cstringKey,valueByType}; nested document/array repeats grammar; string{i32le bytesIncludingNUL,UTF8,00}; binary{i32le,subtype,data}; arrays use decimal string keys. CHECK: byteLength>=5 and exactly bounds document; cstrings terminate; nested lengths/types fit; old binary subtype length consistency; cap nesting and allocation.", "bson", media="application/bson"),
    _f("capnp", "Cap'n Proto serialized message", "data", "capnp capnpbin", (),
       "LAYOUT: stream framing{segmentCountMinus1:u32le,segmentSizesWords:u32le[count],padding u32 if needed} | 8-byte-word segments; root pointer is first word of segment0; struct/list/far pointers encode signed word offsets, data/pointer sizes, element sizes and landing pads. CHECK: segment count/sizes and total words bounded; every pointer target/range inside segment; far/double-far landing pads valid; traversal and nesting limits required; no checksum.", "capnp", media="application/x-capnp"),
    _f("odt", "OpenDocument Text", "document", "odt ott", (_r("ZIP", _c("504B0304")),),
       "LAYOUT: ZIP package whose first uncompressed entry is 'mimetype'='application/vnd.oasis.opendocument.text'; META-INF/manifest.xml plus content.xml, styles.xml, meta.xml, settings.xml and assets. CHECK: ZIP CRC/directory; mimetype first/stored/exact; manifest paths/media types resolve; XML well-formed and package version/namespace constraints.", "opendocument zip", probe="zip_odt", media="application/vnd.oasis.opendocument.text"),
    _f("ods", "OpenDocument Spreadsheet", "document", "ods ots", (_r("ZIP", _c("504B0304")),),
       "LAYOUT: OpenDocument ZIP package with stored first mimetype='application/vnd.oasis.opendocument.spreadsheet'; manifest and content.xml table structures, styles/meta/settings and assets. CHECK: package/ZIP/XML integrity; repeated row/column counts bounded; formula namespace and cell value-type/value attributes consistent.", "opendocument zip", probe="zip_ods", media="application/vnd.oasis.opendocument.spreadsheet"),
    _f("odp", "OpenDocument Presentation", "document", "odp otp", (_r("ZIP", _c("504B0304")),),
       "LAYOUT: OpenDocument ZIP package with stored first mimetype='application/vnd.oasis.opendocument.presentation'; manifest and content.xml presentation pages/draw objects, styles/meta/settings/assets. CHECK: package/ZIP/XML integrity; page/master/style references resolve; embedded objects and links are separately validated and policy-controlled.", "opendocument zip", probe="zip_odp", media="application/vnd.oasis.opendocument.presentation"),
)


_BY_ID = {item.id: item for item in FORMATS}
if len(_BY_ID) != len(FORMATS):
    raise RuntimeError(f"catalog contains duplicate IDs: {len(FORMATS)} records/{len(_BY_ID)} unique IDs")


def get_format(format_id: str) -> FormatSpec:
    normalized = format_id.lower().strip().lstrip(".")
    if normalized in _BY_ID:
        return _BY_ID[normalized]
    candidates = [item for item in FORMATS if normalized in item.extensions]
    if len(candidates) == 1:
        return candidates[0]
    if not candidates:
        raise KeyError(f"unknown format id or unambiguous extension: {format_id!r}")
    raise KeyError(f"ambiguous extension {format_id!r}: {', '.join(item.id for item in candidates)}")


def list_formats() -> list[dict[str, object]]:
    return [item.to_dict(include_structure=False) for item in FORMATS]


def get_structure(format_id: str) -> str:
    """Return only the compact, exact structure knowledge string for an Agent."""
    return get_format(format_id).structure
