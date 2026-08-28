import sys
sys.path.insert(0, "C:/Users/XuYanbin/format_kb/src")
from format_kb import get_template_bytes

for fid in ("tiff-le", "elf32-le", "wasm", "pdf", "png", "rar5"):
    try:
        b = get_template_bytes(fid)
        print(f"{fid}: {len(b)} bytes, head={b[:16].hex(' ').upper()}")
    except Exception as e:
        print(f"{fid}: ERROR {type(e).__name__}: {e}")
