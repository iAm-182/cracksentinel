"""Build all CrackSentinel icons and Windows PE/COFF resource (.syso) from the master PNG.

Inputs:
  - Optional CLI arg: path to raw studio image (crops + applies transparent squircle mask -> assets/cracksentinel.png)
  - Otherwise reads assets/cracksentinel.png directly (reproducible from git!)

Outputs:
  - assets/cracksentinel.png              (512x512 RGBA transparent squircle master)
  - assets/cracksentinel.ico              (16, 24, 32, 48, 64, 128, 256 multi-size Windows icon)
  - cmd/desktop/resource_windows_amd64.syso (RT_ICON + RT_GROUP_ICON + DPI-aware RT_MANIFEST)
  - internal/ui/web/favicon.png           (64x64 RGBA PNG for desktop window & web favicon)
  - internal/ui/web/favicon.ico           (16/32/48 multi-size web favicon)
  - extension/icons/icon16.png, icon48.png, icon128.png
"""

import io
import os
import struct
import sys
from PIL import Image, ImageDraw

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
MASTER_PNG = os.path.join(ROOT, "assets", "cracksentinel.png")
ICO_PATH = os.path.join(ROOT, "assets", "cracksentinel.ico")
SYSO_PATH = os.path.join(ROOT, "cmd", "desktop", "resource_windows_amd64.syso")
WEB_FAV_PNG = os.path.join(ROOT, "internal", "ui", "web", "favicon.png")
WEB_FAV_ICO = os.path.join(ROOT, "internal", "ui", "web", "favicon.ico")
EXT_ICON_DIR = os.path.join(ROOT, "extension", "icons")


def prepare_master_from_raw(raw_path):
    """Trim outer solid margin from generated tile and apply crisp anti-aliased squircle alpha mask."""
    img = Image.open(raw_path).convert("RGBA")
    w, h = img.size
    # Detect bounding box of the glowing rounded-square tile (brighter than dark corner bg).
    bg = img.getpixel((4, 4))
    px = img.load()
    min_x, min_y, max_x, max_y = w, h, 0, 0
    for y in range(h):
        for x in range(w):
            r, g, b, _ = px[x, y]
            if abs(r - bg[0]) + abs(g - bg[1]) + abs(b - bg[2]) > 28:
                if x < min_x:
                    min_x = x
                if x > max_x:
                    max_x = x
                if y < min_y:
                    min_y = y
                if y > max_y:
                    max_y = y

    # Keep a tiny 2% breathing room around the outer rim glow so it never clips.
    bw = max_x - min_x + 1
    bh = max_y - min_y + 1
    side = max(bw, bh)
    cx = (min_x + max_x) / 2.0
    cy = (min_y + max_y) / 2.0
    pad = side * 0.015
    half = side / 2.0 + pad
    box = (
        int(max(0, round(cx - half))),
        int(max(0, round(cy - half))),
        int(min(w, round(cx + half))),
        int(min(h, round(cy + half))),
    )
    cropped = img.crop(box).resize((512, 512), Image.Resampling.LANCZOS)

    # 4x supersampled rounded-square alpha mask for ultra-smooth anti-aliased transparent corners.
    mask_hi = Image.new("L", (2048, 2048), 0)
    draw = ImageDraw.Draw(mask_hi)
    # Match the tile's generous corner radius (~22% of width)
    draw.rounded_rectangle((16, 16, 2032, 2032), radius=455, fill=255)
    mask = mask_hi.resize((512, 512), Image.Resampling.LANCZOS)
    cropped.putalpha(mask)

    os.makedirs(os.path.dirname(MASTER_PNG), exist_ok=True)
    cropped.save(MASTER_PNG, format="PNG", optimize=True)
    print(f"prepared master {MASTER_PNG} (crop={box})")
    return cropped


def png_bytes_at(master, size):
    im = master.resize((size, size), Image.Resampling.LANCZOS)
    buf = io.BytesIO()
    im.save(buf, format="PNG", optimize=True)
    return buf.getvalue()


def build_ico(pngs):
    """Pack list of (size, png_bytes) into a standard Windows .ico file."""
    count = len(pngs)
    header = struct.pack("<HHH", 0, 1, count)
    offset = 6 + 16 * count
    entries = bytearray()
    payload = bytearray()
    for sz, data in pngs:
        dim = 0 if sz >= 256 else sz
        entries.extend(struct.pack("<BBBBHHII", dim, dim, 0, 0, 1, 32, len(data), offset))
        payload.extend(data)
        offset += len(data)
    return header + bytes(entries) + bytes(payload)


def build_syso_amd64(pngs, manifest_bytes):
    """Build a valid Windows PE/COFF amd64 .syso containing RT_ICON, RT_GROUP_ICON, and RT_MANIFEST."""
    grp = bytearray(struct.pack("<HHH", 0, 1, len(pngs)))
    for idx, (sz, data) in enumerate(pngs, start=1):
        dim = 0 if sz >= 256 else sz
        grp.extend(struct.pack("<BBBBHHIH", dim, dim, 0, 0, 1, 32, len(data), idx))

    # RT_ICON = 3, RT_GROUP_ICON = 14, RT_MANIFEST = 24
    tree = [
        (3, [(idx, 0x0409, data) for idx, (_, data) in enumerate(pngs, start=1)]),
        (14, [(1, 0x0409, bytes(grp))]),
        (24, [(1, 0x0409, manifest_bytes)]),
    ]

    def align4(n):
        return (n + 3) & ~3

    dir_hdr_sz, dir_ent_sz, data_ent_sz = 16, 8, 16
    cur = dir_hdr_sz + len(tree) * dir_ent_sz
    name_dir_offsets = {}
    for t_id, items in tree:
        name_dir_offsets[t_id] = cur
        cur += dir_hdr_sz + len(items) * dir_ent_sz

    lang_dir_offsets = {}
    for t_id, items in tree:
        for n_id, _, _ in items:
            lang_dir_offsets[(t_id, n_id)] = cur
            cur += dir_hdr_sz + dir_ent_sz

    data_entry_offsets = {}
    data_entry_list = []
    for t_id, items in tree:
        for n_id, l_id, blob in items:
            data_entry_offsets[(t_id, n_id)] = cur
            data_entry_list.append((t_id, n_id, l_id, blob, cur))
            cur += data_ent_sz

    blob_offsets = {}
    for t_id, n_id, _, blob, _ in data_entry_list:
        cur = align4(cur)
        blob_offsets[(t_id, n_id)] = cur
        cur += len(blob)
    rsrc = bytearray(align4(cur))

    def write_dir(off, entries):
        struct.pack_into("<IIHHHH", rsrc, off, 0, 0, 0, 0, 0, len(entries))
        p = off + dir_hdr_sz
        for eid, target in entries:
            struct.pack_into("<II", rsrc, p, eid, target)
            p += dir_ent_sz

    write_dir(0, [(t_id, 0x80000000 | name_dir_offsets[t_id]) for t_id, _ in tree])
    for t_id, items in tree:
        write_dir(name_dir_offsets[t_id], [(n_id, 0x80000000 | lang_dir_offsets[(t_id, n_id)]) for n_id, _, _ in items])
    for t_id, items in tree:
        for n_id, l_id, _ in items:
            write_dir(lang_dir_offsets[(t_id, n_id)], [(l_id, data_entry_offsets[(t_id, n_id)])])

    relocs = bytearray()
    for t_id, n_id, _, blob, de_off in data_entry_list:
        b_off = blob_offsets[(t_id, n_id)]
        struct.pack_into("<IIII", rsrc, de_off, b_off, len(blob), 0, 0)
        rsrc[b_off:b_off + len(blob)] = blob
        relocs.extend(struct.pack("<IIH", de_off, 0, 3))  # IMAGE_REL_AMD64_ADDR32NB

    raw_ptr = 20 + 40
    reloc_ptr = raw_ptr + len(rsrc)
    sym_ptr = reloc_ptr + len(relocs)
    coff_hdr = struct.pack("<HHIIIHH", 0x8664, 1, 0, sym_ptr, 1, 0, 0)
    sec_hdr = struct.pack(
        "<8sIIIIIIHHI",
        b".rsrc\x00\x00\x00", 0, 0, len(rsrc), raw_ptr, reloc_ptr, 0, len(data_entry_list), 0, 0x40000040,
    )
    sym = struct.pack("<8sIHHBB", b".rsrc\x00\x00\x00", 0, 1, 0, 3, 0)
    strtab = struct.pack("<I", 4)
    return coff_hdr + sec_hdr + bytes(rsrc) + bytes(relocs) + sym + strtab


MANIFEST = b"""<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<assembly xmlns="urn:schemas-microsoft-com:asm.v1" manifestVersion="1.0">
  <assemblyIdentity version="1.9.3.0" processorArchitecture="amd64" name="CrackSentinel.Desktop" type="win32"/>
  <description>CrackSentinel Game Malware Guard</description>
  <trustInfo xmlns="urn:schemas-microsoft-com:asm.v3">
    <security>
      <requestedPrivileges>
        <requestedExecutionLevel level="asInvoker" uiAccess="false"/>
      </requestedPrivileges>
    </security>
  </trustInfo>
  <application xmlns="urn:schemas-microsoft-com:asm.v3">
    <windowsSettings>
      <dpiAware xmlns="http://schemas.microsoft.com/SMI/2005/WindowsSettings">true/PM</dpiAware>
      <dpiAwareness xmlns="http://schemas.microsoft.com/SMI/2016/WindowsSettings">PerMonitorV2,PerMonitor</dpiAwareness>
    </windowsSettings>
  </application>
</assembly>
"""


def main():
    if len(sys.argv) > 1 and os.path.exists(sys.argv[1]):
        master = prepare_master_from_raw(sys.argv[1])
    else:
        master = Image.open(MASTER_PNG).convert("RGBA")

    ico_sizes = [16, 24, 32, 48, 64, 128, 256]
    pngs = [(sz, png_bytes_at(master, sz)) for sz in ico_sizes]

    os.makedirs(os.path.dirname(ICO_PATH), exist_ok=True)
    ico_data = build_ico(pngs)
    with open(ICO_PATH, "wb") as f:
        f.write(ico_data)

    os.makedirs(os.path.dirname(SYSO_PATH), exist_ok=True)
    syso_data = build_syso_amd64(pngs, MANIFEST)
    with open(SYSO_PATH, "wb") as f:
        f.write(syso_data)

    # Web UI favicon (64px PNG + 16/32/48 ICO)
    with open(WEB_FAV_PNG, "wb") as f:
        f.write(png_bytes_at(master, 128))
    with open(WEB_FAV_ICO, "wb") as f:
        f.write(build_ico([(sz, png_bytes_at(master, sz)) for sz in (16, 32, 48)]))

    # Browser extension icons
    os.makedirs(EXT_ICON_DIR, exist_ok=True)
    for sz in (16, 48, 128):
        out_p = os.path.join(EXT_ICON_DIR, f"icon{sz}.png")
        with open(out_p, "wb") as f:
            f.write(png_bytes_at(master, sz))

    print(f"wrote {ICO_PATH} ({len(ico_data)} bytes, {len(ico_sizes)} sizes)")
    print(f"wrote {SYSO_PATH} ({len(syso_data)} bytes)")
    print(f"wrote {WEB_FAV_PNG}, {WEB_FAV_ICO}, and extension/icons/icon{{16,48,128}}.png")


if __name__ == "__main__":
    main()
