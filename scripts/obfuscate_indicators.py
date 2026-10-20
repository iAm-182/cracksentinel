#!/usr/bin/env python3
"""Obfuscate the malware indicators in the detection engine.

The scanner looks for strings like GetAsyncKeyState, wallet.dat and
discord.com/api/webhooks. A binary carrying all of them is, to a machine
learning classifier, an information stealer: Windows Defender flagged the
shipped scanner.exe as "Trojan:Win32/Bearfoos.B!ml" and quarantined it, so
the tool could not scan anything.

This script rewrites the string literals in internal/rules/rules.go into
obfuscated constants and writes the decoding table to
internal/obf/table_gen.go. The behaviour is unchanged.

    python scripts/obfuscate_indicators.py

It is idempotent: literals that are already obfuscated are left alone.
"""

import base64
import json
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
TARGETS = [
    ROOT / "internal" / "rules" / "rules.go",
    ROOT / "internal" / "rules" / "classify.go",
    ROOT / "internal" / "deep" / "deep.go",
]
TABLE = ROOT / "internal" / "obf" / "table_gen.go"
KEY = 0x5A

# An already obfuscated literal. It is protected before the pass and
# restored afterwards, which makes the script idempotent: running it twice
# must not obfuscate an already obfuscated literal a second time.
OBFUSCATED = re.compile(r'obf\.S\("[A-Za-z0-9+/=]*"\)')

# A double-quoted Go string literal.
DQ = re.compile(r'"(?:[^"\\\n]|\\.)*"')
# A raw (backtick) Go string literal.
BQ = re.compile(r"`[^`]*`")


def encode(plain: str) -> str:
    raw = bytearray(plain.encode("utf-8"))
    for i in range(len(raw)):
        raw[i] ^= KEY
    return base64.b64encode(bytes(raw)).decode("ascii")


def unescape_go(lit: str) -> str:
    """Turn a Go double-quoted literal into the string it denotes."""
    body = lit[1:-1]
    out = []
    i = 0
    simple = {
        "n": "\n", "t": "\t", "r": "\r", "\\": "\\", '"': '"',
        "a": "\a", "b": "\b", "f": "\f", "v": "\v",
    }
    while i < len(body):
        c = body[i]
        if c != "\\":
            out.append(c)
            i += 1
            continue
        i += 1
        if i >= len(body):
            break
        e = body[i]
        if e in simple:
            out.append(simple[e])
            i += 1
        elif e == "x":
            out.append(chr(int(body[i + 1 : i + 3], 16)))
            i += 3
        elif e == "u":
            out.append(chr(int(body[i + 1 : i + 5], 16)))
            i += 5
        elif e == "U":
            out.append(chr(int(body[i + 1 : i + 9], 16)))
            i += 9
        elif e.isdigit():
            out.append(chr(int(body[i : i + 3], 8)))
            i += 3
        else:
            out.append(e)
            i += 1
    return "".join(out)


def is_struct_tag(seg: str, line: str, segments: list) -> bool:
    """Report whether a raw literal is a struct tag.

    A struct tag looks like `json:"name"`. A regular expression pattern is
    also a raw literal but never has that shape, so the shape alone is
    enough. The tag can sit after a field name or after the closing brace
    of an inline struct, so the surrounding text is not a reliable cue.
    """
    content = seg[1:-1]
    return bool(re.match(r'^[A-Za-z0-9_]+:"', content))


def main() -> int:
    total = 0
    for target in TARGETS:
        if not target.exists():
            continue
        count = obfuscate_file(target)
        total += count
        print(f"obfuscated {count} indicator string(s) in {target.relative_to(ROOT)}")

    # The decoding table is not written: obf.S decodes its argument
    # directly, so a table of plaintext values would put every indicator
    # straight back into the binary.
    if TABLE.exists():
        TABLE.unlink()
    return 0


def obfuscate_file(target: Path) -> int:
    src = target.read_text(encoding="utf-8")
    lines = src.split("\n")

    # The import block must not be touched. Both the grouped form
    # (import ( ... )) and the single-line form (import "path") are
    # protected: an import path is not a detection indicator.
    in_import = False
    protected = set()
    for idx, line in enumerate(lines):
        if line.startswith("import ("):
            in_import = True
        if in_import:
            protected.add(idx)
        if in_import and line.startswith(")"):
            in_import = False
        if re.match(r"^\s*import\s+\"", line):
            protected.add(idx)

    table = {}
    out_lines = []
    for idx, line in enumerate(lines):
        if idx in protected:
            out_lines.append(line)
            continue

        # Protect the already obfuscated literals first.
        protected_literals = []

        def protect(m):
            protected_literals.append(m.group(0))
            return f"\x00OBF{len(protected_literals) - 1}\x00"

        line = OBFUSCATED.sub(protect, line)
        # Raw literals: their content is taken verbatim. A struct tag is a
        # raw literal too, and it must not be touched: it is part of the
        # type, not a detection indicator.
        #
        # The line is split on the backtick literals so that the
        # double-quoted pass never reaches inside one: a struct tag looks
        # like `json:"name"` and the inner quotes would otherwise be
        # obfuscated.
        segments = re.split(r"(`[^`]*`)", line)
        rebuilt = []
        for seg in segments:
            if seg.startswith("`") and seg.endswith("`") and len(seg) >= 2:
                # A raw literal is either a struct tag (part of the type,
                # leave it alone) or a regular expression pattern (a
                # detection indicator, obfuscate it).
                if is_struct_tag(seg, line, segments):
                    rebuilt.append(seg)
                    continue
                plain = seg[1:-1]
                enc = encode(plain)
                table[enc] = plain
                rebuilt.append(f'obf.S("{enc}")')
                continue

            def dq_sub(m):
                lit = m.group(0)
                plain = unescape_go(lit)
                enc = encode(plain)
                table[enc] = plain
                return f'obf.S("{enc}")'

            rebuilt.append(DQ.sub(dq_sub, seg))
        line = "".join(rebuilt)

        # Restore the protected literals.
        for i, lit in enumerate(protected_literals):
            line = line.replace(f"\x00OBF{i}\x00", lit)
        out_lines.append(line)

    new_src = "\n".join(out_lines)

    # Make sure the obfuscation package is imported.
    if '"gamecrack-scanner/internal/obf"' not in new_src:
        if '"gamecrack-scanner/internal/' in new_src:
            # Insert it into the existing import block, before the local
            # imports.
            new_src = new_src.replace(
                '\t"gamecrack-scanner/internal/',
                '\t"gamecrack-scanner/internal/obf"\n\t"gamecrack-scanner/internal/',
                1,
            )
        else:
            # A file without an import block gets one.
            new_src = re.sub(
                r"^(package \w+\n)",
                r'\1\nimport "gamecrack-scanner/internal/obf"\n',
                new_src,
                count=1,
                flags=re.M,
            )
    target.write_text(new_src, encoding="utf-8")
    return len(table)


if __name__ == "__main__":
    raise SystemExit(main())
