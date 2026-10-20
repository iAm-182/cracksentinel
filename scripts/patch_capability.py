#!/usr/bin/env python3
"""Add the capability/intent classification to the detection engine.

The score has to separate what a file CAN do from what it DOES.

  - capability: the import-based findings. The file hooks the keyboard, it
    injects, it uses the network, it copies to the clipboard. A crack
    emulator has capability. A crack emulator's INTENT is zero.
  - intent: the string-based findings. The file talks to a C2 URL, it
    targets browser credentials, it installs a run key, it carries a
    payload. That is intent, and it is what makes a file malicious.

The capability findings are capped in the scoring policy, the intent
findings are not. Without the split, a legitimate tool that does five
different things added up to 100 and was called MALICIOUS: that is what
happened to Google's adb.exe and to an auto-clicker in a real scan.

The literals are written plain; scripts/obfuscate_indicators.py encodes
them afterwards.
"""

import base64
import pathlib
import re
import sys

ROOT = pathlib.Path(__file__).resolve().parent.parent
RULES = ROOT / "internal" / "rules" / "rules.go"
KEY = 0x5A
LIT = re.compile(r'obf\.S\("([A-Za-z0-9+/=]+)"\)')


def dec(e):
    raw = base64.b64decode(e)
    return bytes(b ^ KEY for b in raw).decode("utf-8")


def enc(plain):
    raw = bytearray(plain.encode("utf-8"))
    for i in range(len(raw)):
        raw[i] ^= KEY
    return base64.b64encode(bytes(raw)).decode("ascii")


def lit(plain):
    return 'obf.S("' + enc(plain) + '")'


def main():
    src = RULES.read_text(encoding="utf-8")
    if "func IsCapability" in src:
        print("  already present")
        return 0

    capability_rules = [
        "keylog_word2", "base64_blob", "sandbox_check", "packer", "dotnet", "pe_parse",
        "crypter_no_raw_sections", "encrypted_payload", "nonstandard_sections",
        "no_readable_strings", "auto_unpacked", "unpack_failed",
    ]
    block = (
        "// IsCapability reports whether a finding describes what the file CAN\n"
        "// do rather than what it DOES.\n"
        "//\n"
        "// The import-based findings are capability: hooking the keyboard,\n"
        "// injecting, using the network. A crack emulator has capability and no\n"
        "// intent. The string-based findings are intent: a C2 URL, a browser\n"
        "// credential target, a run key. The scoring policy caps the capability\n"
        "// bucket so a legitimate tool that does five things at once does not\n"
        "// add up to MALICIOUS.\n"
        "func IsCapability(rule string) bool {\n"
        "\tif strings.HasPrefix(rule, " + lit("imp_") + ") {\n"
        "\t\treturn true\n"
        "\t}\n"
        "\tfor _, r := range []string{"
        + ", ".join(lit(r) for r in capability_rules)
        + "} {\n"
        "\t\tif rule == r {\n"
        "\t\t\treturn true\n"
        "\t\t}\n"
        "\t}\n"
        "\treturn false\n"
        "}\n\n"
    )
    src = src.replace("type MatchInput struct {", block + "type MatchInput struct {", 1)
    RULES.write_text(src, encoding="utf-8")
    print("  ok  : IsCapability")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
