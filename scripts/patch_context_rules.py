#!/usr/bin/env python3
"""Apply the real-folder findings to the detection engine.

Scanning a real Desktop folder exposed three false positives that all come
from the same assumption: that a finding is equally meaningful regardless
of what the file can do.

  1. A plain .txt file holding a base64 PowerShell command was reported
     SUSPICIOUS. A text file cannot execute anything, so the evidence is
     still reported but it stops counting towards the score.
  2. Google's adb.exe was reported MALICIOUS because it hooks the keyboard
     and the network. The hooking APIs are generic input APIs, and a
     binary carrying an Authenticode certificate is a different risk
     profile.
  3. "SDL_WINDOWS_ENABLE_MENU_MNEMONICS" matched the wallet rule because
     "MNEMONIC" is a substring of "MENU_MNEMONICS", and
     "SSL_CTX_get_keylog_callback" matched the keylogger rule because it
     contains "keylog".

The detection engine is stored obfuscated, so the patch works on the
decoded literals and writes them back encoded.
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
    ok = True

    def fail(msg):
        nonlocal ok
        print(f"  MISS: {msg}")
        ok = False

    # 1. MatchInput gains the signature flag.
    if "\tPath  string\n}" in src:
        src = src.replace(
            "\tPath  string\n}",
            "\tPath  string\n"
            "\t// Signed reports that the PE carries an Authenticode certificate\n"
            "\t// table. The certificate is NOT verified, but its presence is\n"
            "\t// still meaningful: a random trojanized crack rarely carries one.\n"
            "\tSigned bool\n}",
            1,
        )
        print("  ok  : MatchInput.Signed")
    else:
        fail("MatchInput.Signed")

    # 2. matchImports takes the signature flag.
    old = "func matchImports(info *pe.Info) []model.Finding {"
    if old in src:
        src = src.replace(
            old,
            "func matchImports(info *pe.Info, signed bool) []model.Finding {",
            1,
        )
        print("  ok  : matchImports signature")
    else:
        fail("matchImports signature")

    # 3. The signed discount covers every import category.
    old = "\t\tif len(hit) > 0 {\n\t\t\tout = append(out, model.Finding{"
    new = (
        "\t\tif len(hit) > 0 {\n"
        "\t\t\tsev := ioc.severity\n"
        "\t\t\t// A signed binary that hooks things is a tool, not a\n"
        "\t\t\t// payload: Google's adb, SDL2, an auto-clicker. The\n"
        "\t\t\t// certificate is not verified, so the finding is\n"
        "\t\t\t// discounted rather than dropped.\n"
        "\t\t\tif signed {\n"
        "\t\t\t\tsev -= 12\n"
        "\t\t\t\tif sev < 0 {\n"
        "\t\t\t\t\tsev = 0\n"
        "\t\t\t\t}\n"
        "\t\t\t}\n"
        "\t\t\tout = append(out, model.Finding{"
    )
    if old in src:
        src = src.replace(old, new, 1)
        print("  ok  : signed discount")
    else:
        fail("signed discount")

    if "\t\t\t\tSeverity: ioc.severity," in src:
        src = src.replace("\t\t\t\tSeverity: ioc.severity,", "\t\t\t\tSeverity: sev,", 1)
        print("  ok  : severity variable")
    else:
        fail("severity variable")

    # 4. The keylogger category split: the generic input APIs are not
    #    keyloggers.
    entry = None
    for m in re.finditer(r'\t+(obf\.S\("[A-Za-z0-9+/=]+"\)): \{', src):
        try:
            key = dec(re.search(r'"([A-Za-z0-9+/=]+)"', m.group(1)).group(1))
        except Exception:
            continue
        if key == "keylogger":
            end = src.find("\n\t},", m.start())
            entry = (m.start(), end + len("\n\t},"))
            break
    if entry is None:
        fail("keylogger table entry")
    else:
        core = ["GetAsyncKeyState", "SetWindowsHookExA", "SetWindowsHookExW",
                "GetRawInputData", "RegisterRawInputDevices"]
        generic = ["GetKeyboardState", "GetKeyState", "MapVirtualKeyA", "GetForegroundWindow"]
        new_block = (
            "\t" + lit("input") + ": {\n"
            "\t\tfuncs:    []string{" + ", ".join(lit(g) for g in generic) + "},\n"
            "\t\tcategory: " + lit("input") + ",\n"
            "\t\tseverity: 6,\n"
            "\t\tdesc:     " + lit("generic input API (keyboard or mouse state) - weak on its own") + ",\n"
            "\t},\n"
            "\t" + lit("keylogger") + ": {\n"
            "\t\tfuncs:    []string{" + ", ".join(lit(c) for c in core) + "},\n"
            "\t\tcategory: " + lit("keylogger") + ",\n"
            "\t\tseverity: 30,\n"
            "\t\tdesc:     " + lit("keyboard/input capture API") + ",\n"
            "\t},"
        )
        src = src[: entry[0]] + new_block + src[entry[1] :]
        print("  ok  : keylogger category split (core keylog APIs vs generic input APIs)")

    # 5. The keylogger terminology regex needs word boundaries.
    m = re.search(r'var reKeylogWord = regexp\.MustCompile\(obf\.S\("([A-Za-z0-9+/=]+)"\)\)', src)
    if not m:
        fail("reKeylogWord")
    else:
        pattern = dec(m.group(1))
        patched = pattern.replace("(keylog|", "(\\bkeylog(ger|ging|ged)?\\b|")
        if patched == pattern:
            fail("keylogger terminology pattern")
        else:
            src = src[: m.start(1)] + enc(patched) + src[m.end(1) :]
            print("  ok  : keylogger terminology word boundaries")

    # 6. The wallet pattern needs word boundaries: "MENU_MNEMONICS"
    #    contains "MNEMONIC".
    m = re.search(r'var reWallet = regexp\.MustCompile\(obf\.S\("([A-Za-z0-9+/=]+)"\)\)', src)
    if not m:
        fail("reWallet")
    else:
        pattern = dec(m.group(1))
        patched = pattern.replace("seed phrase|mnemonic|", "seed[ _]phrase|\\bmnemonic\\b|")
        patched = patched.replace("Login Data|", "\\bLogin Data\\b|")
        if patched == pattern:
            fail("wallet pattern")
        else:
            src = src[: m.start(1)] + enc(patched) + src[m.end(1) :]
            print("  ok  : wallet word boundaries")

    # 7. The action categories, for the text-file policy.
    if "var actionCategories" not in src:
        cats = ["c2", "evasion", "dropper", "stealer", "keylogger",
                "persistence", "network", "ransomware", "miner", "injection", "credential"]
        block = (
            "// actionCategories are the finding categories that describe\n"
            "// something the file DOES. They only matter when the file can act.\n"
            "var actionCategories = map[string]bool{\n"
            + "".join(f"\t{lit(c)}: true,\n" for c in cats)
            + "}\n\n"
        )
        src = src.replace("type MatchInput struct {", block + "type MatchInput struct {", 1)
        print("  ok  : action categories")
    else:
        print("  ok  : action categories (already present)")

    # 8. The text-file policy: a file that cannot execute cannot be a
    #    payload.
    old = "\treturn findings, whitelistHits\n}"
    new = (
        "\t// A file that cannot execute cannot be a payload. The evidence is\n"
        "\t// still reported, but it stops counting towards the score: a\n"
        "\t// base64 PowerShell command in a notes file, an IP:port in a log\n"
        "\t// or a \"schtasks /create\" line in a readme are not threats while\n"
        "\t// the file sits there as text.\n"
        "\tif in.Kind == filetype.KindText {\n"
        "\t\tfor i := range findings {\n"
        "\t\t\tif findings[i].Severity > 0 && actionCategories[findings[i].Category] {\n"
        "\t\t\t\tfindings[i].Severity = 0\n"
        "\t\t\t\tfindings[i].Detail = " + lit("[text file, cannot execute] ") + "+ findings[i].Detail\n"
        "\t\t\t}\n"
        "\t}\n"
        "\t}\n"
        "\treturn findings, whitelistHits\n}"
    )
    if old in src:
        src = src.replace(old, new, 1)
        print("  ok  : text file policy")
    else:
        fail("text file policy")

    if not ok:
        print("some patches did not apply; the file was not written")
        return 1
    RULES.write_text(src, encoding="utf-8")
    print("patched", RULES.relative_to(ROOT))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
