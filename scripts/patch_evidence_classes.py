#!/usr/bin/env python3
"""Separate the evidence classification from the scoring classification.

The adjudicator was calling every binary that hooks something a trojanized
crack: Google's adb, SDL2, libcurl, a game auto-clicker and an Inno Setup
uninstaller. The reason is that the evidence handed to the model put the
IMPORT-based findings into the payload bucket. A model that sees
"payload_indicators: persistence API: RegSetValueExW" concludes that the
file intends to persist, which is exactly what an installer legitimately does.

What the model needs to see is the difference between:

  - what the file CAN do      (hooks, injects, persists, uses the network)
  - what the file DOES        (talks to a C2 URL, targets browser
                                credentials, carries an encoded payload)

So the evidence gets its own classification. The scoring keeps its own: a
run key in a crack folder is still worth points.

The literals are written plain; scripts/obfuscate_indicators.py encodes them
afterwards.
"""

import base64
import pathlib
import re
import sys

ROOT = pathlib.Path(__file__).resolve().parent.parent
RULES = ROOT / "internal" / "rules" / "classify.go"
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


CRACK_EXPECTED = [
    # Hooking, injecting, reading input: what a crack emulator or a game
    # tool legitimately does.
    "imp_keylogger", "imp_injection", "imp_input", "imp_exfil",
    "imp_clipboard", "imp_destructive", "imp_persistence",
    "crack_whitelist", "emu_steamapi",
    # Informational.
    "packer", "dotnet", "pe_parse", "keylog_word2", "base64_blob",
    "sandbox_check", "keylog_word",
    # The packing findings describe an opaque file, not an intent.
    "crypter_no_raw_sections", "encrypted_payload", "nonstandard_sections",
    "no_readable_strings", "auto_unpacked", "unpack_failed",
]

PAYLOAD = [
    # A C2 channel or a stolen-data target. These are never normal.
    "discord_webhook", "telegram_token", "wallet_browser_target",
    "imp_credential",
    # An encoded or downloaded payload.
    "ps_encoded", "download_cradle",
    # Credential theft and tampering.
    "script_cred_paths", "script_defender_bypass", "script_crypto_miner",
    "script_reverse_shell",
    # Persistence, evasion and dropping as a string, not as an import.
    "persistence_string",
    # The sandbox saw it happen.
    "behav_network_connect", "behav_file_drop", "behav_child_process",
    "behav_killed", "behav_crash", "behav_failed",
    # Disguised executables and document macros.
    "double_extension", "archive_double_ext", "archive_office_macro",
    "shortcut_remote", "doc_macro", "doc_dde", "eicar",
]


def main():
    src = RULES.read_text(encoding="utf-8")
    if "func ClassifyEvidence" in src:
        print("  already present")
        return 0

    block = (
        "// EvidenceClass is how a finding is presented to the semantic\n"
        "// adjudicator. It is NOT the same as the scoring classification: an\n"
        "// import-based finding counts as capability for the score, but it is\n"
        "// presented as ordinary behaviour to the model. A model that sees\n"
        "// \"payload_indicators: persistence API\" concludes that the file\n"
        "// intends to persist, which is what an installer legitimately does.\n"
        "type EvidenceClass int\n"
        "\n"
        "const (\n"
        "\t// EvidenceCrackExpected is behaviour a crack, an emulator or a\n"
        "\t// utility legitimately has.\n"
        "\tEvidenceCrackExpected EvidenceClass = iota\n"
        "\t// EvidencePayload is a C2 channel, a stolen-data target or an\n"
        "\t// encoded payload. Never normal.\n"
        "\tEvidencePayload\n"
        "\t// EvidenceNeutral is everything else.\n"
        "\tEvidenceNeutral\n"
        ")\n"
        "\n"
        "// ClassifyEvidence reports how a finding should be presented to the\n"
        "// adjudicator.\n"
        "func ClassifyEvidence(rule string) EvidenceClass {\n"
        "\tfor _, r := range []string{"
        + ", ".join(lit(r) for r in CRACK_EXPECTED)
        + "} {\n"
        "\t\tif rule == r {\n"
        "\t\t\treturn EvidenceCrackExpected\n"
        "\t\t}\n"
        "\t}\n"
        "\tfor _, r := range []string{"
        + ", ".join(lit(r) for r in PAYLOAD)
        + "} {\n"
        "\t\tif rule == r {\n"
        "\t\t\treturn EvidencePayload\n"
        "\t\t}\n"
        "\t}\n"
        "\treturn EvidenceNeutral\n"
        "}\n\n"
    )
    anchor = "// Rule classification for the semantic adjudicator."
    if anchor not in src:
        print("  MISS: anchor")
        return 1
    src = src.replace(anchor, block + anchor, 1)
    RULES.write_text(src, encoding="utf-8")
    print("  ok  : ClassifyEvidence")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
