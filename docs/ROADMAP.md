# CrackSentinel — roadmap & design notes

## Where the project is

| Capability | Status |
|---|---|
| Folder scan, worker pool, asset skip, hash cache | done |
| PE static analysis (sections, entropy, imports, imphash, packer, signature) | done |
| String / IOC engine (43 import APIs, 11 string regexes, EICAR) | done |
| Kind-aware rules (script / shortcut / document / archive) | done |
| Crack + emulator whitelist, Steam-emu cap | done |
| Container expansion, recursive walk, pre-extract size budget | done |
| Online reputation (VirusTotal + MalwareBazaar) with throttle + backoff | done |
| REA/Ghidra deep-dive, manual + auto-escalation | done |
| Behavioural detonation (Docker + wine + strace) | done |
| Watch mode, quarantine, webhook alerts | done |
| Real YARA layer (builtin rules embedded) | done |
| UPX auto-unpack + rescan | done |
| Shared reputation (Cloudflare Worker + D1) | done |
| JSON / Markdown / standalone HTML reports | done |
| CI (vet + test + multi-platform build) + release bundle | done |

## Design notes

### Why the score is a pure function

The scoring policy decides whether a user's game folder is reported as
MALICIOUS. A silent regression there either scares people off (false
positives) or defeats the product (false negatives). It therefore lives in
`internal/scan.computeScore` — a pure function with no filesystem or network
access — and is covered by table-driven tests that pin the 30/70 boundaries,
the whitelist discount and the emulator cap.

### Whitelist does not rescue a strong signal

A crack/emulator whitelist hit discounts 15 points, but only while the score
is below 60. A whitelisted string never rescues a file that is already
strongly malicious.

### The emulator cap

A Steam-emulator-like DLL (many `SteamAPI_*` exports) is suspicious by
construction — hooking imports are its job — so it is capped at 59
(SUSPICIOUS) and stays reviewable. A trojanized twin carries payload strings
(C2 URLs, encoded commands), and those veto the cap upstream. The whitelist
entry is `EMU_STEAMAPI`; the cap is applied in `computeScore`.

### Cross-engine de-duplication

The internal engine and YARA detect the same malware families. Without
de-duplication a single Discord webhook scores 40 (internal regex) + 20
(YARA) = 60 points and pushes an otherwise moderate file into MALICIOUS.
`rules.YaraCategory` maps a YARA rule name to the internal category it
duplicates; a YARA hit for an already-flagged category is recorded as a
finding but contributes 0 severity.

### Container expansion is recursive, and budgeted

Two real defects were fixed here:

1. Only the archive's **top level** was walked, so a payload at
   `setup/bin/payload.exe` was invisible. The walk is now recursive and every
   inner finding is reported with its path relative to the archive root.
2. The extraction budget was applied **after** 7-Zip had already written
   everything to disk, so a 30 GB repack could fill the volume. The archive is
   now listed first (`7z l -slt`) and the projected size is checked before
   anything is written.

Two 7-Zip subtleties are encoded in `internal/scan/container.go`:

- the `r` flag is required (`-ir!*.exe`); without it 7-Zip disables recursion
  and reports "No files to process" for a nested payload
- on the **list** command `-i!` filters the listing down to nothing, so the
  listing is done unfiltered and the extension filter is applied in Go

### Behavioural sandbox

`docker run --network none` with `seccomp=unconfined` + `SYS_PTRACE` so
strace can see the syscalls, a 1 GB memory cap and a PID limit. The sample is
staged as `/det/target.exe` read-only; the report is built from `exit.log`,
`stdout.log`, `files.log` and the `sys.*` strace streams.

A failed detonation is reported as a finding. Otherwise "no behavioural
findings" would be indistinguishable from "the sandbox never ran".

## Known limits

- FreeArc (`fg-*.bin`) repacks need the FreeArc CLI; the scanner reports the
  container and scans the sibling installer separately.
- REA/Ghidra deep-dive takes ~100–150 s per file and is only practical on
  small, suspicious files.
- The shared-reputation worker is opt-in and only ever receives hashes,
  verdicts and scores.
