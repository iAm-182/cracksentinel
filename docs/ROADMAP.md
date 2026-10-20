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
| Semantic adjudication (Jev / TypeSafe System One) | done |
| CI (vet + test + gofmt + multi-platform build) + release bundle | done |

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

### The semantic adjudication layer

The deterministic engine answers "does this file contain known-bad
artefacts?". It cannot answer "is this crack carrying a payload?", because
that is a question about meaning.

A crack emulator hooks the game's API, patches the executable and ships
unsigned DLLs. A trojanized crack does all of that AND exfiltrates
credentials. Both produce the same import table.

Jev (TypeSafe's System One model) is given the same evidence, but
**structured**: the findings are split into `expected_for_a_crack` (hooking
imports, emulator exports, whitelist hits), `payload_indicators` (C2
channels, credential theft, persistence, encoded payloads) and
`other_findings` (everything else). The split is the whole point — fed a
flat list of findings, the model calls every emulator a trojan.

The bucket assignment lives in `internal/rules/classify.go` and the bar for
`payload_indicators` is deliberately high. Dual-use behaviour — reading a
file, copying a hash to the clipboard, listing a directory, downloading an
update, hiding a window — is **not** payload evidence. A checksum verifier,
an archive tool and a crack launcher all do those things. Putting them in
the payload bucket is what made the adjudicator call legitimate tools
trojans.

Measured against real cases:

| File | Deterministic | Adjudication |
|---|---|---|
| crack carrying a Discord webhook + stealer targets | 100 MALICIOUS | `trojanized` 100%, malicious 93% → action *delete* |
| crack emulator, 1212 SteamAPI exports, no payload | 100 MALICIOUS | `legitimate_crack` 78%, malicious 26% |
| QuickSFV.EXE, a checksum verifier inside a repack | 69 MALICIOUS | `legitimate_utility` 93%, malicious 12% |

The last row is the real false positive from the live FitGirl triage: a
checksum tool was reported MALICIOUS because it copies a hash to the
clipboard, enumerates files and carries a large embedded blob.

### The adjudication is advisory

Jev never replaces the deterministic score by default. Its answer is
recorded next to the deterministic verdict so a reviewer sees both.
`-jev-override` lets a confident verdict change the final verdict, and even
then only a verdict above `-jev-confidence` (default 0.7) can act, and only
in the ambiguous band. A model is not evidence.

The calls are budgeted (`-jev-max-files`, default 8) and bounded
(`-jev-concurrency`, default 4), so a folder full of flagged files cannot
turn into a hundred API calls. 429 and 529 are retried with exponential
backoff; 400/401/413/415/422 are not, because a request error cannot be
fixed by trying again.

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
