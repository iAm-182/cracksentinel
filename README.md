# CrackSentinel

Defensive malware scanner for **cracked-game folders** — drag a folder, get a
per-file verdict. Built for the classic problem: pirated game folders are full
of trojanized cracks (keyloggers, stealers, miners, RATs) wrapped around
otherwise legitimate emulators (Goldberg, SmartSteam, RUNE, FLT...).

Pure Go, zero external dependencies, no cgo. Works on Windows, builds anywhere.

## What it does

**Folder-level** (default mode):

```
scanner.exe "D:\Games\SomeCrackedGame"
```

- Walks the whole tree with a small worker pool (default 3 workers, low-memory friendly)
- Skips game assets (`.pak`, `.mp4`, `.uasset`, `.bk2`, ...) and oversized files
- Persistent SHA-256 cache — a re-scan only looks at new files

**Single-file mode**:

```
scanner.exe "D:\Games\SomeCrackedGame\crack\setup.exe" -html report.html
```

Scans exactly that file (and expands it if it is a container) — it does not
widen the scope to the parent folder.

**Binary-level** (per file, automatic):
- PE analysis: sections + entropy, packer detection, manual import-table parse,
  imphash, Authenticode signature presence, .NET / Go detection
- IOC extraction: Discord webhooks, Telegram bot tokens, hardcoded IP:port,
  PowerShell `-enc`, download cradles, wallet/browser-credential target strings,
  EICAR
- Crack whitelist: known emulator/crack strings subtract suspicion, so a legit
  crack is not flagged while its trojanized twin is
- Score 0–100 → `CLEAN` / `SUSPICIOUS` (>=30) / `MALICIOUS` (>=70)

**Kind-aware rules**: scripts (`.bat/.cmd/.ps1/.vbs/.js/.hta`), shortcuts
(`.lnk/.url/.pif`), office documents (`.doc/.docm/.xlsm`) and containers each
get their own rule set, so a Word file that merely mentions "powershell" is
not treated as a malicious script, while a `.lnk` that runs
`powershell -w hidden -enc …` is.

**Container expansion** (no install, no execution):

| Container | Handling |
|---|---|
| `.zip` | stdlib `archive/zip` (always available) |
| `.7z` `.rar` `.iso` `.cab` `.tar` | system `7z` binary (auto-detected) |
| FreeArc (`fg-*.bin` from FitGirl/DODI repacks) | flagged as `container_freearc` — FreeArc needs its own extractor; the repack's `setup.exe -extract` (manual/elevated) or the FreeArc CLI is required |

Archives are walked **recursively**, so a payload at `setup/bin/payload.exe`
inside a repack is found and reported with its path inside the container. The
archive is listed before extraction, so a container that would write more disk
than the budget allows is reported instead of filling the volume.

**Online reputation** (optional): VirusTotal + MalwareBazaar hash lookup with
throttling, auto-backoff on 429, and negative-result caching (second scan = 0 API calls).

**Deep-dive** (per-file, manual): spawns [REA](https://github.com/morluto/rea) +
Ghidra headless to decompile IOC-referencing functions and produce pseudocode evidence.

**Behavioural detonation** (optional): runs the sample inside an isolated
Docker + wine + strace sandbox with no network, and reports outbound connects,
dropped files and spawned children.

**Shared reputation** (optional, opt-in): community telemetry via a Cloudflare
Worker + D1. The scanner looks up each file hash (`shared_rep` finding when 2+
reporters agree) and contributes its own verdicts afterwards. Only hashes +
verdicts + scores leave the machine — no filenames, no paths.

**Semantic adjudication** (optional): the hard problem in this domain is
telling a *legitimate* crack from its *trojanized twin*. Both are unsigned,
both hook processes. With `-jev` the scanner asks [Jev](https://docs.typesafe.ai)
(TypeSafe's System One model) to weigh the evidence, splitting it into what a
crack legitimately does (hooking the game's API, emulator exports) and what a
crack never does (C2 channels, credential theft, persistence). The answer is
recorded next to the deterministic verdict and shown in the console, the JSON
and the HTML report.

**Claim validation**: every payload claim is put to the model on its own. A
claim the model will not support loses its severity, so an unsupported
conclusion cannot push a file into MALICIOUS. The review is always recorded
(`jev_claims_reviewed`), so "every claim held" can be told apart from
"nobody looked".

The adjudication is **advisory**: it never replaces the deterministic score
unless you pass `-jev-override`, and even then only a confident verdict can
act. A model is not evidence.

```
scanner.exe "D:\Games\SomeGame" -jev
```

Needs `TYPESAFE_API_KEY` in the environment. `-jev-min` / `-jev-max` bound the
score band that is adjudicated (default 30–100, the ambiguous middle),
`-jev-max-files` caps the number of calls per scan.

### Measuring the adjudicator

Thresholds picked by intuition are not thresholds. `cmd/calibrate` measures
the adjudicator against a labelled corpus and reports the confusion matrix,
precision, recall, F1, the class margin and the threshold that maximises F1:

```
go run ./cmd/calibrate -manifest corpus.json -root . -dump calibration.json
```

```
corpus          : 7 case(s), 7 correct (100%)
threshold       : 0.50  (best on this corpus: 0.27 -> F1 1.00)
margin          : +0.40 (classes are separated)
confusion       : TP=4 FP=0 TN=3 FN=0
```

`corpus.json` is meant to grow: every real crack folder that gets triaged
adds its files with a label, and the next run measures the tool against your
own data instead of against a guess.

### The raw probability is not a probability

The model's answer is a score, not a probability. On the reference corpus the
expected calibration error of the raw answer was **0.195**: when the model
said 0.6 the file was malicious every single time, and when it said 0.06 it
was clean every single time. The ranking is good, the numbers are not, and a
threshold cannot be compared against them directly.

[JevLab](https://github.com/omnirogue/jevlab) fits a proper calibrator on a
labelled corpus — Platt scaling, temperature scaling or histogram
calibration — and scores it on an untouched holdout split. The fitted
parameters are written to a calibrator file that the scanner loads at
runtime, so the decision is made on a calibrated probability:

```
python scripts/jevlab_report.py calibration.json -o calibration_report.html
```

```
  calibration of the decision-level judge (holdout):
    platt       ECE 0.195 -> 0.002   Brier 0.056 -> 0.000   (brier improvement +0.0562) <-- selected
    temperature ECE 0.195 -> 0.004   Brier 0.056 -> 0.000   (brier improvement +0.0562)
    histogram   ECE 0.195 -> 0.292   Brier 0.056 -> 0.087   (brier improvement -0.0306)
```

```
scanner.exe <folder> -jev -jev-calibration calibration.json
```

The HTML report is self-contained: reliability curves with inline SVG, the
agreement matrix between the two framings of the question, the bias tables
and the fit-selected threshold. JevLab is offline, pure standard library and
performs no network calls.

## Usage

```
# scan a folder
scanner.exe <folder> [-online] [-json report.json] [-md report.md] [-html report.html]

# scan one file
scanner.exe <file> [-html report.html]

# deep static analysis of a flagged file (requires REA MCP + Ghidra)
scanner.exe deep <file.exe> [-out deep.json]

# continuous monitoring with quarantine + alerts
scanner.exe watch <folder> -interval 60 -quarantine -notify-url <webhook>

# build identity
scanner.exe -version
```

Run `scanner.exe -help` for the full flag list.

Flags: `-workers`, `-max-size` (MB), `-skip-assets=false`, `-exclude .bin,.dat`,
`-online`, `-vt-key` / `VT_API_KEY`, `-mb-key` / `MB_API_KEY`, `-vt-interval`,
`-yara-rules <dir>`, `-no-yara`, `-no-cache`, `-cache <path>`, `-quiet`, `-top N`,
`-json`, `-md`, `-html`, `-extract-depth`, `-extract-mb`, `-tmp-dir`,
`-jev`, `-jev-min`, `-jev-max`, `-jev-override`, `-jev-confidence`,
`-jev-max-files`, `-jev-concurrency`, `-jev-model`, `-jev-url`,
`-deep-threshold` / `-deep-max` / `-deep-budget` (REA auto-escalation, 0 = off),
`-detonate` / `-detonate-min` / `-detonator-dir` (Docker+wine behavioural sandbox),
`-no-unpack` (disable UPX auto-unpack).

Optional external tools (auto-detected, everything works without them):
`yara`/`yara64` in PATH enables the real YARA layer (builtin rules always
embedded), `upx` in PATH enables UPX auto-unpack-and-rescan, `7z` enables
7z/rar/iso container expansion, `docker` + the `detonator/` image enables
behavioural detonation of mid-score PEs.

## The host antivirus may flag this tool

A malware scanner is, to a machine learning classifier, a textbook
information stealer: it embeds the names of the hooked APIs
(`GetAsyncKeyState`, `CryptUnprotectData`, `WriteProcessMemory`), the
credential targets (`wallet.dat`, `Login Data`) and the C2 patterns it looks
for. Windows Defender flagged the shipped `scanner.exe` as
`Trojan:Win32/Bearfoos.B!ml` and quarantined it, which means the tool could
not scan anything on a machine with a working antivirus.

Three things are done about it:

- the detection indicators in `internal/rules` and `internal/deep` are
  XOR-obfuscated and decoded at run time, so the shipped binary does not
  carry them in plaintext (`scripts/obfuscate_indicators.py` regenerates
  them; the behaviour is unchanged and covered by the tests)
- the built-in YARA rules are embedded base64-encoded, for the same reason
- the EICAR marker is assembled from fragments at run time, because it is
  the single most heavily matched string on the planet

The release builds are also stripped (`-ldflags "-s -w"`), which makes the
binary 30% smaller and carries less string surface. After all of this the
shipped binary contains none of the indicator strings and the local
Windows Defender no longer flags it, with identical scan results.

### If it still happens to you

Ranked by how much they actually help:

1. **Add an exclusion.** Every security vendor ships this instruction for
   their own tools:

   ```powershell
   # Windows Defender, per folder (elevated PowerShell)
   Add-MpPreference -ExclusionPath "E:\tools\cracksentinel"
   ```

2. **Run with `-no-yara`.** The internal engine keeps working; the only
   thing lost is the YARA layer. If the rules file is what your antivirus
   is eating, this is the switch.

3. **Build it yourself.** The source is public and the indicators are
   obfuscated, so a locally built binary is clean as well:

   ```
   go build -trimpath -ldflags "-s -w" -o scanner.exe ./cmd/scanner
   ```

4. **Use the signed or package-manager build.** A signed binary and a
   winget entry both have a known hash and an established reputation,
   which is what removes the problem rather than working around it. See
   "Signing" below.

### Signing

The proper fix is a publisher signature: Defender and SmartScreen treat a
valid signature as an identity claim instead of guessing from the binary.
`scripts/sign.ps1` signs the release bundle with either a code signing
certificate or Azure Trusted Signing:

```powershell
scripts\sign.ps1 -File dist\cracksentinel-1.3.0-windows-amd64.zip -PfxFile cert.pfx -PfxPassword $env:PFX_PASSWORD
scripts\sign.ps1 -File ... -TrustedSigning -AccountUrl <url> -TenantId <tenant> -CertificateProfileName <profile>
```

### Package manager

`scripts/winget-manifest.ps1 -Version 1.3.0` generates the winget manifest
from a published release. A package manager entry has a known hash, is
reviewed before it ships and builds a reputation over time, which is the
longest-term answer to the whole problem.

## What a real folder test changed

The first test on a real folder (a Desktop with 131 files) found five false
positives and one false negative, and every fix came from that test rather
than from theory:

- a file that **cannot execute** cannot be a payload — a base64 PowerShell
  command in a notes file stops counting towards the score
- **capability is not intent** — the import-based findings (what the file
  *can* do) are capped, the string-based findings (what it *does*) are not.
  A crack emulator has capability and no intent; a trojanized crack has
  both
- generic input APIs (`MapVirtualKeyA`, `GetKeyState`) are not keyloggers
- substrings are not words — `MENU_MNEMONICS` matched the wallet rule and
  `SSL_CTX_get_keylog_callback` matched the keylogger rule
- a **packed** binary is not a clean binary — sections with a virtual size
  but no data on disk, plus a high-entropy payload section, is the
  signature of a crypter, and a trojanized crack is usually encrypted for
  exactly that reason

On that folder the result went from 2 MALICIOUS (both false positives) to
0, with the genuine "worth a look" files still reported, and the malware
fixtures still scoring exactly as before.

The same real files were put through the semantic adjudicator, and it is
weaker than the deterministic engine: F1 0.73, precision 0.57, and the
classes still overlap. It calls a game library and a game cheat
trojanized. That is why the adjudication stays advisory, and why the
default confidence for an override is 0.9 rather than 0.7.

## The signature is checked, not assumed

A file that carries an Authenticode certificate is not automatically
legitimate, and a file without one is not automatically malicious. A
trojanized repack ships a real signature next to an injected payload, and
the certificate table is still there.

So the signature is verified: the Authenticode PE image hash is computed
(the digest over the file with the checksum field, the certificate table
entry and the certificate table itself excluded) and compared against the
digest in the signed attributes. The result is one of:

| Result | Meaning |
|---|---|
| `intact` | signed by a named publisher, content matches the signature — a legitimate tool |
| `mismatch` | **the file was modified after it was signed** — nothing else in the scanner can see this |
| `none` | no signature |

Only an `intact` signature may lower a file's score. A mismatch is a
finding in the other direction.

```
[40] signature_mismatch: the file claims a signature from "Microsoft Corporation"
    but the content no longer matches it - it was modified after signing
```

Pure Go: `encoding/asn1` for the PKCS#7 blob, `crypto/x509` for the
certificates. No cgo, no external tool, no dependency.

## The game data is not a blind spot

In a repack the game data is one huge blob — 3.8 GB for The Liar Princess and
the Blind Prince, which is 99% of the bytes in the folder. The scanner used to
skip a file that was too large to read, which meant the largest and least
examined file in the folder was the one most likely to hide something.

So a file that is larger than the analysis window is searched for embedded
executables: the bytes are scanned for an `MZ` header with a real PE header
behind it, and anything found is extracted and analysed like any other
binary. The findings of the embedded image are reported against the file that
carries it.

```
[MALICIOUS] score=100  data.dat
    [32] embedded_pe: an executable is embedded at offset 104857600 (x64, about 42.0 KB)
    [40] discord_webhook: [embedded] Discord webhook URL: https://discord.com/...
    [30] ps_encoded: [embedded] powershell -enc SQBFAFgAKAAoAE4AZQ...
    [15] persistence_string: [embedded] schtasks /create /tn upd /tr payload.bat
```

The search runs at memory speed (about 400 MB/s) and is only applied where
the scanner would otherwise be blind, so it costs nothing on the normal path.
`-carve` turns it off, `-carve-max-mb` bounds it.

The extraction deliberately runs to the end of the file and not to the end of
the section table: a PE can carry an overlay after its last section, and that
overlay is where the indicators often sit.

## Reports

- **console** — verdict + score + top findings per file
- **JSON** (`-json`) — full machine-readable summary
- **Markdown** (`-md`) — table for pasting into an issue or a chat
- **HTML** (`-html`) — standalone, offline, filterable/sortable report with
  every finding per file. No external assets, so it opens from a USB stick on
  an air-gapped machine.

## No-install design

Scanning never runs, mounts, or installs anything on the host. It reads bytes,
PE headers, sections, import tables, and strings. The `deep` subcommand adds
Ghidra static disassembly — still execution-free. The only layer that executes
anything is the opt-in `-detonate` sandbox, which runs the sample inside a
container with no network access.

## Layout

```
cmd/scanner/       CLI (scan + deep + watch subcommands)
cmd/calibrate/    measures the adjudicator against a labelled corpus
internal/scan/     walker, worker pool, scoring pipeline, container expansion
internal/rules/    detection engine: import IOC table, string IOCs, kind rules
internal/jev/      semantic adjudication client (TypeSafe System One)
internal/obf/      indicator obfuscation for the shipped binary
internal/pe/       PE parsing: sections/entropy, imports, imphash, packer, signature
internal/online/   VirusTotal / MalwareBazaar client + scoring
internal/telemetry/ shared-reputation client (lookup + batch report)
internal/yara/     yara CLI runner + embedded builtin rules
internal/deep/     REA MCP deep-dive driver
internal/sandbox/  Docker + wine + strace behavioural detonation
internal/cache/    JSONL hash cache
internal/report/   console / JSON / Markdown / HTML output
internal/version/  build identity (ldflags-injected)
worker/            Cloudflare Worker + D1 shared-reputation backend
scripts/           packaging scripts for a release bundle
docs/              roadmap and design notes
```

## Development

```
go vet ./...
go test ./...
go build -o scanner.exe ./cmd/scanner
scripts\package.ps1            # build a distributable zip (Windows)
bash scripts/package.sh        # build a distributable zip (Linux/macOS/CI)
```

The scoring policy lives in one pure function (`internal/scan.computeScore`)
and is pinned down by table-driven tests, because it decides whether a user's
game folder is reported as MALICIOUS.

## Defensive tool

This project is a **detector**, not a weaponizer: it reads, scores, and reports.
No mutation of scanned targets, no payload generation.
