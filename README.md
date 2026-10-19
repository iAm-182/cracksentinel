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
`-deep-threshold` / `-deep-max` / `-deep-budget` (REA auto-escalation, 0 = off),
`-detonate` / `-detonate-min` / `-detonator-dir` (Docker+wine behavioural sandbox),
`-no-unpack` (disable UPX auto-unpack).

Optional external tools (auto-detected, everything works without them):
`yara`/`yara64` in PATH enables the real YARA layer (builtin rules always
embedded), `upx` in PATH enables UPX auto-unpack-and-rescan, `7z` enables
7z/rar/iso container expansion, `docker` + the `detonator/` image enables
behavioural detonation of mid-score PEs.

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
internal/scan/     walker, worker pool, scoring pipeline, container expansion
internal/rules/    detection engine: import IOC table, string IOCs, kind rules
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
