# CrackSentinel

Defensive malware scanner for **cracked-game folders** — drag a folder, get a per-file
verdict. Built for the classic problem: pirated game folders are full of trojanized
cracks (keyloggers, stealers, miners, RATs) wrapped around otherwise legitimate
emulators (Goldberg, SmartSteam, RUNE, FLT...).

Pure Go, zero external dependencies, no cgo. Works on Windows, builds anywhere.

## What it does

**Folder-level** (default mode):

```
scanner.exe "D:\Games\SomeCrackedGame"
```

- Walks the whole tree with a small worker pool (default 3 workers, low-memory friendly)
- Skips game assets (`.pak`, `.mp4`, `.uasset`, `.bk2`, ...) and oversized files
- Persistent SHA-256 cache — a re-scan only looks at new files

**Binary-level** (per file, automatic):
- PE analysis: sections + entropy, packer detection, manual import-table parse,
  imphash, Authenticode signature presence, .NET detection
- IOC extraction: Discord webhooks, Telegram bot tokens, hardcoded IP:port,
  PowerShell `-enc`, download cradles, wallet/browser-credential target strings,
  EICAR
- Crack whitelist: known emulator/crack strings subtract suspicion, so a legit
  crack is not flagged while its trojanized twin is
- Score 0–100 → `CLEAN` / `SUSPICIOUS` (>=30) / `MALICIOUS` (>=70)

**Online reputation** (optional): VirusTotal + MalwareBazaar hash lookup with
throttling, auto-backoff on 429, and negative-result caching (second scan = 0 API calls).

**Deep-dive** (per-file, manual): spawns [REA](https://github.com/morluto/rea) +
Ghidra headless to decompile IOC-referencing functions and produce pseudocode evidence.

## Usage

```
# scan a folder
scanner.exe <folder> [-online] [-json report.json] [-md report.md]

# deep static analysis of a flagged file (requires REA MCP + Ghidra)
scanner.exe deep <file.exe> [-out deep.json]
```

Flags: `-workers`, `-max-size` (MB), `-skip-assets=false`, `-exclude .bin,.dat`,
`-online`, `-vt-key` / `VT_API_KEY`, `-mb-key` / `MB_API_KEY`, `-vt-interval`,
`-yara-rules <dir>`, `-no-yara`, `-no-cache`, `-cache <path>`, `-quiet`, `-top N`

## No-install design

Scanning never runs, mounts, or installs anything. It reads bytes, PE headers,
sections, import tables, and strings. The `deep` subcommand adds Ghidra static
disassembly — still execution-free.

All game types are handled by folder scan, and container formats are expanded
headlessly so the *inner* files get the same treatment without extracting by hand:

| Container | Handling |
|---|---|
| `.zip` | stdlib `archive/zip` (always available) |
| `.7z` `.rar` `.iso` `.cab` `.tar` | system `7z` binary (auto-detected, `7z x` with executable-include filters) |
| FreeArc (`fg-*.bin` from FitGirl/DODI repacks) | flagged as `container_freearc` — FreeArc needs its own extractor; the repack's `setup.exe -extract` (manual/elevated) or the FreeArc CLI is required |

Depth is bounded (`-extract-depth`, default 2 levels) with an inner-file budget
(`-extract-mb`, default 500 MB per container), so a 60 GB game does not become a
60 GB temp extraction.

Game-type coverage (AAA ElAmigos/DODI/TENOKE, indies, GOG installers, scene
releases, FitGirl/DODI/DODI-style repacks, emulator cracks):
no per-type special-casing needed — anything that lands as files or as
zip/7z/rar/iso containers is walked and scored.

## Layout

```
cmd/scanner/       CLI (scan + deep subcommands)
internal/scan/     walker, worker pool, scoring pipeline
internal/pe/       PE parsing: sections/entropy, imports, imphash, packer, signature
internal/rules/    detection engine: import IOC table, script IOCs, crack whitelist
internal/online/   VirusTotal / MalwareBazaar client + scoring
internal/yara/     yara CLI runner + embedded builtin rules
internal/deep/     REA MCP deep-dive driver
internal/cache/    JSONL hash cache
internal/report/   console / JSON / Markdown output
```

## Defensive tool

This project is a **detector**, not a weaponizer: it reads, scores, and reports.
No mutation of scanned targets, no payload generation.
