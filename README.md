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

YARA support runs through the system `yara` binary if present (built-in rules are
embedded either way); install YARA 4.x on PATH to enable that layer.

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
