#!/usr/bin/env python3
"""Fetch fresh high-confidence malware SHA-256 IOCs and update
signatures/live-signatures.json + internal/sigfeed/default_signatures.json.

Sources:
1. Optional authenticated abuse.ch MalwareBazaar API (when MB_API_KEY env is set)
   targeting fake-crack families (LummaStealer, StealC, Rhadamanthys, Vidar, AsyncRAT, XWorm).
2. Keyless, hourly-updated multi-source consensus SHA-256 feed (`romainmarcoux/malicious-hash`,
   ordered highest-confidence / multi-tracker consensus first) — works out-of-the-box in
   GitHub Actions with zero external secrets!
"""

import datetime as dt
import json
import os
import re
import urllib.parse
import urllib.request
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
SIG_FILES = [
    ROOT / "signatures" / "live-signatures.json",
    ROOT / "internal" / "sigfeed" / "default_signatures.json",
]

ROMAIN_TOP_SHA256_URL = "https://raw.githubusercontent.com/romainmarcoux/malicious-hash/main/full-hash-sha256-aa.txt"
MB_API_URL = "https://mb-api.abuse.ch/api/v1/"
MB_TAGS = ["LummaStealer", "StealC", "Rhadamanthys", "Vidar", "AsyncRAT", "XWorm", "RemcosRAT", "DarkGate"]

MAX_HASHES = 1200
SHA256_RE = re.compile(r"^[0-9a-f]{64}$")


def fetch_mb_api_hashes(api_key: str) -> list[dict]:
    out: list[dict] = []
    seen = set()
    for tag in MB_TAGS:
        try:
            data = urllib.parse.urlencode({"query": "get_taginfo", "tag": tag, "limit": "100"}).encode("utf-8")
            req = urllib.request.Request(
                MB_API_URL,
                data=data,
                headers={"User-Agent": "CrackSentinel-ThreatFeed/2.2", "Auth-Key": api_key},
                method="POST",
            )
            with urllib.request.urlopen(req, timeout=25) as resp:
                payload = json.loads(resp.read().decode("utf-8", errors="replace"))
            for row in payload.get("data") or []:
                h = str(row.get("sha256_hash", "")).strip().lower()
                if SHA256_RE.match(h) and h not in seen:
                    seen.add(h)
                    sig = str(row.get("signature") or tag)
                    out.append({"sha256": h, "family": sig, "severity": 95})
        except Exception as exc:
            print(f"warning: MalwareBazaar tag {tag} lookup skipped: {exc}")
    return out


def fetch_consensus_feed_hashes(limit: int = 1000) -> list[dict]:
    """Read only the first ~128 KB of the sorted multi-tracker SHA-256 feed (top ~1,000
    highest-consensus malware hashes reported across multiple CTI trackers)."""
    req = urllib.request.Request(
        ROMAIN_TOP_SHA256_URL,
        headers={
            "User-Agent": "CrackSentinel-ThreatFeed/2.2",
            "Range": "bytes=0-131071",
        },
    )
    with urllib.request.urlopen(req, timeout=30) as resp:
        chunk = resp.read(131072).decode("utf-8", errors="replace")

    out: list[dict] = []
    seen = set()
    for line in chunk.splitlines():
        h = line.strip().lower()
        if SHA256_RE.match(h) and h not in seen:
            seen.add(h)
            out.append({
                "sha256": h,
                "family": "MultiSource-Malware-IOC",
                "severity": 92,
            })
            if len(out) >= limit:
                break
    return out


def main() -> int:
    base_doc = json.loads(SIG_FILES[0].read_text(encoding="utf-8"))
    prev_hashes = [h.get("sha256", "").lower() for h in base_doc.get("hashes", [])]

    eicar_hash = "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f"
    merged: list[dict] = [{
        "sha256": eicar_hash,
        "family": "EICAR-Standard-Test",
        "severity": 100,
    }]
    seen = {eicar_hash}

    mb_key = os.environ.get("MB_API_KEY", "").strip()
    if mb_key:
        for item in fetch_mb_api_hashes(mb_key):
            if item["sha256"] not in seen and len(merged) < MAX_HASHES:
                seen.add(item["sha256"])
                merged.append(item)

    try:
        for item in fetch_consensus_feed_hashes(limit=MAX_HASHES - len(merged)):
            if item["sha256"] not in seen and len(merged) < MAX_HASHES:
                seen.add(item["sha256"])
                merged.append(item)
    except Exception as exc:
        print(f"warning: consensus feed fetch failed: {exc}")

    new_hash_list = [h["sha256"] for h in merged]
    if new_hash_list == prev_hashes:
        print(f"Signature feed already current ({len(merged)} hashes).")
        return 0

    now = dt.datetime.now(dt.timezone.utc)
    ver = now.strftime("%Y.%m.%d.%H%M")
    base_doc["version"] = ver
    base_doc["updated_at"] = now.strftime("%Y-%m-%dT%H:%M:%SZ")
    base_doc["hashes"] = merged

    formatted = json.dumps(base_doc, indent=2) + "\n"
    for target in SIG_FILES:
        target.write_text(formatted, encoding="utf-8")
    print(f"Updated live signature feed to v{ver}: {len(merged)} verified SHA-256 IOCs.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
