#!/usr/bin/env python3
"""Turn a CrackSentinel calibration dump into a JevLab reliability report
and a fitted probability calibrator for the scanner.

    go run ./cmd/calibrate -manifest corpus.json -root . -dump calibration.json
    python scripts/jevlab_report.py calibration.json -o calibration_report.html

JevLab brings what a hand-rolled threshold sweep cannot:

  - Platt, temperature and histogram calibration, fitted on the fit split
    and scored on an untouched holdout split
  - ECE, MCE and Brier before and after calibration
  - reliability curves
  - Cohen's / Fleiss' kappa between the judges, so the two framings of the
    question are measured for agreement instead of assumed to agree
  - a self-contained HTML report with inline SVG

Two judges are recorded per case: the two framings of the trojanized
question. Their agreement is a measurement, not an assumption.

The script also writes a calibrator JSON that the scanner loads at runtime
with -jev-calibration, so the decision is made on a calibrated probability
instead of a raw score.

Nothing is uploaded anywhere: JevLab is offline and pure standard library.
"""

import argparse
import json
import sys
from datetime import datetime, timezone
from pathlib import Path


def load(dump_path: Path) -> dict:
    with dump_path.open("r", encoding="utf-8") as fh:
        return json.load(fh)


def build_fixture(cal: dict) -> dict:
    """Convert the scanner's dump into a JevLab fixture.

    The fixture declares itself synthetic under Apache-2.0, which is true
    for the reference corpus. A corpus built from a user's own crack
    folders is NOT synthetic and must not be published as a fixture; for
    that case, call the JevLab Python API directly with local arrays.
    """
    items = []
    for i, r in enumerate(cal.get("Results", [])):
        verdict = r.get("Verdict") or {}
        p1 = float(verdict.get("is_trojanized", 0.0))
        p2 = float(verdict.get("is_trojanized_alt", 0.0))
        if p2 <= 0:
            p2 = p1
        truth = int(r.get("Want", 0)) == 0  # LabelMalicious == 0
        split = r.get("Split") or "fit"
        note = r.get("Note") or ""
        det = r.get("DeterministicVerdict") or "?"
        text = f"{r.get('Name', 'case')}: scanner verdict {det}. {note}".strip()
        items.append(
            {
                "id": f"case-{i:03d}",
                "split": split,
                "question_id": "q1",
                "text": text,
                "truth": truth,
                "judgments": {
                    # The decision-level judge: the conservative combination
                    # of the two framings, which is what the scanner acts on.
                    "adjudicator": min(p1, p2),
                    # The two framings separately, so their agreement can be
                    # measured with Cohen's kappa.
                    "framing-a": p1,
                    "framing-b": p2,
                },
            }
        )
    return {
        "schema_version": 1,
        "synthetic": True,
        "license": "Apache-2.0",
        "rubric": {
            "id": "crack-adjudicator",
            "questions": [
                {
                    "id": "q1",
                    "text": "Is this file a trojanized crack, meaning a crack or emulator that carries a malicious payload?",
                }
            ],
        },
        "items": items,
    }


def pick_method(judge: dict, requested: str) -> tuple:
    """Return the method name and its block, choosing the one with the
    best holdout Brier improvement unless one was requested."""
    methods = judge.get("methods", {})
    if requested and requested != "auto":
        if requested not in methods:
            raise SystemExit(f"unknown method {requested!r}; have {list(methods)}")
        return requested, methods[requested]
    best, best_score = None, None
    for name, block in methods.items():
        score = block.get("improvement", {}).get("brier")
        if score is None:
            continue
        if best_score is None or score > best_score:
            best, best_score = name, score
    if best is None:
        return "none", {}
    return best, methods[best]


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("dump", help="the JSON written by cmd/calibrate -dump")
    ap.add_argument("-o", "--out", default="calibration_report.html")
    ap.add_argument(
        "--calibrator-out",
        default="calibration.json",
        help="where to write the fitted calibrator for the scanner",
    )
    ap.add_argument("--method", default="auto", choices=["auto", "platt", "temperature", "histogram"])
    ap.add_argument("--bins", type=int, default=10)
    args = ap.parse_args()

    try:
        from jevlab_oss.calibration import AgreementMatrix, calibrate_fixture
        from jevlab_oss.report import write_report
    except ImportError:
        print(
            "JevLab is not importable. Install it into a virtualenv and run "
            "this script with that interpreter:\n"
            "  python -m venv E:\\tools\\jevlab-venv\n"
            "  E:\\tools\\jevlab-venv\\Scripts\\pip install <jevlab checkout>",
            file=sys.stderr,
        )
        return 2

    cal = load(Path(args.dump))
    fixture = build_fixture(cal)

    fit = sum(1 for i in fixture["items"] if i["split"] == "fit")
    hold = len(fixture["items"]) - fit
    if fit == 0 or hold == 0:
        print("warning: one of the splits is empty; the holdout score is meaningless", file=sys.stderr)

    report = calibrate_fixture(fixture, n_bins=args.bins)

    # Extra measurement: the agreement between the two framings of the
    # question, on the fit split.
    try:
        fit_items = [i for i in fixture["items"] if i["split"] == "fit"]
        ratings = {
            name: [i["judgments"][name] >= 0.5 for i in fit_items]
            for name in ("framing-a", "framing-b")
        }
        report["scanner_agreement"] = AgreementMatrix(ratings).pairwise()
        report["scanner_note"] = (
            "Cohen's kappa between the two framings of the trojanized "
            "question, on the fit split. A low value means the two framings "
            "do not agree and the verdict should be treated as uncertain."
        )
    except Exception as exc:  # pragma: no cover - diagnostic path
        report["scanner_agreement_error"] = str(exc)

    out = write_report(report, args.out)

    judge = report.get("judges", {}).get("adjudicator", {})
    method, block = pick_method(judge, args.method)
    before = block.get("before", {})
    after = block.get("after", {})
    improvement = block.get("improvement", {})
    params = block.get("parameters", {})
    decision = block.get("decision", {})

    print(f"wrote {out}")
    print(f"  judges: {', '.join(sorted(report.get('judges', {})))}")
    print(f"  split : {fit} fit / {hold} holdout")
    print()
    print("  calibration of the decision-level judge (holdout):")
    for name in ("platt", "temperature", "histogram"):
        m = judge.get("methods", {}).get(name)
        if not isinstance(m, dict):
            continue
        b, a = m.get("before", {}), m.get("after", {})
        mark = " <-- selected" if name == method else ""
        print(
            f"    {name:<11} ECE {b.get('ece', 0):.3f} -> {a.get('ece', 0):.3f}   "
            f"Brier {b.get('brier', 0):.3f} -> {a.get('brier', 0):.3f}   "
            f"(brier improvement {m.get('improvement', {}).get('brier', 0):+.4f}){mark}"
        )
    print()
    print(f"  selected method : {method}")
    print(f"  parameters      : {params}")
    print(f"  decision        : threshold {decision.get('threshold')}, "
          f"fit accuracy {decision.get('fit_accuracy')}, "
          f"holdout accuracy {decision.get('holdout_accuracy')}")
    if "scanner_agreement" in report:
        print(f"  framing agreement: {report['scanner_agreement']}")

    # Write the calibrator the scanner loads at runtime.
    if method in ("platt", "temperature") and params:
        calibrator = {
            "method": method,
            "a": params.get("a", 0.0),
            "b": params.get("b", 0.0),
            "threshold": decision.get("threshold", 0.5),
            "ece": after.get("ece", 0.0),
            "mce": after.get("mce", 0.0),
            "brier": after.get("brier", 0.0),
            "margin": cal.get("Margin", 0.0),
            "corpus_size": fit,
            "holdout_size": hold,
            "fitted_at": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        }
        cpath = Path(args.calibrator_out)
        cpath.write_text(json.dumps(calibrator, indent=2) + "\n", encoding="utf-8")
        print()
        print(f"  wrote {cpath}")
        print(f"  use it with:  scanner.exe <folder> -jev -jev-calibration {cpath}")
    else:
        print()
        print("  no calibrator written: the selected method produced no parameters")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
