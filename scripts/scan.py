#!/usr/bin/env python3
"""Local CLI to eyeball Layer 1 findings for a policy file or the sample set.

Offline. No AWS, no LLM. Used to manually verify the deterministic engine.

Usage:
    python scripts/scan.py samples/03_messy_deploy_role.json
    python scripts/scan.py --all          # scan every file in samples/
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

# Make backend/ importable when run from the repo root.
REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT))

from backend.checks import run_checks_safe  # noqa: E402

SEVERITY_TAG = {
    "CRITICAL": "[CRIT]",
    "HIGH": "[HIGH]",
    "MEDIUM": "[MED ]",
    "LOW": "[LOW ]",
}


def scan_file(path: Path) -> int:
    """Print findings for one policy file. Returns the number of findings."""
    print(f"\n=== {path.name} ===")
    result = run_checks_safe(path.read_text())
    if not result["ok"]:
        print(f"  ERROR: {result['error']}")
        return 0
    findings = result["findings"]
    if not findings:
        print("  No findings. Policy looks clean.")
        return 0
    for f in findings:
        loc = "doc" if f["statement_index"] < 0 else f"stmt {f['statement_index']}"
        tag = SEVERITY_TAG.get(f["severity"], f["severity"])
        print(f"  {tag} {f['rule_id']} ({loc})")
        print(f"        {f['detail']}")
    return len(findings)


def main() -> int:
    parser = argparse.ArgumentParser(description="PolicyLens deterministic scanner.")
    parser.add_argument("path", nargs="?", help="Policy JSON file to scan.")
    parser.add_argument(
        "--all", action="store_true", help="Scan every file in samples/."
    )
    args = parser.parse_args()

    if args.all:
        samples = sorted((REPO_ROOT / "samples").glob("*.json"))
        total = sum(scan_file(p) for p in samples)
        print(f"\nScanned {len(samples)} files, {total} findings total.")
        return 0

    if not args.path:
        parser.error("provide a policy file path or use --all")

    scan_file(Path(args.path))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
