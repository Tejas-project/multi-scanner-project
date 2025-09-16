#!/usr/bin/env python3
"""
scripts/consensus.py
Generate a consensus report from normalized scanner results.

Usage:
  python scripts/consensus.py --input normalized-results.json --output consensus-results.json
"""

import argparse
import json
from pathlib import Path
from typing import List, Dict, Any

# Optional: map severities to numeric values for comparison
SEVERITY_ORDER = {
    "LOW": 1,
    "MEDIUM": 2,
    "HIGH": 3,
    "CRITICAL": 4
}

def make_key(finding: Dict[str, Any]) -> str:
    """
    Create a unique key for a finding, similar to normalize.py
    """
    if finding.get("id"):
        return f"{finding.get('id')}|{finding.get('package') or ''}|{finding.get('version') or ''}"
    else:
        return f"NOID|{finding.get('package') or ''}"

def main():
    parser = argparse.ArgumentParser(description="Generate consensus from normalized scanner JSON.")
    parser.add_argument("--input", default="normalized-results.json", help="Path to normalized JSON")
    parser.add_argument("--output", default="consensus-results.json", help="Output JSON path")
    args = parser.parse_args()

    input_path = Path(args.input)
    output_path = Path(args.output)

    data = json.loads(input_path.read_text(encoding="utf-8"))

    consensus_dict = {}

    for f in data:
        key = make_key(f)
        if key not in consensus_dict:
            # Initialize consensus entry
            consensus_dict[key] = {
                **f,
                "final_severity": f["severity"],
                "scanners_reporting": [f["scanner"]] if f.get("scanner") else [],
                "confidence": 1
            }
        else:
            existing = consensus_dict[key]
            # Merge scanners
            scanners = set(existing["scanners_reporting"])
            if f.get("scanner"):
                scanners.update([s.strip() for s in f["scanner"].split(",")])
            existing["scanners_reporting"] = sorted(scanners)
            existing["confidence"] = len(existing["scanners_reporting"])

            # Pick the highest severity
            if SEVERITY_ORDER.get(f["severity"], 0) > SEVERITY_ORDER.get(existing["final_severity"], 0):
                existing["final_severity"] = f["severity"]

            # Merge description if new info
            if f.get("description") and f["description"] not in existing.get("description", ""):
                if len(existing.get("description", "")) < 200:
                    existing["description"] = (existing.get("description", "") + "\n\n" + f["description"]).strip()

            # Merge fixed_version if missing
            if not existing.get("fixed_version") and f.get("fixed_version"):
                existing["fixed_version"] = f["fixed_version"]

            # Merge location if missing
            if not existing.get("location") and f.get("location"):
                existing["location"] = f["location"]

    # Write final consensus results
    final_list: List[Dict[str, Any]] = list(consensus_dict.values())
    output_path.write_text(json.dumps(final_list, indent=2), encoding="utf-8")
    print(f"[+] Wrote {len(final_list)} consensus findings to {output_path}")

if __name__ == "__main__":
    main()
