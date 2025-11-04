#!/usr/bin/env python3
"""
convert_to_sarif.py — Converts normalized JSON findings to GitHub SARIF format.
Fixes:
- Ensures "security-severity" is a stringified numeric value (GitHub-specific)
- Avoids duplicate rule IDs
- Ensures helpUri is always a valid string
"""

import json
import argparse
import hashlib
import uuid
from datetime import datetime
from pathlib import Path

# Severity → Numeric CVSS mapping (stringified)
SEVERITY_SCORES = {
    "CRITICAL": "9.0",
    "HIGH": "7.0",
    "MEDIUM": "5.0",
    "LOW": "3.0",
    "UNKNOWN": "1.0"
}

def normalize_severity(sev: str) -> str:
    """Return GitHub-compatible numeric string for severity."""
    return SEVERITY_SCORES.get(sev.upper(), "1.0")

def make_rule(find):
    """Create a SARIF rule entry."""
    rule_id = find.get("id") or hashlib.sha1(
        f"{find.get('package','')}{find.get('description','')}".encode("utf-8")
    ).hexdigest()

    description = find.get("description") or "No description available."
    help_uri = (
        f"https://nvd.nist.gov/vuln/detail/{rule_id}"
        if rule_id.startswith("CVE")
        else "https://nvd.nist.gov/"
    )

    return {
        "id": rule_id,
        "shortDescription": {"text": description[:100]},
        "fullDescription": {"text": description},
        "helpUri": str(help_uri),
        "properties": {
            "security-severity": normalize_severity(find.get("severity", "UNKNOWN")),
            "scanner": find.get("scanner", "unknown")
        }
    }

def make_result(find):
    """Create SARIF result entry."""
    severity = find.get("severity", "LOW").upper()
    level = "error" if severity in ["CRITICAL", "HIGH"] else "warning" if severity == "MEDIUM" else "note"

    return {
        "ruleId": find.get("id") or "NOID",
        "level": level,
        "message": {"text": find.get("description", "No details available.")},
        "locations": [{
            "physicalLocation": {
                "artifactLocation": {
                    "uri": str(find.get("location") or "Dockerfile")
                },
                "region": {
                    "startLine": 1,
                    "startColumn": 1,
                    "endLine": 1,
                    "endColumn": 1
                }
            }
        }],
        "properties": {
            "package": find.get("package"),
            "version": find.get("version"),
            "scanner": find.get("scanner")
        }
    }

def main():
    parser = argparse.ArgumentParser(description="Convert normalized results to SARIF format.")
    parser.add_argument("--input", required=True, help="Path to normalized JSON results")
    parser.add_argument("--output", required=True, help="Path to SARIF output file")
    args = parser.parse_args()

    findings = json.loads(Path(args.input).read_text(encoding="utf-8"))

    rules_map = {}
    results = []

    for f in findings:
        rule_id = f.get("id") or "NOID"
        if rule_id not in rules_map:
            rules_map[rule_id] = make_rule(f)
        results.append(make_result(f))

    sarif = {
        "version": "2.1.0",
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "Multi-Scanner Security Analyzer",
                        "informationUri": "https://github.com/Tejas-project/multi-scanner-project",
                        "rules": list(rules_map.values())
                    }
                },
                "automationDetails": {
                    "id": "multi-scanner-analysis",
                    "guid": str(uuid.uuid4())
                },
                "columnKind": "utf16CodeUnits",
                "results": results
            }
        ]
    }

    Path(args.output).write_text(json.dumps(sarif, indent=2), encoding="utf-8")
    print(f"[+] Valid SARIF file written to {args.output} at {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")

if __name__ == "__main__":
    main()
