#!/usr/bin/env python3
"""
convert_to_sarif.py — Converts normalized JSON findings to GitHub SARIF format.

Fixes:
- Ensures security-severity is a stringified number
- Ensures helpUri is always a string
- Removes duplicate rules
- Sanitizes invalid or container-based URIs for GitHub Code Scanning
"""

import json
import argparse
import hashlib
import uuid
from datetime import datetime
from pathlib import Path
from urllib.parse import quote

# ---- Severity Mappings ----
SEVERITY_SCORES = {
    "CRITICAL": "9.0",
    "HIGH": "7.0",
    "MEDIUM": "5.0",
    "LOW": "3.0",
    "UNKNOWN": "1.0"
}


def normalize_severity(sev: str) -> str:
    """Return GitHub-compatible numeric string for severity."""
    return SEVERITY_SCORES.get(str(sev).upper(), "1.0")


def sanitize_uri(uri):
    """
    Ensure URI is SARIF-compliant (file:// scheme or simple path).
    - If it's a dict/list, flatten and escape it.
    - If it has colon (like 'my-app:latest'), quote it.
    """
    if not uri:
        return "file://unknown"

    # Flatten dicts or lists from scanners
    if isinstance(uri, (dict, list)):
        try:
            uri = json.dumps(uri, ensure_ascii=False)[:200]
        except Exception:
            uri = str(uri)

    uri = str(uri)

    # Replace "my-app:" or image tags with file-safe name
    if ":" in uri and not uri.startswith("file://"):
        uri = uri.replace(":", "_")

    # Quote invalid URL characters
    return f"file://{quote(uri)}"


def make_rule(find):
    rule_id = find.get("id") or hashlib.sha1(
        f"{find.get('package','')}{find.get('description','')}".encode("utf-8")
    ).hexdigest()

    desc = find.get("description") or "No description available."
    help_uri = (
        f"https://nvd.nist.gov/vuln/detail/{rule_id}"
        if rule_id.startswith("CVE")
        else "https://nvd.nist.gov/"
    )

    return {
        "id": rule_id,
        "shortDescription": {"text": desc[:120]},
        "fullDescription": {"text": desc},
        "helpUri": str(help_uri),
        "properties": {
            "security-severity": normalize_severity(find.get("severity")),
            "scanner": find.get("scanner", "unknown")
        }
    }


def make_result(find):
    severity = find.get("severity", "LOW").upper()
    level = (
        "error" if severity in ["CRITICAL", "HIGH"]
        else "warning" if severity == "MEDIUM"
        else "note"
    )

    return {
        "ruleId": find.get("id") or "NOID",
        "level": level,
        "message": {"text": find.get("description", "No details available.")},
        "locations": [{
            "physicalLocation": {
                "artifactLocation": {
                    "uri": sanitize_uri(find.get("location"))
                },
                "region": {
                    "startLine": 1,
                    "startColumn": 1
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

    rules = {}
    results = []

    for f in findings:
        rule_id = f.get("id") or "NOID"
        if rule_id not in rules:
            rules[rule_id] = make_rule(f)
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
                        "rules": list(rules.values())
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
