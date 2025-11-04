#!/usr/bin/env python3
"""
scripts/convert_to_sarif.py

Converts normalized-results.json into valid SARIF format for GitHub Security tab.
Handles complex or non-string 'location' fields safely.
"""

import json
import argparse
from pathlib import Path
from datetime import datetime

def safe_uri(location):
    """Ensure artifactLocation.uri is a valid string path"""
    if isinstance(location, str):
        return location
    elif isinstance(location, list) and location:
        # If it's a list of dicts or strings
        if isinstance(location[0], dict) and "path" in location[0]:
            return str(location[0]["path"])
        else:
            return str(location[0])
    elif isinstance(location, dict):
        return str(location.get("path") or location.get("Target") or location.get("file") or "unknown")
    elif location is None:
        return "unknown"
    else:
        return str(location)

def main():
    parser = argparse.ArgumentParser(description="Convert normalized-results.json into SARIF format")
    parser.add_argument("--input", default="normalized-results.json", help="Input JSON file")
    parser.add_argument("--output", default="results.sarif", help="Output SARIF file")
    args = parser.parse_args()

    data_path = Path(args.input)
    if not data_path.exists():
        raise FileNotFoundError(f"{args.input} not found")

    findings = json.loads(data_path.read_text(encoding="utf-8"))

    # SARIF skeleton
    sarif = {
        "version": "2.1.0",
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "runs": [{
            "tool": {
                "driver": {
                    "name": "Multi-Scanner Security Framework",
                    "informationUri": "https://github.com/Tejas-project/multi-scanner-project",
                    "rules": []
                }
            },
            "results": []
        }]
    }

    rule_ids = {}
    for f in findings:
        rule_id = f.get("id", "UNKNOWN")
        description = f.get("description", "")
        severity = f.get("severity", "LOW").upper()
        scanner = f.get("scanner", "unknown")
        uri = safe_uri(f.get("location"))

        # Add rule metadata (once per unique ID)
        if rule_id not in rule_ids:
            sarif["runs"][0]["tool"]["driver"]["rules"].append({
                "id": rule_id,
                "shortDescription": {"text": description[:120]},
                "helpUri": "https://nvd.nist.gov/vuln/detail/" + rule_id if rule_id.startswith("CVE") else None,
                "properties": {"scanner": scanner, "severity": severity}
            })
            rule_ids[rule_id] = True

        # Add finding result
        sarif["runs"][0]["results"].append({
            "ruleId": rule_id,
            "level": severity.lower(),
            "message": {"text": description},
            "locations": [{
                "physicalLocation": {
                    "artifactLocation": {"uri": uri},
                    "region": {"startLine": 1}
                }
            }]
        })

    Path(args.output).write_text(json.dumps(sarif, indent=2), encoding="utf-8")
    print(f"[+] Valid SARIF file written to {args.output} at {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")

if __name__ == "__main__":
    main()
