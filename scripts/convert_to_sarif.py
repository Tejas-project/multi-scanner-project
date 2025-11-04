#!/usr/bin/env python3
import json
import argparse
from pathlib import Path
import uuid
from datetime import datetime


def convert_to_sarif(input_path, output_path):
    data = json.loads(Path(input_path).read_text(encoding="utf-8"))

    rules_seen = set()
    rules = []
    results = []

    severity_map = {
        "CRITICAL": "error",
        "HIGH": "error",
        "MEDIUM": "warning",
        "LOW": "note",
        "UNKNOWN": "none"
    }

    for finding in data:
        rule_id = str(finding.get("id") or f"NOID-{uuid.uuid4()}")
        desc = finding.get("description", "")
        sev = str(finding.get("severity", "UNKNOWN")).upper()
        scanner = finding.get("scanner", "unknown")

        # Build rule (deduplicated)
        if rule_id not in rules_seen:
            rules_seen.add(rule_id)
            rule_entry = {
                "id": rule_id,
                "shortDescription": {"text": desc[:120]},
                "fullDescription": {"text": desc},
                "properties": {
                    "security-severity": sev,
                    "scanner": scanner
                }
            }
            # only include helpUri if it's a valid CVE
            if rule_id.startswith("CVE-"):
                rule_entry["helpUri"] = f"https://nvd.nist.gov/vuln/detail/{rule_id}"

            rules.append(rule_entry)

        # Map severity → SARIF level
        level = severity_map.get(sev, "note")

        results.append({
            "ruleId": rule_id,
            "level": level,
            "message": {"text": desc},
            "locations": [{
                "physicalLocation": {
                    "artifactLocation": {
                        "uri": str(finding.get("location") or "unknown")
                    },
                    "region": {
                        "startLine": 1,
                        "startColumn": 1
                    }
                }
            }],
            "properties": {
                "package": finding.get("package"),
                "version": finding.get("version"),
                "scanner": scanner
            }
        })

    sarif = {
        "version": "2.1.0",
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "runs": [{
            "tool": {
                "driver": {
                    "name": "Multi-Scanner Security Analyzer",
                    "informationUri": "https://github.com/Tejas-project/multi-scanner-project",
                    "rules": rules
                }
            },
            "automationDetails": {
                "id": "multi-scanner-analysis",
                "guid": str(uuid.uuid4())  # valid UUID
            },
            "columnKind": "utf16CodeUnits",
            "results": results
        }]
    }

    Path(output_path).write_text(json.dumps(sarif, indent=2), encoding="utf-8")
    print(f"[+] Valid SARIF file written to {output_path} at {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Convert normalized results to SARIF format.")
    parser.add_argument("--input", required=True, help="Path to normalized JSON results.")
    parser.add_argument("--output", required=True, help="Path to output SARIF file.")
    args = parser.parse_args()
    convert_to_sarif(args.input, args.output)
