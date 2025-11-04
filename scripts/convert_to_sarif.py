#!/usr/bin/env python3
import json
import argparse
from pathlib import Path
import uuid
from datetime import datetime

def convert_to_sarif(input_path, output_path):
    data = json.loads(Path(input_path).read_text(encoding="utf-8"))

    rules_seen = set()
    results = []
    rules = []

    severity_map = {
        "CRITICAL": "error",
        "HIGH": "error",
        "MEDIUM": "warning",
        "LOW": "note",
        "UNKNOWN": "none"
    }

    for finding in data:
        rule_id = str(finding.get("id") or f"NOID-{uuid.uuid4()}")
        if rule_id not in rules_seen:
            rules_seen.add(rule_id)
            rules.append({
                "id": rule_id,
                "shortDescription": {"text": finding.get("description", "")[:120]},
                "fullDescription": {"text": finding.get("description", "")},
                "helpUri": "https://nvd.nist.gov/vuln/detail/" + rule_id if rule_id.startswith("CVE-") else None,
                "properties": {
                    "security-severity": finding.get("severity", "UNKNOWN"),
                    "scanner": finding.get("scanner", "unknown")
                }
            })

        results.append({
            "ruleId": rule_id,
            "level": severity_map.get(finding.get("severity", "UNKNOWN").upper(), "note"),
            "message": {"text": finding.get("description", "")},
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
                "scanner": finding.get("scanner")
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
                "guid": str(uuid.uuid4())  # unique valid UUID
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
