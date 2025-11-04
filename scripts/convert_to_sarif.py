#!/usr/bin/env python3
"""
convert_to_sarif.py — converts normalized JSON results to SARIF 2.1.0 format
so GitHub can display scanner findings under the "Code scanning alerts" tab.
"""

import json
import argparse
from datetime import datetime

def main():
    parser = argparse.ArgumentParser(description="Convert normalized JSON findings to SARIF format")
    parser.add_argument("--input", required=True, help="Path to normalized JSON file")
    parser.add_argument("--output", required=True, help="Output SARIF file path")
    args = parser.parse_args()

    with open(args.input, "r") as f:
        findings = json.load(f)

    sarif_results = []
    for fdata in findings:
        rule_id = fdata.get("id") or "NO-ID"
        message = fdata.get("description", "No description provided")
        severity = fdata.get("severity", "LOW").lower()
        level = {
            "critical": "error",
            "high": "error",
            "medium": "warning",
            "low": "note",
        }.get(severity, "note")

        sarif_results.append({
            "ruleId": rule_id,
            "level": level,
            "message": {"text": message},
            "locations": [{
                "physicalLocation": {
                    "artifactLocation": {
                        "uri": fdata.get("location") or "unknown"
                    },
                    "region": {"startLine": 1}
                }
            }]
        })

    sarif_doc = {
        "version": "2.1.0",
        "$schema": "https://schemastore.azurewebsites.net/schemas/json/sarif-2.1.0-rtm.5.json",
        "runs": [{
            "tool": {
                "driver": {
                    "name": "Multi-Scanner (Trivy+Grype+Hadolint)",
                    "informationUri": "https://github.com/aquasecurity/trivy",
                    "rules": []
                }
            },
            "results": sarif_results,
            "columnKind": "utf16",
            "invocations": [{
                "executionSuccessful": True,
                "startTimeUtc": datetime.utcnow().isoformat() + "Z"
            }]
        }]
    }

    with open(args.output, "w") as f:
        json.dump(sarif_doc, f, indent=2)

    print(f"[+] SARIF report generated: {args.output}")

if __name__ == "__main__":
    main()
