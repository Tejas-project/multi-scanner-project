#!/usr/bin/env python3
import json
import argparse
import uuid
from datetime import datetime

# SARIF-compliant severity → level mapping
SARIF_LEVELS = {
    "CRITICAL": "error",
    "HIGH": "error",
    "MEDIUM": "warning",
    "LOW": "note",
    "UNKNOWN": "none",
}


def to_sarif_level(sev):
    """Convert severity to valid SARIF level."""
    return SARIF_LEVELS.get(sev.upper(), "note")


def sanitize_text(text):
    """Escape problematic characters and strip control codes."""
    if not text:
        return ""
    return str(text).replace("\r", "").replace("\n", " ").strip()


def convert_to_sarif(input_file, output_file):
    with open(input_file, "r", encoding="utf-8") as f:
        findings = json.load(f)

    results = []
    rules = []

    for f_item in findings:
        rule_id = f_item.get("id", "UNKNOWN")
        sev = f_item.get("severity", "LOW").upper()
        message = sanitize_text(f_item.get("description", "No description provided."))
        package = f_item.get("package", "N/A")
        scanner = f_item.get("scanner", "unknown")

        # Make sure artifact URI is always a string
        location_uri = str(f_item.get("location") or f"{scanner}:unknown")

        results.append(
            {
                "ruleId": rule_id,
                "level": to_sarif_level(sev),
                "message": {"text": message},
                "locations": [
                    {
                        "physicalLocation": {
                            "artifactLocation": {"uri": location_uri},
                            "region": {
                                "startLine": 1,
                                "startColumn": 1,
                                "endLine": 1,
                                "endColumn": 1,
                            },
                        }
                    }
                ],
                "properties": {
                    "package": package,
                    "severity": sev,
                    "scanner": scanner,
                },
            }
        )

        # Optional: Add a rule entry for GitHub Code Scanning UI
        rules.append(
            {
                "id": rule_id,
                "name": f"{rule_id} ({scanner})",
                "shortDescription": {"text": f"Vulnerability {rule_id} ({sev})"},
                "fullDescription": {"text": message[:300]},
                "helpUri": "https://nvd.nist.gov/vuln/detail/" + rule_id if rule_id.startswith("CVE") else "",
                "properties": {"security-severity": sev},
            }
        )

    sarif = {
        "version": "2.1.0",
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "Multi-Scanner Security Analyzer",
                        "informationUri": "https://github.com/Tejas-project/multi-scanner-project",
                        "rules": rules,
                    }
                },
                "originalUriBaseIds": {
                    "SRCROOT": {"uri": "file:///github/workspace/", "description": {"text": "Repository root"}}
                },
                "versionControlProvenance": [
                    {
                        "repositoryUri": "https://github.com/Tejas-project/multi-scanner-project",
                        "branch": "main",
                    }
                ],
                "automationDetails": {
                    "id": "multi-scanner-analysis",
                    # ✅ Always a valid RFC4122 UUID
                    "guid": str(uuid.uuid4()),
                },
                "columnKind": "utf16CodeUnits",
                "results": results,
            }
        ],
    }

    with open(output_file, "w", encoding="utf-8") as out:
        json.dump(sarif, out, indent=2)

    print(f"[+] Valid SARIF file written to {output_file} at {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Convert normalized JSON findings to SARIF format.")
    parser.add_argument("--input", required=True, help="Path to normalized JSON file")
    parser.add_argument("--output", required=True, help="Path to SARIF output file")
    args = parser.parse_args()

    convert_to_sarif(args.input, args.output)
