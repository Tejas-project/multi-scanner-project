import json
import argparse
import hashlib
from datetime import datetime
from urllib.parse import quote

def normalize_uri(uri: str) -> str:
    """Return safe file URI for SARIF"""
    uri = uri.replace(" ", "_").replace(":", "_").replace("(", "_").replace(")", "_")
    return f"file:///{quote(uri)}"

def main():
    parser = argparse.ArgumentParser(description="Convert normalized vulnerability data to SARIF format")
    parser.add_argument("--input", required=True, help="Path to normalized JSON file")
    parser.add_argument("--output", required=True, help="Path to output SARIF file")
    args = parser.parse_args()

    with open(args.input, "r") as f:
        data = json.load(f)

    results = []
    rules_dict = {}

    for item in data:
        vuln_id = item.get("id", "UNKNOWN_ID")
        description = item.get("description", "No detailed description provided.")
        severity = item.get("severity", "UNKNOWN").upper()
        package = item.get("package", "unknown-package")
        scanner = item.get("scanner", "unknown-scanner")
        location = item.get("location", "my-app_latest_debian_12.7")

        # Required message.text field
        message_text = description if description.strip() else f"{vuln_id} detected in {package} ({scanner})"

        # Create SARIF rule entry (deduplicated)
        if vuln_id not in rules_dict:
            rule = {
                "id": vuln_id,
                "shortDescription": {"text": description[:120]},
                "fullDescription": {"text": description},
                "helpUri": f"https://nvd.nist.gov/vuln/detail/{vuln_id}",
                "properties": {
                    "security-severity": str(severity_to_score(severity)),
                    "scanner": scanner
                }
            }
            rules_dict[vuln_id] = rule

        # Create SARIF result entry
        result = {
            "ruleId": vuln_id,
            "level": severity_to_level(severity),
            "message": {"text": message_text},  # <-- REQUIRED field
            "locations": [
                {
                    "physicalLocation": {
                        "artifactLocation": {
                            "uri": normalize_uri(location)
                        },
                        "region": {
                            "startLine": 1,
                            "startColumn": 1
                        }
                    }
                }
            ],
            "properties": {
                "package": package,
                "severity": severity,
                "scanner": scanner
            }
        }
        results.append(result)

    # Assemble SARIF structure
    sarif = {
        "version": "2.1.0",
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "Multi-Scanner Security Analyzer",
                        "informationUri": "https://github.com/Tejas-project/multi-scanner-project",
                        "rules": list(rules_dict.values())
                    }
                },
                "columnKind": "utf16CodeUnits",
                "results": results
            }
        ]
    }

    with open(args.output, "w") as f:
        json.dump(sarif, f, indent=2)

    print(f"[+] Valid SARIF file written to {args.output} at {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")


def severity_to_level(sev: str) -> str:
    sev = sev.upper()
    if sev == "CRITICAL":
        return "error"
    elif sev == "HIGH":
        return "error"
    elif sev == "MEDIUM":
        return "warning"
    elif sev == "LOW":
        return "note"
    else:
        return "none"


def severity_to_score(sev: str) -> float:
    """Convert severity to numeric value (SARIF security-severity expects a float between 0.0–10.0)."""
    sev = sev.upper()
    mapping = {
        "CRITICAL": 9.5,
        "HIGH": 8.0,
        "MEDIUM": 5.0,
        "LOW": 2.5,
        "UNKNOWN": 0.0
    }
    return mapping.get(sev, 0.0)


if __name__ == "__main__":
    main()
