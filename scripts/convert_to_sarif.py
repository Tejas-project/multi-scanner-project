import json
import argparse
from datetime import datetime
from urllib.parse import quote


def normalize_uri(uri):
    """Return a valid and safe file URI for SARIF."""
    if isinstance(uri, list):  # handle lists of paths
        uri = uri[0] if uri else "unknown-location"
    uri = str(uri)
    uri = uri.replace(" ", "_").replace(":", "_").replace("(", "_").replace(")", "_")
    return f"file:///{quote(uri)}"


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
    """Convert severity to numeric value for SARIF (0.0–10.0)."""
    mapping = {
        "CRITICAL": 9.5,
        "HIGH": 8.0,
        "MEDIUM": 5.0,
        "LOW": 2.5,
        "UNKNOWN": 0.0
    }
    return mapping.get(sev.upper(), 0.0)


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
        description = item.get("description", "").strip()
        severity = item.get("severity", "UNKNOWN").upper()
        package = item.get("package", "unknown-package")
        scanner = item.get("scanner", "unknown-scanner")
        location = item.get("location", "my-app_latest_debian_12.7")

        # Fallback message
        message_text = description if description else f"{vuln_id} detected in {package} by {scanner}"

        # Deduplicate rule entries
        if vuln_id not in rules_dict:
            rule = {
                "id": vuln_id,
                "shortDescription": {"text": description[:120] or vuln_id},
                "fullDescription": {"text": description or "No detailed description available."},
                "helpUri": f"https://nvd.nist.gov/vuln/detail/{vuln_id}",
                "properties": {
                    "security-severity": str(severity_to_score(severity)),
                    "scanner": scanner
                }
            }
            rules_dict[vuln_id] = rule

        # Build SARIF result
        result = {
            "ruleId": vuln_id,
            "level": severity_to_level(severity),
            "message": {"text": message_text},
            "locations": [
                {
                    "physicalLocation": {
                        "artifactLocation": {
                            "uri": normalize_uri(location)
                        },
                        "region": {"startLine": 1, "startColumn": 1}
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

    # Construct SARIF output
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


if __name__ == "__main__":
    main()
