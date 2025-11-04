#!/usr/bin/env python3
"""
convert_to_sarif.py

Converts normalized scanner results into a valid SARIF file
for upload to GitHub Code Scanning.
Supports Trivy, Grype, Hadolint results merged via normalize.py.
"""

import json
import argparse
from datetime import datetime
from pathlib import Path

# -------------------- Severity → SARIF Level Mapping --------------------
def map_severity_to_level(severity):
    """Map scanner severities to SARIF-compliant levels."""
    sev = (severity or "").upper()
    if sev in ["CRITICAL", "HIGH"]:
        return "error"
    elif sev in ["MEDIUM"]:
        return "warning"
    elif sev in ["LOW"]:
        return "note"
    else:
        return "none"

# -------------------- Build SARIF result entries --------------------
def build_sarif_results(findings):
    """Convert normalized findings list into SARIF results array."""
    results = []
    for f in findings:
        # Extract a valid URI (must be string for SARIF)
        location_value = f.get("location") or f.get("package") or "unknown"
        if not isinstance(location_value, str):
            location_value = str(location_value)

        # Build result entry
        result = {
            "ruleId": str(f.get("id", "UNKNOWN")),
            "level": map_severity_to_level(f.get("severity")),
            "message": {
                "text": f.get("description", "No description provided.")
            },
            "locations": [{
                "physicalLocation": {
                    "artifactLocation": {
                        "uri": location_value
                    }
                }
            }]
        }
        results.append(result)
    return results

# -------------------- Generate SARIF structure --------------------
def generate_sarif(findings):
    """Create a valid SARIF v2.1.0 document."""
    return {
        "version": "2.1.0",
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "runs": [{
            "tool": {
                "driver": {
                    "name": "Multi-Scanner Security Analyzer",
                    "informationUri": "https://github.com/aquasecurity/trivy",
                    "rules": []
                }
            },
            "automationDetails": {
                "id": "multi-scanner",
                "guid": "multi-scanner-run"
            },
            "results": build_sarif_results(findings),
            "columnKind": "utf16",
            "properties": {
                "timestamp": datetime.utcnow().isoformat() + "Z"
            }
        }]
    }

# -------------------- CLI entrypoint --------------------
def main():
    parser = argparse.ArgumentParser(description="Convert normalized results to SARIF format.")
    parser.add_argument("--input", required=True, help="Path to normalized-results.json")
    parser.add_argument("--output", default="results.sarif", help="Output SARIF file path")
    args = parser.parse_args()

    input_path = Path(args.input)
    output_path = Path(args.output)

    if not input_path.exists():
        print(f"[!] Input file not found: {input_path}")
        return

    # Load normalized JSON
    with open(input_path, "r", encoding="utf-8") as f:
        findings = json.load(f)

    # Generate SARIF data
    sarif = generate_sarif(findings)

    # Write to file
    with open(output_path, "w", encoding="utf-8") as f:
        json.dump(sarif, f, indent=2)

    print(f"[+] Valid SARIF file written to {output_path} at {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")

if __name__ == "__main__":
    main()
