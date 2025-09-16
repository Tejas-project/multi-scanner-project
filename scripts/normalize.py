#!/usr/bin/env python3
"""
scripts/normalize.py
Normalize JSON outputs from Trivy, Grype, and Hadolint into a single JSON array.
Usage:
  python scripts/normalize.py \
    --trivy trivy-results.json \
    --grype grype-results.json \
    --hadolint hadolint-results.json \
    --output normalized-results.json
"""

import argparse
import json
import hashlib
from pathlib import Path
from typing import List, Dict, Any, Optional

SEVERITY_MAP = {
    "UNKNOWN": "LOW",
    "NEGLIGIBLE": "LOW",
    "LOW": "LOW",
    "MEDIUM": "MEDIUM",
    "MODERATE": "MEDIUM",
    "HIGH": "HIGH",
    "CRITICAL": "CRITICAL",
    "ERROR": "HIGH",
    "WARNING": "MEDIUM",
    "INFO": "LOW",
}


def normalize_severity(level: Optional[str]) -> str:
    if not level:
        return "LOW"
    return SEVERITY_MAP.get(level.upper(), "LOW")


def safe_load(path: Path) -> Optional[Any]:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except FileNotFoundError:
        print(f"[!] file missing: {path}")
        return None
    except json.JSONDecodeError as e:
        print(f"[!] json decode error for {path}: {e}")
        return None


def parse_trivy(path: Path) -> List[Dict[str, Any]]:
    data = safe_load(path)
    findings = []
    if not data:
        return findings
    for result in data.get("Results", []):
        for vuln in result.get("Vulnerabilities", []) or []:
            findings.append({
                "id": vuln.get("VulnerabilityID"),
                "package": vuln.get("PkgName"),
                "version": vuln.get("InstalledVersion"),
                "severity": normalize_severity(vuln.get("Severity")),
                "scanner": "trivy",
                "description": vuln.get("Description") or vuln.get("Title") or "",
                "fixed_version": vuln.get("FixedVersion"),
                "location": result.get("Target")
            })
    return findings


def parse_grype(path: Path) -> List[Dict[str, Any]]:
    data = safe_load(path)
    findings = []
    if not data:
        return findings
    for match in data.get("matches", []) or []:
        vuln = match.get("vulnerability", {}) or {}
        artifact = match.get("artifact", {}) or {}
        fix_versions = vuln.get("fix", {}).get("versions", []) if vuln.get("fix") else []
        findings.append({
            "id": vuln.get("id"),
            "package": artifact.get("name"),
            "version": artifact.get("version"),
            "severity": normalize_severity(vuln.get("severity")),
            "scanner": "grype",
            "description": vuln.get("description") or "",
            "fixed_version": fix_versions[0] if fix_versions else None,
            "location": artifact.get("locations") or artifact.get("matchDetails") or None
        })
    return findings


def parse_hadolint(path: Path) -> List[Dict[str, Any]]:
    data = safe_load(path)
    findings = []
    if not data:
        return findings
    for issue in data or []:
        findings.append({
            "id": issue.get("code"),
            "package": "Dockerfile",
            "version": None,
            "severity": normalize_severity(issue.get("level")),
            "scanner": "hadolint",
            "description": issue.get("message") or "",
            "fixed_version": None,
            "location": issue.get("file") or issue.get("line")
        })
    return findings


def make_key(f: Dict[str, Any]) -> str:
    if f.get("id"):
        key = f"{f.get('id')}|{f.get('package') or ''}|{f.get('version') or ''}"
    else:
        digest = hashlib.sha1((f.get("package","") + (f.get("version") or "") + (f.get("description") or "")).encode("utf-8")).hexdigest()
        key = f"NOID|{digest}"
    return key


def merge_findings(existing: Dict[str, Any], new: Dict[str, Any]) -> Dict[str, Any]:
    scanners = set([s.strip() for s in str(existing.get("scanner", "")).split(",") if s.strip()])
    scanners.update([s.strip() for s in str(new.get("scanner", "")).split(",") if s.strip()])
    existing["scanner"] = ", ".join(sorted(scanners))

    order = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1}
    if order.get(new.get("severity"), 0) > order.get(existing.get("severity"), 0):
        existing["severity"] = new.get("severity")

    if not existing.get("fixed_version") and new.get("fixed_version"):
        existing["fixed_version"] = new.get("fixed_version")

    if not existing.get("location") and new.get("location"):
        existing["location"] = new.get("location")

    if new.get("description") and new.get("description") not in existing.get("description", ""):
        if len(existing.get("description", "")) < 200:
            existing["description"] = (existing.get("description", "") + "\n\n" + new.get("description")).strip()

    return existing


def main():
    parser = argparse.ArgumentParser(description="Normalize scanner JSON outputs to a single JSON file.")
    parser.add_argument("--trivy", default="trivy-results.json", help="Path to Trivy JSON")
    parser.add_argument("--grype", default="grype-results.json", help="Path to Grype JSON")
    parser.add_argument("--hadolint", default="hadolint-results.json", help="Path to Hadolint JSON")
    parser.add_argument("--output", default="normalized-results.json", help="Output JSON path")
    args = parser.parse_args()

    trivy_path = Path(args.trivy)
    grype_path = Path(args.grype)
    hadolint_path = Path(args.hadolint)
    out_path = Path(args.output)

    findings = []
    findings += parse_trivy(trivy_path)
    findings += parse_grype(grype_path)
    findings += parse_hadolint(hadolint_path)

    print(f"[+] Parsed {len(findings)} raw findings from inputs.")

    unique = {}
    for f in findings:
        key = make_key(f)
        if key not in unique:
            unique[key] = f
        else:
            unique[key] = merge_findings(unique[key], f)

    final = list(unique.values())
    out_path.write_text(json.dumps(final, indent=2), encoding="utf-8")
    print(f"[+] Wrote {len(final)} normalized findings to {out_path}")


if __name__ == "__main__":
    main()
