#!/usr/bin/env python3
"""
scripts/normalize.py

Enhanced normalizer for Trivy, Grype, and Hadolint JSON outputs.
- Tolerates minified, NDJSON, or nested JSON.
- Normalizes vulnerability IDs for consistent consensus.
- Merges duplicate findings across scanners.
"""

import json
import argparse
import hashlib
from pathlib import Path
from typing import Any, Dict, List, Optional

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
    return SEVERITY_MAP.get(str(level).upper(), "LOW")


def safe_load(path: Path) -> Optional[Any]:
    try:
        text = path.read_text(encoding="utf-8").strip()
    except FileNotFoundError:
        print(f"[!] file missing: {path}")
        return None

    if not text:
        return []

    try:
        return json.loads(text)
    except json.JSONDecodeError:
        objs = []
        for i, line in enumerate(text.splitlines(), start=1):
            line = line.strip()
            if not line:
                continue
            try:
                objs.append(json.loads(line))
            except json.JSONDecodeError:
                print(f"[!] warning: unable to parse line {i} in {path}; skipping")
                continue
        if objs:
            return objs

        try:
            inner = json.loads(text)
            if isinstance(inner, str):
                return json.loads(inner)
        except Exception:
            pass

        print(f"[!] json decode error for {path}")
        return None


# ----------------------------------------------------------------------
# Trivy Parser (with unified ID normalization)
# ----------------------------------------------------------------------
def parse_trivy(path: Path) -> List[Dict[str, Any]]:
    data = safe_load(path)
    findings: List[Dict[str, Any]] = []
    if data is None:
        return findings

    def _add(vuln, target=None):
        vid = (vuln.get("VulnerabilityID") or vuln.get("ID") or "").upper().strip()
        findings.append({
            "id": vid,
            "package": vuln.get("PkgName") or vuln.get("PackageName"),
            "version": vuln.get("InstalledVersion") or vuln.get("Version"),
            "severity": normalize_severity(vuln.get("Severity")),
            "scanner": "trivy",
            "description": vuln.get("Description") or vuln.get("Title") or "",
            "fixed_version": vuln.get("FixedVersion"),
            "location": target,
        })

    if isinstance(data, dict):
        for result in data.get("Results", []):
            vulns = result.get("Vulnerabilities") or []
            for vuln in vulns:
                if isinstance(vuln, dict):
                    _add(vuln, result.get("Target"))
    elif isinstance(data, list):
        for entry in data:
            if isinstance(entry, dict):
                if "Results" in entry:
                    for result in entry.get("Results", []):
                        for vuln in result.get("Vulnerabilities", []):
                            _add(vuln, result.get("Target"))
                elif "VulnerabilityID" in entry or "ID" in entry:
                    _add(entry)
    else:
        print(f"[!] unexpected trivy JSON structure in {path}")
    return findings


# ----------------------------------------------------------------------
# Grype Parser (with unified ID normalization)
# ----------------------------------------------------------------------
def parse_grype(path: Path) -> List[Dict[str, Any]]:
    data = safe_load(path)
    findings: List[Dict[str, Any]] = []
    if data is None:
        return findings

    matches = []
    if isinstance(data, dict):
        matches = data.get("matches") or data.get("vulnerabilities") or [data]
    elif isinstance(data, list):
        matches = data
    else:
        print(f"[!] unexpected grype JSON type in {path}")
        return findings

    for match in matches:
        if not isinstance(match, dict):
            continue

        vuln = match.get("vulnerability", match)
        artifact = match.get("artifact", {})

        vid = (
            vuln.get("id")
            or vuln.get("VulnerabilityID")
            or vuln.get("ID")
            or ""
        ).upper().strip()

        pkg_name = (
            artifact.get("name")
            or artifact.get("Package")
            or match.get("package")
            or match.get("PkgName")
        )

        severity = normalize_severity(vuln.get("severity") or vuln.get("Severity"))
        description = vuln.get("description") or vuln.get("Description") or ""
        fixes = None
        if isinstance(vuln.get("fix"), dict):
            versions = vuln.get("fix", {}).get("versions", [])
            fixes = versions[0] if versions else None

        findings.append({
            "id": vid,
            "package": pkg_name,
            "version": artifact.get("version") or match.get("Version"),
            "severity": severity,
            "scanner": "grype",
            "description": description,
            "fixed_version": fixes,
            "location": artifact.get("locations"),
        })

    return findings


# ----------------------------------------------------------------------
# Hadolint Parser (unchanged but consistent with schema)
# ----------------------------------------------------------------------
def parse_hadolint(path: Path) -> List[Dict[str, Any]]:
    data = safe_load(path)
    findings: List[Dict[str, Any]] = []
    if data is None:
        return findings

    if isinstance(data, list):
        for issue in data:
            if not isinstance(issue, dict):
                continue
            findings.append({
                "id": issue.get("code"),
                "package": "Dockerfile",
                "version": None,
                "severity": normalize_severity(issue.get("level")),
                "scanner": "hadolint",
                "description": issue.get("message") or "",
                "fixed_version": None,
                "location": f"{issue.get('file', 'Dockerfile')}:{issue.get('line', '')}"
            })
    elif isinstance(data, dict):
        for key, issue in data.items():
            if isinstance(issue, dict):
                findings.append({
                    "id": issue.get("code") or key,
                    "package": "Dockerfile",
                    "version": None,
                    "severity": normalize_severity(issue.get("level")),
                    "scanner": "hadolint",
                    "description": issue.get("message") or "",
                    "fixed_version": None,
                    "location": f"{issue.get('file', 'Dockerfile')}:{issue.get('line', '')}"
                })
    else:
        print(f"[!] unexpected hadolint JSON structure in {path}")

    return findings


# ----------------------------------------------------------------------
# Helper utilities
# ----------------------------------------------------------------------
def make_key(f: Dict[str, Any]) -> str:
    if f.get("id"):
        key = f"{f.get('id')}|{f.get('package') or ''}|{f.get('version') or ''}"
    else:
        digest = hashlib.sha1(
            (f.get("package", "") + (f.get("version") or "") + (f.get("description") or "")).encode("utf-8")
        ).hexdigest()
        key = f"NOID|{digest}"
    return key


def merge_findings(existing: Dict[str, Any], new: Dict[str, Any]) -> Dict[str, Any]:
    scanners = set(s.strip() for s in existing.get("scanner", "").split(",") if s.strip())
    scanners.update(s.strip() for s in new.get("scanner", "").split(",") if s.strip())
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
            existing["description"] = (
                existing.get("description", "") + "\n\n" + new.get("description")
            ).strip()

    return existing


# ----------------------------------------------------------------------
# Main entrypoint
# ----------------------------------------------------------------------
def main():
    parser = argparse.ArgumentParser(description="Normalize scanner JSON outputs to a single JSON file.")
    parser.add_argument("--trivy", default="trivy-results.json", help="Path to Trivy JSON")
    parser.add_argument("--grype", default="grype-results.json", help="Path to Grype JSON")
    parser.add_argument("--hadolint", default="hadolint-results.json", help="Path to Hadolint JSON")
    parser.add_argument("--output", default="normalized-results.json", help="Output JSON path")
    args = parser.parse_args()

    findings: List[Dict[str, Any]] = []
    findings += parse_trivy(Path(args.trivy))
    findings += parse_grype(Path(args.grype))
    findings += parse_hadolint(Path(args.hadolint))

    print(f"[+] Parsed {len(findings)} raw findings from inputs.")

    unique: Dict[str, Dict[str, Any]] = {}
    for f in findings:
        key = make_key(f)
        if key not in unique:
            unique[key] = f
        else:
            unique[key] = merge_findings(unique[key], f)

    final = list(unique.values())
    Path(args.output).write_text(json.dumps(final, indent=2), encoding="utf-8")
    print(f"[+] Wrote {len(final)} normalized findings to {args.output}")


if __name__ == "__main__":
    main()
