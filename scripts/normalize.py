#!/usr/bin/env python3
"""
scripts/normalize.py

Robust normalizer for Trivy, Grype, and Hadolint JSON outputs.
This script tolerates:
 - minified (single-line) JSON
 - newline-delimited JSON (one JSON object per line)
 - top-level dicts or lists
 - empty outputs (e.g. Hadolint -> [])
It logs warnings instead of crashing and always writes a normalized-results.json list.
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
    """
    Load JSON robustly:
    - Try json.load on full content
    - If that fails, try line-delimited JSON parsing
    - If that fails, return None and print a warning
    """
    try:
        text = path.read_text(encoding="utf-8").strip()
    except FileNotFoundError:
        print(f"[!] file missing: {path}")
        return None

    if not text:
        # Empty file is valid (e.g. hadolint -> [])
        return []

    # Try full parse first
    try:
        return json.loads(text)
    except json.JSONDecodeError:
        # Try line-delimited JSON (one JSON object per line)
        objs = []
        for i, line in enumerate(text.splitlines(), start=1):
            line = line.strip()
            if not line:
                continue
            try:
                objs.append(json.loads(line))
            except json.JSONDecodeError:
                # skip unparseable lines
                print(f"[!] warning: unable to parse line {i} in {path}; skipping")
                continue
        if objs:
            return objs

        # As a last-ditch attempt, sometimes the file contains a single JSON string that itself encodes JSON
        # e.g., "\"{...}\"" -> try to decode twice
        try:
            inner = json.loads(text)
            if isinstance(inner, str):
                try:
                    return json.loads(inner)
                except Exception:
                    pass
        except Exception:
            pass

        print(f"[!] json decode error for {path} and no line-delimited JSON found")
        return None


def parse_trivy(path: Path) -> List[Dict[str, Any]]:
    data = safe_load(path)
    findings: List[Dict[str, Any]] = []
    if data is None:
        return findings

    # Trivy standard output is a dict with "Results": [ { "Target":..., "Vulnerabilities": [...] }, ... ]
    if isinstance(data, dict) and "Results" in data:
        for result in data.get("Results") or []:
            if not isinstance(result, dict):
                continue
            vulns = result.get("Vulnerabilities") or []
            # Some Trivy versions may put vulnerabilities directly as a list at top-level
            for vuln in vulns or []:
                if not isinstance(vuln, dict):
                    continue
                findings.append({
                    "id": vuln.get("VulnerabilityID") or vuln.get("ID"),
                    "package": vuln.get("PkgName") or vuln.get("PackageName"),
                    "version": vuln.get("InstalledVersion") or vuln.get("Version"),
                    "severity": normalize_severity(vuln.get("Severity")),
                    "scanner": "trivy",
                    "description": vuln.get("Description") or vuln.get("Title") or "",
                    "fixed_version": vuln.get("FixedVersion"),
                    "location": result.get("Target")
                })
    elif isinstance(data, list):
        # Some outputs may be a list of vulnerability dicts or results
        for entry in data:
            if not isinstance(entry, dict):
                continue
            # If entry looks like a vulnerability object:
            if "VulnerabilityID" in entry or "ID" in entry:
                findings.append({
                    "id": entry.get("VulnerabilityID") or entry.get("ID"),
                    "package": entry.get("PkgName") or entry.get("PackageName") or entry.get("PkgName"),
                    "version": entry.get("InstalledVersion") or entry.get("Version"),
                    "severity": normalize_severity(entry.get("Severity")),
                    "scanner": "trivy",
                    "description": entry.get("Description") or entry.get("Title") or "",
                    "fixed_version": entry.get("FixedVersion"),
                    "location": entry.get("Target")
                })
            # Or if entry contains nested Results
            elif "Results" in entry:
                for result in entry.get("Results") or []:
                    for vuln in result.get("Vulnerabilities") or []:
                        if not isinstance(vuln, dict):
                            continue
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
    else:
        print(f"[!] unexpected trivy JSON structure in {path}; skipping parse")
    return findings


def parse_grype(path: Path) -> List[Dict[str, Any]]:
    data = safe_load(path)
    findings: List[Dict[str, Any]] = []
    if data is None:
        return findings

    # Anchore/Grype typical structure: { "matches": [ { "vulnerability": {...}, "artifact": {...} }, ... ] }
    matches = []
    if isinstance(data, dict):
        # common keys that might hold matches
        if "matches" in data:
            matches = data.get("matches", [])
        elif "vulnerabilities" in data:
            matches = data.get("vulnerabilities", [])
        else:
            # maybe the dict is actually a single match
            matches = [data]
    elif isinstance(data, list):
        matches = data
    else:
        print(f"[!] unexpected grype JSON type in {path}: {type(data)}")
        return findings

    for match in matches:
        if isinstance(match, dict):
            # If it's the standard match object
            if "vulnerability" in match or "vulnerability" in match.keys():
                vuln = match.get("vulnerability", {}) or match.get("vulnerability")
                artifact = match.get("artifact", {}) or match.get("artifact")
                # some versions place vulnerability data at top-level
                if not vuln and any(k in match for k in ("Vulnerability", "id", "ID")):
                    vuln = match
                    artifact = match.get("artifact", {})
            elif "Vulnerability" in match:
                vuln = match.get("Vulnerability", {})
                artifact = match.get("Artifact", {}) or match.get("artifact", {})
            else:
                # Try to treat the dict as a vuln-like object
                vuln = match
                artifact = match.get("artifact", {}) if isinstance(match, dict) else {}

            # Pull fields robustly
            vid = None
            if isinstance(vuln, dict):
                vid = vuln.get("id") or vuln.get("ID") or vuln.get("VulnerabilityID") or vuln.get("vulnerability")
            else:
                vid = vuln

            pkg_name = None
            if isinstance(artifact, dict):
                pkg_name = artifact.get("name") or artifact.get("Package") or artifact.get("pkg") or artifact.get("package")
                pkg_version = artifact.get("version") or artifact.get("Version")
                location = artifact.get("locations") or artifact.get("matchDetails") or None
            else:
                pkg_name = match.get("Package") or match.get("package") or match.get("PkgName")
                pkg_version = match.get("Version") or match.get("version")
                location = None

            # severity could be on vuln dict or match
            severity = None
            if isinstance(vuln, dict):
                severity = vuln.get("severity") or vuln.get("Severity")
                description = vuln.get("description") or vuln.get("Description", "")
                fixes = (vuln.get("fix", {}) or {}).get("versions", []) if isinstance(vuln.get("fix", {}), dict) else None
            else:
                severity = match.get("severity") or match.get("Severity")
                description = match.get("description") or match.get("Description", "")

            findings.append({
                "id": vid,
                "package": pkg_name,
                "version": pkg_version,
                "severity": normalize_severity(severity),
                "scanner": "grype",
                "description": description or "",
                "fixed_version": fixes[0] if fixes else None,
                "location": location
            })
        else:
            print(f"[!] skipping non-dict grype entry: {type(match)}")
    return findings


def parse_hadolint(path: Path) -> List[Dict[str, Any]]:
    data = safe_load(path)
    findings: List[Dict[str, Any]] = []
    if data is None:
        return findings

    # hadolint output is typically a list of issue objects, but can be empty list
    if isinstance(data, list):
        for issue in data:
            if not isinstance(issue, dict):
                continue
            findings.append({
                "id": issue.get("code"),
                "package": "Dockerfile",
                "version": None,
                "severity": normalize_severity(issue.get("level") or "LOW"),
                "scanner": "hadolint",
                "description": issue.get("message") or "",
                "fixed_version": None,
                "location": issue.get("file") or issue.get("line")
            })
    elif isinstance(data, dict):
        # Some hadolint variants may output dict with issues
        for key, issue in data.items():
            if isinstance(issue, dict):
                findings.append({
                    "id": issue.get("code") or key,
                    "package": "Dockerfile",
                    "version": None,
                    "severity": normalize_severity(issue.get("level") or "LOW"),
                    "scanner": "hadolint",
                    "description": issue.get("message") or "",
                    "fixed_version": None,
                    "location": issue.get("file") or issue.get("line")
                })
    else:
        print(f"[!] unexpected hadolint JSON structure in {path}; skipping parse")

    return findings


def make_key(f: Dict[str, Any]) -> str:
    # Prefer CVE/ID; fallback to package+version+description hash
    if f.get("id"):
        key = f"{f.get('id')}|{f.get('package') or ''}|{f.get('version') or ''}"
    else:
        digest = hashlib.sha1((f.get("package", "") + (f.get("version") or "") + (f.get("description") or "")).encode("utf-8")).hexdigest()
        key = f"NOID|{digest}"
    return key


def merge_findings(existing: Dict[str, Any], new: Dict[str, Any]) -> Dict[str, Any]:
    # Merge scanner names
    scanners = set([s.strip() for s in str(existing.get("scanner", "")).split(",") if s.strip()])
    scanners.update([s.strip() for s in str(new.get("scanner", "")).split(",") if s.strip()])
    existing["scanner"] = ", ".join(sorted(scanners))

    # Keep highest severity (CRITICAL > HIGH > MEDIUM > LOW)
    order = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1}
    if order.get(new.get("severity"), 0) > order.get(existing.get("severity"), 0):
        existing["severity"] = new.get("severity")

    # Prefer any non-empty fixed_version
    if not existing.get("fixed_version") and new.get("fixed_version"):
        existing["fixed_version"] = new.get("fixed_version")

    # Append extra location info if missing
    if not existing.get("location") and new.get("location"):
        existing["location"] = new.get("location")

    # Optionally concat descriptions if short and different
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

    findings: List[Dict[str, Any]] = []
    findings += parse_trivy(trivy_path)
    findings += parse_grype(grype_path)
    findings += parse_hadolint(hadolint_path)

    print(f"[+] Parsed {len(findings)} raw findings from inputs.")

    # Deduplicate & merge
    unique: Dict[str, Dict[str, Any]] = {}
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
