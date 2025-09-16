import json
import argparse
from collections import defaultdict

def load_json(file_path):
    try:
        with open(file_path, "r") as f:
            return json.load(f)
    except FileNotFoundError:
        print(f"[!] file missing: {file_path}")
        return []

def normalize_findings(trivy, grype, hadolint):
    all_findings = []

    # Example: flatten Trivy findings
    for f in trivy:
        all_findings.append({
            "scanner": "trivy",
            "id": f.get("VulnerabilityID"),
            "package": f.get("PkgName"),
            "severity": f.get("Severity", "LOW"),
            "description": f.get("Title", ""),
            "scanner_count": 1,
            "exploit_available": f.get("PrimaryURL") is not None
        })

    # Flatten Grype findings
    for f in grype:
        all_findings.append({
            "scanner": "grype",
            "id": f.get("Vulnerability", f.get("ID")),
            "package": f.get("Package", ""),
            "severity": f.get("Severity", "LOW"),
            "description": f.get("Description", ""),
            "scanner_count": 1,
            "exploit_available": f.get("Advisory") is not None
        })

    # Flatten Hadolint findings
    for f in hadolint:
        all_findings.append({
            "scanner": "hadolint",
            "id": f.get("code"),
            "package": f.get("file"),
            "severity": "LOW",
            "description": f.get("message", ""),
            "scanner_count": 1,
            "exploit_available": False
        })

    return all_findings

def deduplicate_findings(findings):
    deduped = defaultdict(lambda: {"scanner_count": 0, "severity": "LOW"})
    for f in findings:
        key = f["id"] + "|" + f["package"]
        if deduped[key]["scanner_count"] > 0:
            deduped[key]["scanner_count"] += 1
        else:
            deduped[key].update(f)
    return list(deduped.values())

def add_priority_score(findings):
    severity_weights = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1}
    for f in findings:
        severity_score = severity_weights.get(f["severity"].upper(), 0)
        exploit_score = 2 if f.get("exploit_available") else 0
        consensus_score = f.get("scanner_count", 1)
        f["priority_score"] = severity_score + exploit_score + consensus_score
    return findings

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--trivy", default="trivy-results.json")
    parser.add_argument("--grype", default="grype-results.json")
    parser.add_argument("--hadolint", default="hadolint-results.json")
    parser.add_argument("--output", default="consensus-results.json")
    args = parser.parse_args()

    trivy_data = load_json(args.trivy)
    grype_data = load_json(args.grype)
    hadolint_data = load_json(args.hadolint)

    findings = normalize_findings(trivy_data, grype_data, hadolint_data)
    print(f"[+] Parsed {len(findings)} raw findings from inputs.")

    findings = deduplicate_findings(findings)
    findings = add_priority_score(findings)
    print(f"[+] Wrote {len(findings)} consensus findings to {args.output}")

    with open(args.output, "w") as f:
        json.dump(findings, f, indent=2)

if __name__ == "__main__":
    main()
