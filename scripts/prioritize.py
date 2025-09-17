import json
import argparse

def load_json(file_path):
    with open(file_path, "r") as f:
        return json.load(f)

def add_priority_score(findings, top_n=None):
    severity_weights = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1}

    for f in findings:
        severity_score = severity_weights.get(f["severity"].upper(), 0)
        exploit_score = 2 if f.get("exploit_available") else 0
        consensus_score = f.get("scanner_count", 1)
        f["priority_score"] = severity_score + exploit_score + consensus_score

    if top_n:
        findings = sorted(findings, key=lambda x: x["priority_score"], reverse=True)[:top_n]

    return findings

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--input", default="consensus-results.json")
    parser.add_argument("--output", default="prioritized-findings.json")
    parser.add_argument("--top", type=int, default=None)
    args = parser.parse_args()

    findings = load_json(args.input)
    findings = add_priority_score(findings, args.top)

    print(f"[+] Prioritized {len(findings)} findings.")
    with open(args.output, "w") as f:
        json.dump(findings, f, indent=2)

if __name__ == "__main__":
    main()
