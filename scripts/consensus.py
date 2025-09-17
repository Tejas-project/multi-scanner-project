import json
import argparse
from collections import defaultdict

def load_json(file_path):
    with open(file_path, "r") as f:
        return json.load(f)

def deduplicate_findings(findings):
    deduped = defaultdict(lambda: {"scanner_count": 0, "severity": "LOW"})
    for f in findings:
        key = f["id"] + "|" + f["package"]
        if deduped[key]["scanner_count"] > 0:
            deduped[key]["scanner_count"] += 1
        else:
            deduped[key].update(f)
    return list(deduped.values())

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--input", default="normalized-results.json")
    parser.add_argument("--output", default="consensus-results.json")
    args = parser.parse_args()

    findings = load_json(args.input)
    findings = deduplicate_findings(findings)

    print(f"[+] Computed consensus for {len(findings)} findings.")

    with open(args.output, "w") as f:
        json.dump(findings, f, indent=2)

if __name__ == "__main__":
    main()
