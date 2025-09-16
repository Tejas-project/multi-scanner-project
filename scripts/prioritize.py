import json
import argparse

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--input", default="consensus-results.json")
    parser.add_argument("--output", default="prioritized-findings.json")
    parser.add_argument("--top", type=int, default=10, help="Number of top findings to output")
    args = parser.parse_args()

    with open(args.input) as f:
        findings = json.load(f)

    # Sort descending by priority_score
    findings.sort(key=lambda x: x.get("priority_score", 0), reverse=True)

    top_findings = findings[: args.top]

    with open(args.output, "w") as f:
        json.dump(top_findings, f, indent=2)

    print(f"[+] Wrote top {args.top} prioritized findings to {args.output}")

if __name__ == "__main__":
    main()
