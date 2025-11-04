import json
import os
from datetime import datetime

# ----------------------------------------------------------------------
# Multi-Scanner Security Report Generator
# Generates an HTML summary with severity, consensus, prioritization,
# and Hadolint linting analysis.
# ----------------------------------------------------------------------

def load_normalized_results(file_path):
    if not os.path.exists(file_path):
        raise FileNotFoundError(f"{file_path} not found.")
    with open(file_path, "r") as f:
        return json.load(f)


# --- Count findings by severity ---
def severity_summary(findings):
    counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "unknown": 0}
    for f in findings:
        sev = f.get("severity", "unknown").lower()
        if sev not in counts:
            counts["unknown"] += 1
        else:
            counts[sev] += 1
    return counts


# --- Consensus Summary (2-level logic) ---
def consensus_summary(findings):
    consensus = {"matched": 0, "unique_trivy": 0, "unique_grype": 0, "unique_hadolint": 0, "unknown": 0}
    for f in findings:
        src = f.get("scanner", "").lower()
        if "trivy" in src and "grype" in src:
            consensus["matched"] += 1
        elif "trivy" in src and "grype" not in src:
            consensus["unique_trivy"] += 1
        elif "grype" in src and "trivy" not in src:
            consensus["unique_grype"] += 1
        elif "hadolint" in src:
            consensus["unique_hadolint"] += 1
        else:
            consensus["unknown"] += 1
    return consensus


# --- Prioritization (simple two-level) ---
def prioritize_findings(findings):
    prioritized = []
    for f in findings:
        severity = f.get("severity", "").lower()
        if severity in ["high", "critical"]:
            prioritized.append(f)
    return prioritized


# --- Hadolint extraction ---
def extract_hadolint_findings(findings):
    return [f for f in findings if f.get("scanner", "").lower() == "hadolint"]


# --- Generate HTML report ---
def generate_html_report(findings, severity_counts, consensus_counts, prioritized_findings, hadolint_findings, output_file):
    html_content = f"""
    <html>
    <head>
        <title>Multi-Scanner Security Report</title>
        <style>
            body {{ font-family: Arial, sans-serif; background-color: #f7f7f7; padding: 20px; }}
            h1, h2 {{ color: #333; }}
            table {{ border-collapse: collapse; width: 100%; margin-bottom: 20px; }}
            th, td {{ border: 1px solid #ccc; padding: 8px; text-align: left; }}
            th {{ background-color: #eee; }}
            .critical {{ color: red; font-weight: bold; }}
            .high {{ color: orange; font-weight: bold; }}
            .medium {{ color: goldenrod; }}
            .low {{ color: green; }}
            .hadolint {{ color: blue; font-weight: bold; }}
            .section-divider {{
                border-top: 3px solid #999;
                margin: 30px 0;
            }}
        </style>
    </head>
    <body>
        <h1>Multi-Scanner Security Report</h1>
        <p><strong>Generated:</strong> {datetime.now().strftime("%Y-%m-%d %H:%M:%S")}</p>

        <h2>Severity Summary</h2>
        <table>
            <tr><th>Severity</th><th>Count</th></tr>
            <tr><td class="critical">Critical</td><td>{severity_counts['critical']}</td></tr>
            <tr><td class="high">High</td><td>{severity_counts['high']}</td></tr>
            <tr><td class="medium">Medium</td><td>{severity_counts['medium']}</td></tr>
            <tr><td class="low">Low</td><td>{severity_counts['low']}</td></tr>
            <tr><td>Unknown</td><td>{severity_counts['unknown']}</td></tr>
        </table>

        <div class="section-divider"></div>

        <h2>Consensus Summary (Trivy + Grype)</h2>
        <table>
            <tr><th>Category</th><th>Count</th></tr>
            <tr><td>Matched (in both scanners)</td><td>{consensus_counts['matched']}</td></tr>
            <tr><td>Unique to Trivy</td><td>{consensus_counts['unique_trivy']}</td></tr>
            <tr><td>Unique to Grype</td><td>{consensus_counts['unique_grype']}</td></tr>
            <tr><td>Unique to Hadolint</td><td>{consensus_counts['unique_hadolint']}</td></tr>
            <tr><td>Unknown</td><td>{consensus_counts['unknown']}</td></tr>
        </table>

        <div class="section-divider"></div>

        <h2>Top Prioritized Findings (High / Critical)</h2>
        <table>
            <tr><th>ID</th><th>Severity</th><th>Package</th><th>Description</th></tr>
    """

    for f in prioritized_findings:
        html_content += f"""
            <tr>
                <td>{f.get('id', '')}</td>
                <td class="{f.get('severity', '').lower()}">{f.get('severity', '')}</td>
                <td>{f.get('package', '')}</td>
                <td>{f.get('description', '')}</td>
            </tr>
        """

    html_content += """
        </table>
        <p><i>Note: Only HIGH and CRITICAL vulnerabilities are prioritized. 
        This logic can later include exploitability or CVSS weighting.</i></p>

        <div class="section-divider"></div>

        <h2>Dockerfile Linting Summary (Hadolint)</h2>
        <table>
            <tr><th>Rule ID</th><th>Severity</th><th>File</th><th>Message</th></tr>
    """

    if not hadolint_findings:
        html_content += "<tr><td colspan='4'>No Dockerfile linting issues found.</td></tr>"
    else:
        for f in hadolint_findings:
            html_content += f"""
            <tr>
                <td class="hadolint">{f.get('id', '')}</td>
                <td>{f.get('severity', '')}</td>
                <td>{f.get('location', '')}</td>
                <td>{f.get('description', '')}</td>
            </tr>
            """

    html_content += """
        </table>
        <p><i>Hadolint helps detect misconfigurations and enforce Docker best practices.</i></p>
    </body>
    </html>
    """

    with open(output_file, "w", encoding="utf-8") as f:
        f.write(html_content)

    print(f"[+] HTML report generated: {output_file}")


# --- Main entry point ---
def main():
    normalized_file = "normalized-results.json"
    output_file = "multi-scanner-report.html"

    findings = load_normalized_results(normalized_file)
    severity_counts = severity_summary(findings)
    consensus_counts = consensus_summary(findings)
    prioritized_findings = prioritize_findings(findings)
    hadolint_findings = extract_hadolint_findings(findings)

    generate_html_report(
        findings,
        severity_counts,
        consensus_counts,
        prioritized_findings,
        hadolint_findings,
        output_file,
    )


if __name__ == "__main__":
    main()
