
import requests
import json
import html
from datetime import datetime
from urllib.parse import urlparse
from pathlib import Path


SECURITY_HEADERS = {
    "Content-Security-Policy": "HIGH",
    "Strict-Transport-Security": "MEDIUM",
    "X-Content-Type-Options": "MEDIUM",
    "X-Frame-Options": "MEDIUM",
    "Referrer-Policy": "LOW",
}


def scan_website(url):
    if not url.startswith(("http://", "https://")):
        url = "https://" + url

    parsed = urlparse(url)

    if (
        parsed.scheme not in ("http", "https")
        or not parsed.hostname
        or parsed.username
        or parsed.password
    ):
        print("ERROR: Enter a valid HTTP/HTTPS URL without credentials.")
        return

    report = {
        "target": url,
        "scan_time": datetime.now().astimezone().isoformat(
            timespec="seconds"
        ),
        "http_status": None,
        "final_url": None,
        "https": None,
        "findings": [],
        "error": None,
    }

    print("\n=== Automated Web Security Scanner ===")
    print("Target:", url)

    try:
        response = requests.get(
            url,
            timeout=10,
            allow_redirects=True
        )

        report["http_status"] = response.status_code
        report["final_url"] = response.url
        report["https"] = response.url.startswith("https://")

        if not report["https"]:
            report["findings"].append({
                "check": "HTTPS",
                "severity": "HIGH",
                "status": "REVIEW",
                "details": "Final URL uses HTTP instead of HTTPS."
            })

        for header, severity in SECURITY_HEADERS.items():
            if header not in response.headers:
                report["findings"].append({
                    "check": header,
                    "severity": severity,
                    "status": "MISSING",
                    "details": f"Response does not contain {header}."
                })

        print("\nHTTP Status:", response.status_code)
        print("Final URL:", response.url)

    except requests.exceptions.RequestException as error:
        report["error"] = str(error)

    # Count findings by severity
    summary = {
        "total_findings": len(report["findings"]),
        "HIGH": 0,
        "MEDIUM": 0,
        "LOW": 0,
    }

    for finding in report["findings"]:
        severity = finding["severity"]
        if severity in summary:
            summary[severity] += 1

    report["summary"] = summary

    # Create the output folder
    output_dir = Path("reports")
    output_dir.mkdir(exist_ok=True)

    # Save JSON report
    json_path = output_dir / "scan_report.json"
    json_path.write_text(
        json.dumps(report, indent=4),
        encoding="utf-8"
    )

    # Build an HTML report safely escaping displayed values
    rows = ""
    for finding in report["findings"]:
        rows += (
            "<tr>"
            f"<td>{html.escape(finding['check'])}</td>"
            f"<td>{html.escape(finding['severity'])}</td>"
            f"<td>{html.escape(finding['status'])}</td>"
            f"<td>{html.escape(finding['details'])}</td>"
            "</tr>"
        )

    if not rows:
        rows = '<tr><td colspan="4">No findings recorded.</td></tr>'

    error_message = ""
    if report["error"]:
        error_message = (
            "<p><strong>Request error:</strong> "
            + html.escape(report["error"])
            + "</p>"
        )

    html_report = f"""<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Web Security Scan Report</title>
<style>
body {{ font-family: Arial, sans-serif; margin: 32px; line-height: 1.5; }}
table {{ border-collapse: collapse; width: 100%; }}
th, td {{ border: 1px solid #ccc; padding: 10px; text-align: left; }}
th {{ background: #eee; }}
</style>
</head>
<body>
<h1>Automated Web Security Scanner</h1>
<p><strong>Target:</strong> {html.escape(report['target'])}</p>
<p><strong>Scan time:</strong> {html.escape(report['scan_time'])}</p>
<p><strong>HTTP status:</strong> {html.escape(str(report['http_status']))}</p>
<p><strong>Final URL:</strong> {html.escape(str(report['final_url']))}</p>
<p><strong>Total findings:</strong> {summary['total_findings']}</p>
<p><strong>High:</strong> {summary['HIGH']} |
<strong>Medium:</strong> {summary['MEDIUM']} |
<strong>Low:</strong> {summary['LOW']}</p>
{error_message}
<h2>Findings</h2>
<table>
<thead><tr><th>Check</th><th>Severity</th>
<th>Status</th><th>Details</th></tr></thead>
<tbody>{rows}</tbody>
</table>
<p>Automated observations only; findings require manual validation.</p>
</body>
</html>"""

    html_path = output_dir / "scan_report.html"
    html_path.write_text(html_report, encoding="utf-8")

    print("\n--- Summary ---")
    print("Total findings:", summary["total_findings"])
    print("High:", summary["HIGH"])
    print("Medium:", summary["MEDIUM"])
    print("Low:", summary["LOW"])
    print("\nJSON report:", json_path)
    print("HTML report:", html_path)
    print("Scan completed.")


if __name__ == "__main__":
    target = input(
        "Enter a website you own or are authorized to test: "
    ).strip()
    scan_website(target)
