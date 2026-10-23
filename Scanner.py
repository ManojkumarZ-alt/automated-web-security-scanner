
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

# Reserved test origin for basic CORS configuration checks.
TEST_ORIGIN = "https://cors-test.invalid"


def add_finding(report, check, severity, status, details):
    """Add one finding to the report."""
    report["findings"].append({
        "check": check,
        "severity": severity,
        "status": status,
        "details": details,
    })


def check_cors(response, report):
    """Inspect CORS headers for preliminary misconfiguration indicators."""
    headers = response.headers

    allow_origin = headers.get("Access-Control-Allow-Origin", "").strip()
    allow_credentials = (
        headers.get("Access-Control-Allow-Credentials", "")
        .strip()
        .lower()
    )
    allow_methods = headers.get("Access-Control-Allow-Methods")
    allow_headers = headers.get("Access-Control-Allow-Headers")
    vary = headers.get("Vary", "")

    # Error responses may not represent the normal application response.
    if response.status_code >= 400:
        add_finding(
            report,
            "CORS",
            "INFO",
            "INCONCLUSIVE",
            f"Server returned HTTP {response.status_code}. "
            "CORS behavior could not be reliably assessed from "
            "this error response."
        )
        return

    if not allow_origin:
        add_finding(
            report,
            "CORS",
            "INFO",
            "NOT OBSERVED",
            "Access-Control-Allow-Origin was not returned for "
            "the test origin. This alone does not prove CORS is "
            "correctly configured."
        )
        return

    if allow_origin == "*":
        add_finding(
            report,
            "CORS wildcard origin",
            "MEDIUM",
            "REVIEW",
            "The response allows any origin. This can be appropriate "
            "for public resources; verify whether sensitive data "
            "is involved."
        )

        if allow_credentials == "true":
            add_finding(
                report,
                "CORS credentials with wildcard",
                "INFO",
                "REVIEW",
                "The response contains both wildcard origin and "
                "credentials=true. Browsers reject credentialed "
                "CORS responses with a wildcard origin, but review "
                "the configuration and actual browser behavior."
            )

    elif allow_origin == TEST_ORIGIN:
        if allow_credentials == "true":
            add_finding(
                report,
                "CORS reflected origin with credentials",
                "HIGH",
                "REVIEW",
                "The server allowed the arbitrary test origin and "
                "allowed credentials. Verify with an authorized "
                "browser-based test whether sensitive authenticated "
                "data can actually be read."
            )
        else:
            add_finding(
                report,
                "CORS reflected origin",
                "MEDIUM",
                "REVIEW",
                "The server returned the supplied test origin as "
                "an allowed origin. Confirm that only trusted "
                "origins are accepted."
            )

    else:
        add_finding(
            report,
            "CORS allowed origin",
            "INFO",
            "OBSERVED",
            f"The response returned Access-Control-Allow-Origin: "
            f"{allow_origin}. Compare it with the intended "
            "trusted-origin policy."
        )

    if allow_credentials == "true":
        add_finding(
            report,
            "CORS credentials",
            "INFO",
            "OBSERVED",
            "Access-Control-Allow-Credentials is true. This is "
            "not automatically a vulnerability; review together "
            "with the allowed origin and the protected resource."
        )

    if allow_origin == TEST_ORIGIN and "origin" not in [
        value.strip().lower() for value in vary.split(",")
    ]:
        add_finding(
            report,
            "CORS Vary header",
            "LOW",
            "REVIEW",
            "The test origin was reflected but Vary: Origin was "
            "not observed. Check caching behavior to prevent "
            "responses from being reused across origins incorrectly."
        )

    if allow_methods:
        report["cors_observations"]["allowed_methods"] = allow_methods

    if allow_headers:
        report["cors_observations"]["allowed_headers"] = allow_headers

    report["cors_observations"]["allow_origin"] = allow_origin
    report["cors_observations"]["allow_credentials"] = (
        allow_credentials or "not present"
    )
    report["cors_observations"]["vary"] = vary or "not present"


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
        "cors_observations": {},
    }

    print("\n=== Automated Web Security Scanner ===")
    print("Target:", url)

    try:
        response = requests.get(
            url,
            headers={"Origin": TEST_ORIGIN},
            timeout=10,
            allow_redirects=True,
        )

        report["http_status"] = response.status_code
        report["final_url"] = response.url
        report["https"] = response.url.startswith("https://")

        print("\nHTTP Status:", response.status_code)
        print("Final URL:", response.url)

        # HTTPS check
        if not report["https"]:
            add_finding(
                report,
                "HTTPS",
                "HIGH",
                "REVIEW",
                "Final URL uses HTTP instead of HTTPS."
            )

        # Security headers: avoid false conclusions on error pages.
        if response.status_code >= 400:
            add_finding(
                report,
                "Security header assessment",
                "INFO",
                "INCONCLUSIVE",
                f"Server returned HTTP {response.status_code}. "
                "Missing security headers on this error response "
                "are not being treated as confirmed findings."
            )
        else:
            for header, severity in SECURITY_HEADERS.items():
                if header not in response.headers:
                    add_finding(
                        report,
                        header,
                        severity,
                        "MISSING",
                        f"Response does not contain {header}."
                    )

        # CORS check
        print("\n--- CORS Check ---")
        check_cors(response, report)

        for finding in report["findings"]:
            print(
                f"{finding['severity']} | {finding['status']} | "
                f"{finding['check']}: {finding['details']}"
            )

    except requests.exceptions.RequestException as error:
        report["error"] = str(error)
        print("ERROR: Could not scan website:", error)

    # Count findings by severity.
    summary = {
        "total_findings": len(report["findings"]),
        "HIGH": 0,
        "MEDIUM": 0,
        "LOW": 0,
        "INFO": 0,
    }

    for finding in report["findings"]:
        severity = finding["severity"]
        if severity in summary:
            summary[severity] += 1

    report["summary"] = summary

    # Create the output folder.
    output_dir = Path("reports")
    output_dir.mkdir(exist_ok=True)

    # Save JSON report.
    json_path = output_dir / "scan_report.json"
    json_path.write_text(
        json.dumps(report, indent=4),
        encoding="utf-8"
    )

    # Build HTML report, escaping untrusted values.
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

    cors_rows = ""

    for key, value in report["cors_observations"].items():
        cors_rows += (
            "<tr>"
            f"<td>{html.escape(key)}</td>"
            f"<td>{html.escape(str(value))}</td>"
            "</tr>"
        )

    if not cors_rows:
        cors_rows = '<tr><td colspan="2">No CORS observations recorded.</td></tr>'

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
table {{ border-collapse: collapse; width: 100%; margin-bottom: 24px; }}
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
<strong>Low:</strong> {summary['LOW']} |
<strong>Info:</strong> {summary['INFO']}</p>
{error_message}
<h2>Findings</h2>
<table>
<thead><tr><th>Check</th><th>Severity</th>
<th>Status</th><th>Details</th></tr></thead>
<tbody>{rows}</tbody>
</table>
<h2>CORS Observations</h2>
<table>
<thead><tr><th>Header</th><th>Value</th></tr></thead>
<tbody>{cors_rows}</tbody>
</table>
<p>Automated observations only. Findings require manual validation.
This basic scanner does not test browser access to sensitive data
or fully validate CORS preflight behavior.</p>
</body>
</html>"""

    html_path = output_dir / "scan_report.html"
    html_path.write_text(html_report, encoding="utf-8")

    print("\n--- Summary ---")
    print("Total findings:", summary["total_findings"])
    print("High:", summary["HIGH"])
    print("Medium:", summary["MEDIUM"])
    print("Low:", summary["LOW"])
    print("Info:", summary["INFO"])
    print("\nJSON report:", json_path)
    print("HTML report:", html_path)
    print("Scan completed.")


if __name__ == "__main__":
    target = input(
        "Enter a website you own or are authorized to test: "
    ).strip()
    scan_website(target)
