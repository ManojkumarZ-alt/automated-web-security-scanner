# Automated Web Security Scanner

A Python-based beginner-friendly project that performs basic web security checks by analyzing HTTP responses, selected security headers, and CORS-related response headers.

## Features

- **HTTPS Check:** Checks whether the final URL uses HTTPS.
- **Security Header Check:** Identifies missing security headers, including Content-Security-Policy, Strict-Transport-Security, X-Content-Type-Options, X-Frame-Options, and Referrer-Policy.
- **CORS Check:** Sends a request with a test Origin header and examines CORS-related response headers.
- **Severity Classification:** Organizes findings by severity: High, Medium, Low, and Info.
- **JSON Report:** Saves scan results in a structured JSON file.
- **HTML Report:** Generates a readable HTML report for viewing in a web browser.
- **Error Handling:** Records request errors and helps identify inconclusive results.

## What Is CORS?

Cross-Origin Resource Sharing (CORS) is a browser security mechanism that controls whether a web page can access resources from another origin.

This scanner performs a basic CORS response-header assessment by examining:

- `Access-Control-Allow-Origin`
- `Access-Control-Allow-Credentials`
- `Access-Control-Allow-Methods`
- `Access-Control-Allow-Headers`
- `Vary`

It records relevant observations in the generated reports and flags selected configurations for review.

**Important:** This is a basic assessment, not a complete CORS security test. Missing headers do not automatically indicate a vulnerability. Results may be inconclusive when a server returns an error response, blocks automated requests, or handles browser preflight requests differently.

## Technologies Used

- Python 3
- Requests library
- JSON
- HTML and CSS
- Git and GitHub

## Requirements

- Python 3 installed on your system
- Internet connection
- Required Python package: `requests`

Install the dependency using:

```bash
py -m pip install requests
```

## How to Run

1. Clone or download this repository.
2. Open PowerShell or a terminal in the project folder.
3. Run the scanner:

```bash
py Scanner.py
```

4. Enter a website URL that you own or are authorized to test.
5. Wait for the scan to finish.
6. Open the generated reports in the `reports` folder.

## Generated Reports

The scanner generates the following files:

- `reports/scan_report.json` — contains structured scan results, findings, and summary information.
- `reports/scan_report.html` — displays scan results in a readable HTML format.

The `reports` folder is excluded from Git tracking by `.gitignore`, so generated reports are not uploaded to the repository by default.

## Limitations

This tool performs basic automated checks of HTTP responses and selected headers. It does not identify every web application vulnerability or replace a professional security assessment.

A website returning HTTP 403 or another error status may prevent reliable evaluation of its normal response headers. CORS behavior can also depend on browser enforcement, request type, credentials, and preflight responses.

All findings should be manually validated before drawing security conclusions.

## Disclaimer

This project is intended for educational purposes and cybersecurity learning. Only scan websites and systems that you own or have explicit permission to test. Do not use this tool for unauthorized security testing.

## Author

Manoj Kumar
