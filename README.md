# Automated Web Security Scanner

## Project Overview

The Automated Web Security Scanner is a beginner-friendly Python project developed as part of my cybersecurity learning journey. It checks a website's HTTP response, HTTPS usage, and selected security headers, then generates JSON and HTML reports.

## Features

- Checks HTTP response status codes.
- Checks whether the final URL uses HTTPS.
- Inspects selected HTTP security headers.
- Records findings with preliminary severity levels.
- Generates JSON and HTML scan reports.
- Handles common HTTP request errors and timeouts.

## Technologies Used

- Python
- Requests library
- HTML and CSS
- JSON
- Visual Studio Code

## Installation

1. Install Python.
2. Install the required library:

   `py -m pip install requests`

3. Download or clone this repository.
4. Open the project folder in a terminal.

## How to Run

Run the scanner:

`py scanner.py`

Enter a website URL that you own or have permission to test.

Reports are saved in the `reports` folder.

## Limitations

This is a basic security-header inspection tool, not a complete vulnerability scanner. Missing headers do not automatically mean a website is vulnerable. Findings require manual validation.

## Responsible Use

Use this tool only on websites you own or are explicitly authorized to assess.

## Learning Outcomes

This project helped me practise Python programming, HTTP requests, security-header inspection, error handling, JSON report generation, and basic security assessment concepts.
