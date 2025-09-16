
# Python Vulnerability Scanner

A safe, modular tool that scans a given URL or IP for common, non-destructive vulnerabilities and produces a clear report.

**Disclaimer:** This tool is for educational purposes and authorized testing only. Unauthorized scanning of websites is illegal. The user is responsible for their actions.

## Features

-   Connectivity check
-   TCP port scanning
-   Security header analysis
-   Non-destructive SQL injection checks
-   Non-destructive reflected XSS checks
-   Text and JSON reporting

## Installation

1.  Clone the repository:

    ```bash
    git clone https://github.com/your-username/vulnerability-scanner.git
    cd vulnerability-scanner
    ```

2.  Install the dependencies:

    ```bash
    pip install -r requirements.txt
    ```

## Usage

```bash
python3 scanner.py --target <URL_OR_IP> [OPTIONS]
```

### Options

-   `--target`: The target URL or IP address (required).
-   `--output`: The output format (`text` or `json`, default: `text`).
-   `--ports`: A comma-separated list of ports to scan (e.g., `80,443,8080`).
-   `--timeout`: The timeout for network requests in seconds (default: `1.0`).
-   `--aggressive`: Perform more intensive (but still safe) checks.
-   `--i-have-permission`: Required for aggressive scans.

### Examples

**Safe Scan**

```bash
python3 scanner.py --target http://localhost:8000 --safe
```

**Aggressive Scan**

```bash
python3 scanner.py --target "http://localhost:8000?id=1" --aggressive --i-have-permission
```

## Sample Output

### Text Output

```
[Medium] Missing Security Header: Content-Security-Policy
  Description: Mitigates XSS and other injection attacks.
  Remediation: Implement a strict Content-Security-Policy.

[High] Potential SQL Injection
  Description: A potential SQL injection vulnerability was found in the 'id' parameter.
  Remediation: Use parameterized queries to prevent SQL injection.
```

### JSON Output

```json
[
    {
        "title": "Missing Security Header: Content-Security-Policy",
        "severity": "Medium",
        "description": "Mitigates XSS and other injection attacks.",
        "remediation": "Implement a strict Content-Security-Policy."
    },
    {
        "title": "Potential SQL Injection",
        "severity": "High",
        "description": "A potential SQL injection vulnerability was found in the 'id' parameter.",
        "remediation": "Use parameterized queries to prevent SQL injection."
    }
]
```

## JSON Schema

The JSON output is an array of finding objects, each with the following structure:

-   `title` (string): The title of the finding.
-   `severity` (string): The severity of the finding (`High`, `Medium`, `Low`, `Info`).
-   `description` (string): A description of the finding.
-   `remediation` (string, optional): Remediation advice.

## Extending the Scanner

To add a new scan module, see `CONTRIBUTING.md`.

## Non-Destructive Checklist

-   [x] The tool does not perform any actions that could alter or delete data on the target system.
-   [x] SQL injection checks use benign payloads that only trigger errors.
-   [x] XSS checks only look for reflections and do not execute any scripts.
-   [x] The tool does not send any exploit payloads.

## Running a Local Test Target

To test the scanner locally, you can run a simple Python web server:

1.  Create a file named `test_server.py`:

    ```python
    from flask import Flask, request

    app = Flask(__name__)

    @app.route('/')
    def index():
        param = request.args.get('id', '')
        if "'" in param:
            return "sql syntax error", 500
        return f"Hello, {param}!"

    if __name__ == '__main__':
        app.run(port=8000)
    ```

2.  Run the server:

    ```bash
    pip install Flask
    python3 test_server.py
    ```

3.  Scan the local server:

    ```bash
    python3 scanner.py --target "http://localhost:8000?id=1" --aggressive --i-have-permission
    ```
