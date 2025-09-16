# Contributing to the Vulnerability Scanner

First off, thank you for considering contributing! Your help is appreciated.

## Adding a New Scan Module

To add a new scanner, follow these steps:

1.  **Create a new Python file** in the `modules/` directory (e.g., `modules/new_scan.py`).
2.  **Implement your scan logic** inside a function. This function should accept the target URL or IP and other necessary parameters.
3.  **Return a list of findings.** Each finding should be a dictionary with keys like `title`, `severity`, `description`, and `remediation`.
4.  **Import and integrate your new module** into `scanner.py`. Add it to the list of scans to be executed.

## Running Tests

To ensure the quality of the code, please run the test suite before submitting a pull request.

1.  Install the development dependencies:

    ```bash
    pip install -r requirements.txt
    ```

2.  Run the tests using pytest:

    ```bash
    pytest
    ```

This will run all the tests in the `tests/` directory. Make sure all tests pass before submitting your changes.
