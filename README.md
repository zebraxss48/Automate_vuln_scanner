This Python-based Web Vulnerability Scanner is an automated security tool designed to detect multiple types of security flaws in web applications. Using a multi-threaded approach with the ThreadPoolExecutor, it efficiently scans for various vulnerabilities, logs findings, and saves results in a structured format.
Key Features:

✅ Multi-Threaded Execution: Uses concurrent scanning for faster results.
✅ Supports Multiple Vulnerabilities: Scans for XSS, SQL Injection, Local File Inclusion (LFI), Command Injection, and Sensitive Data Leaks.
✅ Customizable Payloads: Reads attack payloads from payloads.yaml, allowing easy customization and expansion.
✅ Logging & Reporting: Saves results in a structured scan_results.json file and logs critical findings in scanner.log.
✅ Progress Tracking: Uses tqdm to show real-time progress updates.
✅ User-Friendly Interface: Simple CLI-based interaction using argparse.
How It Works

    Load Payloads: Reads attack payloads from a YAML file.
    Multi-Threaded Scanning: Simultaneously launches different vulnerability checks.
    Analyze Responses: Detects vulnerabilities based on response patterns and logs findings.
    Save & Display Results: Stores detected vulnerabilities in JSON format and prints findings.

This scanner is an essential tool for bug hunters, penetration testers, and security professionals looking to automate security assessments efficiently. 🚀
