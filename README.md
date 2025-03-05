# Automate_vuln_scanner
AutoVulnScanner is a versatile and interactive penetration testing tool designed to identify various web application vulnerabilities. 
Key Features:

    Cross-Site Scripting (XSS) Scanning:
        Injects common XSS payloads into URL parameters to detect potential XSS vulnerabilities.
        Outputs detailed information about detected vulnerabilities, including the payload used and a snippet of the response.

    SQL Injection Scanning:
        Injects SQL injection payloads into URL parameters to identify potential SQL injection vulnerabilities.
        Looks for specific keywords in the response that indicate a SQL injection issue.

    Subdomain Takeover Scanning:
        Checks various subdomains of a given base URL to detect potential subdomain takeover vulnerabilities.
        Identifies subdomains that may be for sale or not found, indicating a potential takeover risk.

    Information Disclosure Scanning:
        Scans the target URL for keywords that suggest information disclosure, such as "password", "username", and "error".
        Helps identify sensitive information that should not be exposed publicly.

    Multi-threading:
        Utilizes Python's threading capabilities to run multiple scans concurrently, significantly reducing the overall scan time.
        Ensures efficient use of system resources by parallelizing the scanning process.

    User-Friendly Interface:
        Prompts the user to input the URL to scan and the base URL for subdomain scanning.
        Provides clear and colorful output to make it easy to understand the results of the scans.

    Error Handling:
        Gracefully handles errors during the scanning process, providing informative messages about any issues encountered.
        Ensures the tool remains robust and reliable even in the face of network or server issues.

How to Use the Tool:

    Install Required Libraries:
    Ensure you have the necessary libraries installed. You can install them using pip:

    sh

pip install requests termcolor

Save the Code:
Save the provided code to a file, for example, auto_vuln_scanner.py.

Run the Script:
Open a terminal or command prompt and navigate to the directory where you saved the script. Run the script using Python:

sh

python auto_vuln_scanner.py

Enter the URL to Scan:
When prompted, enter the URL you want to scan for vulnerabilities. For example:

Enter the URL to scan: http://example.com/vulnerable-endpoint

Enter the Base URL for Subdomain Takeover Scan:
When prompted, enter the base URL for the subdomain takeover scan. For example:

    Enter the base URL for subdomain scanning (e.g., example.com): example.com

Example Output:

Here is an example of what the output might look like:

    _______  _______  _______  _______  _______  _______  _______
   |       ||       ||       ||       ||       ||       ||       |
   |  _____||  _____||  _____||  _____||  _____||  _____||  _____|
   | |_____ | |_____ | |_____ | |_____ | |_____ | |_____ | |_____
   |_____  ||_____  ||_____  ||_____  ||_____  ||_____  ||_____  |
          |       |       |       |       |       |       |       |
          |_______|_______|_______|_______|_______|_______|_______|

Enter the URL to scan: http://example.com/vulnerable-endpoint
Enter the base URL for subdomain scanning (e.g., example.com): example.com
[XSS] Potential vulnerability found with payload: <script>alert('XSS')</script>
[SQLi] Potential vulnerability found with payload: ' OR '1'='1
[Info Disclosure] Potential vulnerability found at: http://example.com/vulnerable-endpoint
[Subdomain Takeover] Potential vulnerability found: https://test.example.com

Next Steps:

    Expand Functionality: Add more vulnerability checks, such as CRLF injection, IDOR, and other common vulnerabilities.
    Error Handling: Improve error handling to make the scanner more robust.
    User Interface: Create a command-line interface or a graphical user interface for easier use.
    Database Integration: Store scan results in a database for later analysis.


