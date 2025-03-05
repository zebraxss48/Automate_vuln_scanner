import requests
import threading
from termcolor import colored
import socket

def print_banner():
    banner = """
    _______  _______  _______  _______  _______  _______  _______
   |       ||       ||       ||       ||       ||       ||       |
   |  _____||  _____||  _____||  _____||  _____||  _____||  _____|
   | |_____ | |_____ | |_____ | |_____ | |_____ | |_____ | |_____
   |_____  ||_____  ||_____  ||_____  ||_____  ||_____  ||_____  |
          |       |       |       |       |       |       |       |
          |_______|_______|_______|_______|_______|_______|_______|
    """
    print(colored(banner, 'green'))

def scan_xss(url, payloads):
    headers = {"User-Agent": "Mozilla/5.0"}
    for payload in payloads:
        try:
            response = requests.get(url, headers=headers, params={'q': payload}, timeout=5)
            if payload in response.text:
                print(colored(f"[XSS] Potential vulnerability found with payload: {payload}", 'red'))
        except requests.RequestException as e:
            print(colored(f"[XSS] Error scanning {url}: {e}", 'yellow'))

def scan_sql_injection(url, payloads):
    headers = {"User-Agent": "Mozilla/5.0"}
    for payload in payloads:
        try:
            response = requests.get(url, headers=headers, params={'id': payload}, timeout=5)
            if "sql syntax" in response.text.lower() or "warning" in response.text.lower():
                print(colored(f"[SQLi] Potential vulnerability found with payload: {payload}", 'red'))
        except requests.RequestException as e:
            print(colored(f"[SQLi] Error scanning {url}: {e}", 'yellow'))

def scan_subdomain_takeover(base_url, subdomains):
    headers = {"User-Agent": "Mozilla/5.0"}
    for subdomain in subdomains:
        full_url = f"https://{subdomain}.{base_url}"
        try:
            # Check if the subdomain resolves
            socket.gethostbyname(full_url.replace("https://", ""))
            response = requests.get(full_url, headers=headers, timeout=5)
            if "This domain may be for sale" in response.text or "Domain not found" in response.text:
                print(colored(f"[Subdomain Takeover] Potential vulnerability found: {full_url}", 'red'))
        except (socket.gaierror, requests.RequestException) as e:
            print(colored(f"[Subdomain Takeover] Error scanning {full_url}: {e}", 'yellow'))

def scan_information_disclosure(url):
    headers = {"User-Agent": "Mozilla/5.0"}
    try:
        response = requests.get(url, headers=headers, timeout=5)
        keywords = ["password", "username", "error", "confidential"]
        if any(keyword in response.text.lower() for keyword in keywords):
            print(colored(f"[Info Disclosure] Potential vulnerability found at: {url}", 'red'))
    except requests.RequestException as e:
        print(colored(f"[Info Disclosure] Error scanning {url}: {e}", 'yellow'))

def run_scans():
    print_banner()
    url = input("Enter the URL to scan: ")
    base_url = input("Enter the base URL for subdomain scanning (e.g., example.com): ")

    xss_payloads = ["<script>alert('XSS')</script>", "<img src=x onerror=alert('XSS')>", "<svg/onload=alert('XSS')>"]
    sql_payloads = ["' OR '1'='1", "' OR '1'='1' --", "' OR '1'='1' /*"]
    subdomains = ["test", "dev", "staging", "old"]

    threads = [
        threading.Thread(target=scan_xss, args=(url, xss_payloads)),
        threading.Thread(target=scan_sql_injection, args=(url, sql_payloads)),
        threading.Thread(target=scan_information_disclosure, args=(url,)),
        threading.Thread(target=scan_subdomain_takeover, args=(base_url, subdomains)),
    ]

    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()

if __name__ == "__main__":
    run_scans()
