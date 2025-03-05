import requests
import threading
import socket
import yaml
import json
import argparse
import logging
from tqdm import tqdm
from concurrent.futures import ThreadPoolExecutor
from termcolor import colored

# Configure Logging
logging.basicConfig(filename="scanner.log", level=logging.INFO, format="%(asctime)s - %(message)s")

# Load attack payloads from YAML file
def load_payloads(filename="payloads.yaml"):
    with open(filename, "r") as file:
        return yaml.safe_load(file)

# Save results as JSON report
def save_results(results, filename="scan_results.json"):
    with open(filename, "w") as file:
        json.dump(results, file, indent=4)
    print(colored(f"\n[✔] Results saved to {filename}", "cyan"))

# XSS Scanner
def scan_xss(url, payloads, results, progress_bar):
    headers = {"User-Agent": "Mozilla/5.0"}
    for payload in payloads:
        try:
            response = requests.get(url, headers=headers, params={'q': payload}, timeout=5)
            if payload in response.text:
                results.append({"type": "XSS", "url": url, "payload": payload})
                print(colored(f"[XSS] Vulnerability found: {payload}", "red"))
                logging.info(f"XSS Vulnerability found at {url} with payload: {payload}")
        except requests.RequestException as e:
            logging.warning(f"[XSS] Error scanning {url}: {e}")
        progress_bar.update(1)

# SQL Injection Scanner
def scan_sql_injection(url, payloads, results, progress_bar):
    headers = {"User-Agent": "Mozilla/5.0"}
    for payload in payloads:
        try:
            response = requests.get(url, headers=headers, params={'id': payload}, timeout=5)
            if "sql syntax" in response.text.lower() or "warning" in response.text.lower():
                results.append({"type": "SQLi", "url": url, "payload": payload})
                print(colored(f"[SQLi] Vulnerability found: {payload}", "red"))
                logging.info(f"SQL Injection found at {url} with payload: {payload}")
        except requests.RequestException as e:
            logging.warning(f"[SQLi] Error scanning {url}: {e}")
        progress_bar.update(1)

# Open Redirect Scanner
def scan_open_redirect(url, payloads, results, progress_bar):
    headers = {"User-Agent": "Mozilla/5.0"}
    for payload in payloads:
        try:
            response = requests.get(url, headers=headers, params={'redirect': payload}, timeout=5, allow_redirects=True)
            if payload in response.url:
                results.append({"type": "Open Redirect", "url": url, "payload": payload})
                print(colored(f"[Open Redirect] Vulnerability found: {payload}", "red"))
                logging.info(f"Open Redirect found at {url} with payload: {payload}")
        except requests.RequestException as e:
            logging.warning(f"[Open Redirect] Error scanning {url}: {e}")
        progress_bar.update(1)

# Directory Traversal Scanner
def scan_directory_traversal(url, payloads, results, progress_bar):
    headers = {"User-Agent": "Mozilla/5.0"}
    for payload in payloads:
        try:
            response = requests.get(url + payload, headers=headers, timeout=5)
            if "root:x:0:0:" in response.text or "boot.ini" in response.text:
                results.append({"type": "Directory Traversal", "url": url, "payload": payload})
                print(colored(f"[Directory Traversal] Vulnerability found: {payload}", "red"))
                logging.info(f"Directory Traversal found at {url} with payload: {payload}")
        except requests.RequestException as e:
            logging.warning(f"[Directory Traversal] Error scanning {url}: {e}")
        progress_bar.update(1)

# Subdomain Takeover Scanner
def scan_subdomain_takeover(base_url, subdomains, results, progress_bar):
    headers = {"User-Agent": "Mozilla/5.0"}
    for subdomain in subdomains:
        full_url = f"https://{subdomain}.{base_url}"
        try:
            socket.gethostbyname(f"{subdomain}.{base_url}")
            response = requests.get(full_url, headers=headers, timeout=5)
            if "This domain may be for sale" in response.text or "Domain not found" in response.text:
                results.append({"type": "Subdomain Takeover", "url": full_url})
                print(colored(f"[Subdomain Takeover] Found: {full_url}", "red"))
                logging.info(f"Subdomain takeover vulnerability found: {full_url}")
        except (socket.gaierror, requests.RequestException) as e:
            logging.warning(f"[Subdomain Takeover] Error scanning {full_url}: {e}")
        progress_bar.update(1)

# Multi-threaded scanning function
def run_scans(url, base_url):
    payloads = load_payloads()
    results = []
    
    total_tasks = sum(len(payloads[key]) for key in payloads) + len(payloads["subdomains"])
    
    print("\n[✔] Starting scans...\n")
    with tqdm(total=total_tasks, desc="Scanning Progress") as progress_bar, ThreadPoolExecutor(max_workers=10) as executor:
        executor.submit(scan_xss, url, payloads["xss"], results, progress_bar)
        executor.submit(scan_sql_injection, url, payloads["sql_injection"], results, progress_bar)
        executor.submit(scan_open_redirect, url, payloads["open_redirect"], results, progress_bar)
        executor.submit(scan_directory_traversal, url, payloads["directory_traversal"], results, progress_bar)
        executor.submit(scan_subdomain_takeover, base_url, payloads["subdomains"], results, progress_bar)

    save_results(results)

# Command-line argument parsing
def main():
    parser = argparse.ArgumentParser(description="Advanced Web Vulnerability Scanner")
    parser.add_argument("-u", "--url", help="Target URL", required=True)
    parser.add_argument("-b", "--base-url", help="Base domain for subdomain scanning", required=True)
    args = parser.parse_args()
    
    run_scans(args.url, args.base_url)

if __name__ == "__main__":
    main()
