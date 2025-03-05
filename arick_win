import requests
import threading
import yaml
import json
import argparse
import logging
from tqdm import tqdm
from concurrent.futures import ThreadPoolExecutor
from termcolor import colored
import re

# Configure Logging
logging.basicConfig(filename="scanner.log", level=logging.INFO, format="%(asctime)s - %(message)s")

def load_payloads(filename="payloads.yaml"):
    with open(filename, "r") as file:
        return yaml.safe_load(file)

def save_results(results, filename="scan_results.json"):
    with open(filename, "w") as file:
        json.dump(results, file, indent=4)
    print(colored(f"\n[✔] Results saved to {filename}", "cyan"))

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

def scan_sql_injection(url, payloads, results, progress_bar):
    headers = {"User-Agent": "Mozilla/5.0"}
    for payload in payloads:
        try:
            response = requests.get(url, headers=headers, params={'id': payload}, timeout=5)
            if re.search(r"(sql syntax|warning|mysql_fetch_array|native client)", response.text.lower()):
                results.append({"type": "SQLi", "url": url, "payload": payload})
                print(colored(f"[SQLi] Vulnerability found: {payload}", "red"))
                logging.info(f"SQL Injection found at {url} with payload: {payload}")
        except requests.RequestException as e:
            logging.warning(f"[SQLi] Error scanning {url}: {e}")
        progress_bar.update(1)

def scan_sensitive_data(url, patterns, results, progress_bar):
    headers = {"User-Agent": "Mozilla/5.0"}
    try:
        response = requests.get(url, headers=headers, timeout=5)
        found_patterns = [pattern for pattern in patterns if re.search(pattern, response.text)]
        if found_patterns:
            results.append({"type": "Sensitive Data Leak", "url": url, "patterns": found_patterns})
            print(colored(f"[Sensitive Data Leak] Found at: {url}", "red"))
            for pattern in found_patterns:
                print(colored(f"  - {pattern}", "yellow"))
                logging.info(f"Sensitive Data Leak found at {url}: {pattern}")
    except requests.RequestException as e:
        logging.warning(f"[Sensitive Data Leak] Error scanning {url}: {e}")
    progress_bar.update(1)

def scan_command_injection(url, payloads, results, progress_bar):
    headers = {"User-Agent": "Mozilla/5.0"}
    for payload in payloads:
        try:
            response = requests.get(url, headers=headers, params={'cmd': payload}, timeout=5)
            if re.search(r"(root:x:0:0:|bash:.*command not found)", response.text):
                results.append({"type": "Command Injection", "url": url, "payload": payload})
                print(colored(f"[Command Injection] Vulnerability found: {payload}", "red"))
                logging.info(f"Command Injection found at {url} with payload: {payload}")
        except requests.RequestException as e:
            logging.warning(f"[Command Injection] Error scanning {url}: {e}")
        progress_bar.update(1)

def scan_lfi(url, payloads, results, progress_bar):
    headers = {"User-Agent": "Mozilla/5.0"}
    for payload in payloads:
        try:
            response = requests.get(url + payload, headers=headers, timeout=5)
            if "root:x:0:0:" in response.text or "boot.ini" in response.text:
                results.append({"type": "LFI", "url": url, "payload": payload})
                print(colored(f"[LFI] Vulnerability found: {payload}", "red"))
                logging.info(f"Local File Inclusion found at {url} with payload: {payload}")
        except requests.RequestException as e:
            logging.warning(f"[LFI] Error scanning {url}: {e}")
        progress_bar.update(1)

def run_scans(url):
    payloads = load_payloads()
    results = []
    total_tasks = sum(len(payloads[key]) for key in payloads)
    print("\n[✔] Starting scans...\n")
    with tqdm(total=total_tasks, desc="Scanning Progress") as progress_bar, ThreadPoolExecutor(max_workers=10) as executor:
        executor.submit(scan_xss, url, payloads["xss"], results, progress_bar)
        executor.submit(scan_sql_injection, url, payloads["sql_injection"], results, progress_bar)
        executor.submit(scan_sensitive_data, url, payloads["sensitive_data"], results, progress_bar)
        executor.submit(scan_command_injection, url, payloads["command_injection"], results, progress_bar)
        executor.submit(scan_lfi, url, payloads["lfi"], results, progress_bar)
    save_results(results)

def main():
    parser = argparse.ArgumentParser(description="Advanced Web Vulnerability Scanner")
    parser.add_argument("-u", "--url", help="Target URL", required=True)
    args = parser.parse_args()
    run_scans(args.url)

if __name__ == "__main__":
    main()
