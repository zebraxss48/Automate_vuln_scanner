import requests
import threading
import yaml
import json
import argparse
import logging
import random
from tqdm import tqdm
from concurrent.futures import ThreadPoolExecutor
from termcolor import colored
import re

# Awesome ASCII Banner
def print_banner():
    banner = """
    █████╗ ███████╗██╗  ██╗██╗███╗   ██╗██╗  ██╗██████╗  █████╗ ██╗
   ██╔══██╗██╔════╝██║  ██║██║████╗  ██║██║  ██║██╔══██╗██╔══██╗██║
   ███████║███████╗███████║██║██╔██╗ ██║███████║██████╔╝███████║██║
   ██╔══██║╚════██║██╔══██║██║██║╚██╗██║██╔══██║██╔══██╗██╔══██║██║
   ██║  ██║███████║██║  ██║██║██║ ╚████║██║  ██║██║  ██║██║  ██║███████╗
   ╚═╝  ╚═╝╚══════╝╚═╝  ╚═╝╚═╝╚═╝  ╚═══╝╚═╝  ╚═╝╚═╝  ╚═╝╚═╝  ╚═╝╚══════╝
    """
    print(colored(banner, "red"))

# Configure Logging
logging.basicConfig(filename="scanner.log", level=logging.INFO, format="%(asctime)s - %(message)s")

def load_payloads(filename="payloads.yaml"):
    with open(filename, "r") as file:
        return yaml.safe_load(file)

def save_results(results, filename="scan_results.json"):
    with open(filename, "w") as file:
        json.dump(results, file, indent=4)
    print(colored(f"\n[✔] Results saved to {filename}", "cyan"))

def send_request(url, params, timeout=10):
    headers = {"User-Agent": "Mozilla/5.0"}
    try:
        return requests.get(url, headers=headers, params=params, timeout=timeout)
    except requests.RequestException as e:
        logging.warning(f"[!] Error scanning {url}: {e}")
        return None

def scan_xss(url, payloads, results, progress_bar):
    for payload in payloads:
        response = send_request(url, {'q': payload})
        if response and payload in response.text:
            results.append({"type": "XSS", "url": url, "payload": payload})
            print(colored(f"[XSS] Vulnerability found: {payload}", "red"))
            logging.info(f"XSS Vulnerability found at {url} with payload: {payload}")
        progress_bar.update(1)

def scan_sql_injection(url, payloads, results, progress_bar):
    for payload in payloads:
        response = send_request(url, {'id': payload})
        if response and re.search(r"(sql syntax|warning|mysql_fetch_array|native client)", response.text.lower()):
            results.append({"type": "SQLi", "url": url, "payload": payload})
            print(colored(f"[SQLi] Vulnerability found: {payload}", "red"))
            logging.info(f"SQL Injection found at {url} with payload: {payload}")
        progress_bar.update(1)

def scan_command_injection(url, payloads, results, progress_bar):
    for payload in payloads:
        response = send_request(url, {'cmd': payload})
        if response and re.search(r"(root:x:0:0:|bash:.*command not found)", response.text):
            results.append({"type": "Command Injection", "url": url, "payload": payload})
            print(colored(f"[Command Injection] Vulnerability found: {payload}", "red"))
            logging.info(f"Command Injection found at {url} with payload: {payload}")
        progress_bar.update(1)

def run_scans(url):
    print_banner()
    payloads = load_payloads()
    results = []
    total_tasks = sum(len(payloads[key]) for key in payloads)
    print("\n[✔] Starting aggressive scans...\n")
    
    with tqdm(total=total_tasks, desc="Scanning Progress") as progress_bar, ThreadPoolExecutor(max_workers=20) as executor:
        scan_functions = [scan_xss, scan_sql_injection, scan_command_injection]
        random.shuffle(scan_functions)  # Shuffle execution order for unpredictability
        for scan_func in scan_functions:
            executor.submit(scan_func, url, payloads[scan_func.__name__.split('_')[1]], results, progress_bar)
    
    save_results(results)

def main():
    parser = argparse.ArgumentParser(description="🔥 Aggressive Web Vulnerability Scanner 🔥")
    parser.add_argument("-u", "--url", help="Target URL", required=True)
    args = parser.parse_args()
    run_scans(args.url)

if __name__ == "__main__":
    main()
