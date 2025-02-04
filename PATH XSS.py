import os
import time
import logging
import urllib3
from urllib.parse import urlsplit, urlunsplit, parse_qs, urlencode
from concurrent.futures import ThreadPoolExecutor, as_completed
from queue import Queue
from threading import Lock
from selenium import webdriver
from selenium.webdriver.chrome.service import Service
from selenium.webdriver.common.by import By
from selenium.webdriver.support.ui import WebDriverWait
from selenium.webdriver.support import expected_conditions as EC
from selenium.common.exceptions import TimeoutException, UnexpectedAlertPresentException
from webdriver_manager.chrome import ChromeDriverManager
from selenium.webdriver.chrome.options import Options
from colorama import Fore, Style, init
from rich.console import Console
from rich.panel import Panel
from prompt_toolkit import prompt
from prompt_toolkit.completion import PathCompleter

# Initialize colorama
init(autoreset=True)

# Disable SSL warnings
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# Configure logging
logging.getLogger('WDM').setLevel(logging.ERROR)
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

# Initialize console
console = Console()

# Global variables
browser_queue = Queue()
queue_lock = Lock()

def show_banner():
    banner_text = r"""
██████╗  █████╗ ████████╗██╗  ██╗    ██╗  ██╗███████╗███████╗
██╔══██╗██╔══██╗╚══██╔══╝██║  ██║    ╚██╗██╔╝██╔════╝██╔════╝
██████╔╝███████║   ██║   ███████║     ╚███╔╝ ███████╗███████╗
██╔═══╝ ██╔══██║   ██║   ██╔══██║     ██╔██╗ ╚════██║╚════██║
██║     ██║  ██║   ██║   ██║  ██║    ██╔╝ ██╗███████║███████║
╚═╝     ╚═╝  ╚═╝   ╚═╝   ╚═╝  ╚═╝    ╚═╝  ╚═╝╚══════╝╚══════╝
"""
    console.print(Panel(banner_text, style="bold cyan", border_style="magenta"))

def read_payloads(file_path):
    try:
        with open(file_path, "r") as f:
            return [line.strip() for line in f if line.strip()]
    except Exception as err:
        print(Fore.RED + f"[!] Error loading payloads: {err}")
        os._exit(0)

def initialize_driver():
    options = Options()
    options.add_argument("--headless")
    options.add_argument("--no-sandbox")
    options.add_argument("--disable-dev-shm-usage")
    options.add_argument("--disable-gpu")
    options.add_argument("--disable-extensions")
    options.add_argument("--disable-dev-shm-usage")
    options.add_argument("--disable-browser-side-navigation")
    options.add_argument("--disable-infobars")
    options.add_argument("--disable-notifications")
    options.page_load_strategy = 'eager'
    logging.disable(logging.CRITICAL)

    # Automatically determine the best ChromeDriver version
    driver_service = Service(ChromeDriverManager().install())
    return webdriver.Chrome(service=driver_service, options=options)

def acquire_driver():
    try:
        return browser_queue.get_nowait()
    except:
        with queue_lock:
            return initialize_driver()

def release_driver(browser):
    browser_queue.put(browser)

def test_vulnerability(url, payload, vulnerable_list, scan_count, wait_time):
    browser = acquire_driver()
    try:
        test_url = url.replace("FUZZ", payload)
        print(Fore.BLUE + f"[i] Testing URL: {test_url} with payload: {Fore.YELLOW}{payload}")
        
        browser.get(test_url)
        scan_count[0] += 1
        
        try:
            alert = WebDriverWait(browser, wait_time).until(EC.alert_is_present())
            alert_content = alert.text

            if alert_content:
                result = Fore.GREEN + f"[✓] {Fore.MAGENTA}Vulnerable:{Fore.GREEN} {test_url} {Fore.MAGENTA}- Alert Text: {alert_content}"
                print(result)
                vulnerable_list.append(test_url)
                alert.accept()
            else:
                result = Fore.RED + f"[✗] {Fore.MAGENTA}Not Vulnerable:{Fore.RED} {test_url}"
                print(result)

        except TimeoutException:
            print(Fore.RED + f"[✗] {Fore.MAGENTA}Not Vulnerable:{Fore.RED} {test_url}")

    except UnexpectedAlertPresentException:
        pass
    finally:
        release_driver(browser)

def execute_scan(urls, payload_file, wait_time):
    payloads = read_payloads(payload_file)
    vulnerable_list = []
    scan_count = [0]
    
    for _ in range(3):
        browser_queue.put(initialize_driver())
    
    try:
        with ThreadPoolExecutor(max_workers=2) as executor:
            tasks = []
            for url in urls:
                for payload in payloads:
                    tasks.append(
                        executor.submit(
                            test_vulnerability,
                            url,
                            payload,
                            vulnerable_list,
                            scan_count,
                            wait_time
                        )
                    )
            
            for task in as_completed(tasks):
                try:
                    task.result(wait_time)
                except Exception as err:
                    print(Fore.RED + f"[!] Error during scan: {err}")
                    
    finally:
        while not browser_queue.empty():
            browser = browser_queue.get()
            browser.quit()
            
        return vulnerable_list, scan_count[0]

def display_summary(found_count, scanned_count, start_time):
    summary_info = [
        f"{Fore.MAGENTA}→ Scanning finished.",
        f"{Fore.CYAN}• Total Vulnerable URLs Found: {Fore.GREEN}{found_count}",
        f"{Fore.CYAN}• Total URLs Scanned: {Fore.GREEN}{scanned_count}",
        f"{Fore.CYAN}• Time Taken: {Fore.GREEN}{int(time.time() - start_time)} seconds"
    ]
    for info in summary_info:
        print(info)

def save_results(vulnerable_list):
    if vulnerable_list:
        output_file = "vulnerable_urls.txt"
        with open(output_file, "w") as f:
            for url in vulnerable_list:
                f.write(url + "\n")
        print(f"{Fore.GREEN}[✓] Vulnerable URLs saved to {Fore.CYAN}{output_file}")
    else:
        print(f"{Fore.RED}[✗] No vulnerable URLs found to save.")

def clear_console():
    os.system('cls' if os.name == 'nt' else 'clear')

def get_file_input(prompt_message):
    completer = PathCompleter()
    return prompt(prompt_message, completer=completer).strip()

def ask_for_urls():
    while True:
        try:
            file_input = get_file_input("[?] Enter the path to the input file containing URLs (or press Enter to enter a single URL): ")
            if file_input:
                if not os.path.isfile(file_input):
                    raise FileNotFoundError(f"File not found: {file_input}")
                with open(file_input) as f:
                    urls = [line.strip() for line in f if line.strip()]
                return urls
            else:
                single_url = input(Fore.BLUE + "[?] Enter a single URL to scan: ").strip()
                if single_url:
                    return [single_url]
                else:
                    print(Fore.RED + "[!] You must provide either a file with URLs or a single URL.")
                    input(Fore.YELLOW + "\n[i] Press Enter to try again...")
                    clear_console()
                    show_banner()
                    print(Fore.CYAN + "Welcome to the PATH XSS Scanner!\n")
        except Exception as err:
            print(Fore.RED + f"[!] Error reading the input file. Exception: {str(err)}")
            input(Fore.YELLOW + "[i] Press Enter to try again...")
            clear_console()
            show_banner()
            print(Fore.CYAN + "Welcome to the PATH XSS Scanner!\n")

def ask_for_payload_file(prompt_message):
    while True:
        file_path = get_file_input(prompt_message).strip()
        if not file_path:
            print(Fore.RED + "[!] You must provide a file containing the payloads.")
            input(Fore.YELLOW + "[i] Press Enter to try again...")
            clear_console()
            show_banner()
            print(Fore.CYAN + "Welcome to the PATH XSS Scanner!\n")
            continue
        if os.path.isfile(file_path):
            return file_path
        else:
            print(Fore.RED + "[!] Error reading the input file.")
            input(Fore.YELLOW + "[i] Press Enter to try again...")
            clear_console()
            show_banner()
            print(Fore.CYAN + "Welcome to the PATH XSS Scanner!\n")

def main():
    clear_console()
    time.sleep(0.1)
    clear_console()
    show_banner()
    print(Fore.CYAN + "Welcome to the PATH XSS Testing Tool!\n")
    urls_to_scan = ask_for_urls()

    payload_file_path = ask_for_payload_file("[?] Enter the path to the payloads file: ")
    
    try:
        timeout_duration = float(input(Fore.BLUE + "Enter the timeout duration for each request (Press Enter for 0.5): "))
    except ValueError:
        timeout_duration = 0.5

    clear_console()
    print(f"{Fore.MAGENTA}[i] Starting scan...\n")

    all_vulnerable_urls = []
    total_scanned = 0
    start_time = time.time()

    try:
        for url in urls_to_scan:
            box_content = f" → Scanning URL: {url} "
            box_width = max(len(box_content) + 2, 40)
            print(Fore.YELLOW + "\n┌" + "─" * (box_width - 2) + "┐")
            print(Fore.YELLOW + f"│{box_content.center(box_width - 2)}│")
            print(Fore.YELLOW + "└" + "─" * (box_width - 2) + "┘\n")

            vulnerable_urls, scanned = execute_scan([url], payload_file_path, timeout_duration)
            all_vulnerable_urls.extend(vulnerable_urls)
            total_scanned += scanned

    except KeyboardInterrupt:
        print(Fore.RED + "\n[!] Scan interrupted by the user.")
        display_summary(len(all_vulnerable_urls), total_scanned, start_time)
        save_results(all_vulnerable_urls)
        os._exit(0)

    display_summary(len(all_vulnerable_urls), total_scanned, start_time)
    save_results(all_vulnerable_urls)
    os._exit(0)

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print(Fore.RED + "\n[!] Scan interrupted by the user. Exiting...")
        os._exit(0)
