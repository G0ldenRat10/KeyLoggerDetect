import psutil
import hashlib
import os
import requests
from bs4 import BeautifulSoup
import time


def display_ascii_art():
    art = r"""
   __ __         __                          ___      __          __      __ 
  / //_/__ __ __/ /  ___  ___ ____ ____ ____/ _ \___ / /____ ____/ /_  __/ /_
 / ,< / -_) // / /__/ _ \/ _ `/ _ `/ -_) __/ // / -_) __/ -_) __/ __/ /_  __/
/_/|_|\__/\_, /____/\___/\_, /\_, /\__/_/ /____/\__/\__/\__/\__/\__/   /_/   
         /___/          /___//___/                                           

                    Developed by: ZakaLino                                      
    """
    print(art)
    print("\nBeta Version 1.1")
    time.sleep(3)


# Not added to the list since SPAMHaUS is regularly updated.
malicious_ips = []

malicious_processes = [
    'keylogger',
    'logkeys',
    'xinput',
    'passwordrecorder',
    'clipboardlogger',
    'mousetrack',
    'mousehook',
    'keyboardmonitor',
    'inputlogger',
    'keyspy',
    'remoteadmin',
    'backgroundlog',
    'datasteal',
    'keylogger64',
    'procspy',
    'keylog64',
    'driverupdater',
    'secureinput',
    'passwordstealer',
    'sessionlogger',
    'winservice',
    'mouserecorder',
    'logcapture',
    'clipboardcapture',
    'userinit',
    'eventtracker',
    'ms32',
    'sysinput',
    'kernelsvc',
    'spoolservice'
]


def scrape_malicious_ips():
    urls = [
        'https://www.spamhaus.org/drop/drop.txt',
    ]

    new_malicious_ips = set()
    headers = {
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/105.0.0.0 Safari/537.36'
    }

    for url in urls:
        try:
            response = requests.get(url, headers=headers)
            response.raise_for_status()
            content = response.text

            for line in content.splitlines():
                ip = line.strip()
                if ip and ip not in new_malicious_ips:  # Avoid adding empty lines or duplicates
                    new_malicious_ips.add(ip)

        except Exception as e:
            print(f"Error scraping {url}: {e}")

    return new_malicious_ips


def update_spamhaus_drop_list():
    url = 'https://www.spamhaus.org/drop/drop.txt'
    headers = {
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/105.0.0.0 Safari/537.36'
    }

    try:
        response = requests.get(url, headers=headers)
        response.raise_for_status()
        drop_list = response.text.splitlines()

        new_malicious_ips = {line.strip() for line in drop_list if line.strip() and not line.startswith(';')}

        malicious_ips.extend(new_malicious_ips)
        print(f"Updated Spamhaus DROP list with {len(new_malicious_ips)} IPs.")

    except Exception as e:
        print(f"Error updating Spamhaus DROP list: {e}")


def scrape_malicious_processes():
    urls = [
        'https://blog.malwarebytes.com/',  # Malwarebytes Labs
        'https://www.av-test.org/en/news/',  # AV-TEST
        'https://cymulate.com/blog/',  # Cymulate
        'https://www.phishtank.com/',  # Phishtank
        'https://threatpost.com/'  # ThreatPost
    ]

    new_malicious_processes = set()
    headers = {
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/105.0.0.0 Safari/537.36'
    }

    for url in urls:
        try:
            response = requests.get(url, headers=headers)
            response.raise_for_status()
            soup = BeautifulSoup(response.text, 'html.parser')

            for item in soup.select('selector-for-process-names'):
                process_name = item.get_text().strip().lower()
                new_malicious_processes.add(process_name)

        except Exception as e:
            print(f"Error scraping {url}: {e}")

    return new_malicious_processes


def get_process_hash(proc):
    try:
        if proc.pid == 0:
            return None

        exe_path = proc.exe()
        if os.path.exists(exe_path):
            with open(exe_path, 'rb') as f:
                return hashlib.sha256(f.read()).hexdigest()
    except Exception as e:
        print(f"Error getting hash for process {proc.info['name']}: {e}")
    return None


def standard_scan():
    global malicious_processes
    malicious_processes_set = set(malicious_processes)
    scraped_processes = scrape_malicious_processes()
    malicious_processes_set.update(scraped_processes)

    print("Scanning, please wait", end="")
    for _ in range(5):
        time.sleep(0.5)
        print(".", end="", flush=True)
    print()  # To move to the next line after the dots

    for proc in psutil.process_iter(['pid', 'name']):
        try:
            process_name = proc.info['name'].lower()
            if any(susp_name in process_name for susp_name in malicious_processes_set):
                print(f"[!] Suspicious process detected: {process_name} (PID: {proc.info['pid']})")
        except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
            continue

    input("\nPress Enter to return to the menu...")


def hash_scan():
    user_input_hash = input("Enter SHA256 hash to compare with running processes: ").strip()

    if len(user_input_hash) != 64:
        print("[-] Invalid hash format. Enter a valid SHA256 hash.")
        input("Press Enter to return to the menu...")
        return

    found = False

    for proc in psutil.process_iter(['pid', 'name']):
        try:
            process_hash = get_process_hash(proc)
            if process_hash and process_hash == user_input_hash:
                print(
                    f"[+] Process matches the input hash: {proc.info['name']} (PID: {proc.info['pid']}) - Hash: {process_hash}")
                found = True
        except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
            continue

    if not found:
        print(f"[-] No process matches the input hash: {user_input_hash}")

    input("\nPress Enter to return to the menu...")


def network_activity_monitor():
    global malicious_ips
    # Update malicious IPs via scraping
    scraped_ips = scrape_malicious_ips()
    malicious_ips.extend(scraped_ips)

    print("[+] Monitoring active network connections...\n")
    connections = psutil.net_connections(kind='inet')

    if not connections:
        print("[-] No active network connections.")
    else:
        for conn in connections:
            try:
                process = psutil.Process(conn.pid) if conn.pid else None
                process_name = process.name() if process else "N/A"
                remote_ip = conn.raddr[0] if conn.raddr else "N/A"

                if remote_ip in malicious_ips:
                    print(
                        f"[!] Malicious connection detected: {conn.laddr} -> {remote_ip} (PID: {conn.pid}, Process: {process_name}, Status: {conn.status})")
                else:
                    print(
                        f"[+] Connection: {conn.laddr} -> {remote_ip} (PID: {conn.pid}, Process: {process_name}, Status: {conn.status})")

                if remote_ip in ['IP_ADDRESS_TO_WARN']:  # Replace with actual WALRNABLE IP addresses
                    print(f"[!] WARNING: Found vulnerable IP address: {remote_ip}")

            except (psutil.NoSuchProcess, psutil.AccessDenied):
                continue

    print(f"[+] Found {len(connections)} active network connections.")
    input("\nPress Enter to return to the menu...")


def system_usage_analysis():
    cpu_usage = psutil.cpu_percent(interval=1)
    memory_info = psutil.virtual_memory()

    print(f"[+] CPU usage: {cpu_usage}%")
    print(f"[+] Memory usage: {memory_info.percent}%")
    print(f"[+] Total memory: {memory_info.total / (1024 ** 2):.2f} MB")
    print(f"[+] Free memory: {memory_info.free / (1024 ** 2):.2f} MB")

    cpu_threshold = 80
    memory_threshold = 80

    if cpu_usage > cpu_threshold or memory_info.percent > memory_threshold:
        print("[!] Warning: High system usage detected.")
    else:
        print("Your system usage is normal, not suspecting high usage.")

    input("\nPress Enter to return to the menu...")


def display_menu():
    print("\n---- KeyLoggerDetect+ Menu ----")
    print("1. Standard Scan (Process names)")
    print("2. Hash Scan")
    print("3. Network Activity Monitor")
    print("4. System Usage Analysis")
    print("5. Exit")


def main():
    display_ascii_art()

    while True:
        display_menu()
        choice = input("\nSelect an option: ").strip()

        if choice == '1':
            standard_scan()
        elif choice == '2':
            hash_scan()
        elif choice == '3':
            network_activity_monitor()
        elif choice == '4':
            system_usage_analysis()
        elif choice == '5':
            print("Exiting KeyLoggerDetect+. Goodbye!")
            break
        else:
            print("Invalid option. Please select a valid option.")


if __name__ == '__main__':
    main()
