import concurrent.futures
import socket
import time
import random
import os
import requests
import urllib3
from ipaddress import ip_network
from tabulate import tabulate

# Disable SSL verification warnings in terminal for clean output
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# Full Iran ISP IP Ranges Database
ISP_DATABASE = {
    "tci": {
        "name": "TCI (Mokhaberat - ADSL/VDSL/Fiber)",
        "keywords": ["tci", "telecommunication", "mokhaberat"],
        "ranges": [
            "2.176.0.0/14", "5.213.0.0/16", "78.38.0.0/16", "78.39.0.0/16",
            "91.98.0.0/16", "91.99.0.0/16", "37.254.0.0/16", "37.255.0.0/16",
            "185.120.240.0/22", "188.136.0.0/16"
        ]
    },
    "shatel": {
        "name": "Shatel (ADSL/VDSL/Fiber)",
        "keywords": ["shatel", "aria ratsand"],
        "ranges": [
            "85.185.0.0/16", "79.127.0.0/17", "94.182.0.0/16", "94.183.0.0/16",
            "185.8.172.0/22", "185.8.174.0/24", "161.1.1.0/24"
        ]
    },
    "irancell": {
        "name": "Irancell (Mobile/TD-LTE/Fiber)",
        "keywords": ["irancell", "mtn"],
        "ranges": [
            "5.112.0.0/13", "37.130.0.0/16", "92.42.0.0/18", "109.125.128.0/17",
            "176.200.0.0/14", "185.212.0.0/22"
        ]
    },
    "mci": {
        "name": "MCI (Hamrah Aval Mobile)",
        "keywords": ["mci", "mobile communication company of iran", "hamrah"],
        "ranges": [
            "5.232.0.0/14", "80.253.144.0/20", "94.232.128.0/18", "192.152.0.0/16",
            "37.32.0.0/16", "213.217.32.0/19"
        ]
    },
    "mobinnet": {
        "name": "Mobinnet (TD-LTE)",
        "keywords": ["mobinnet", "ertelecom"],
        "ranges": [
            "46.209.0.0/16", "188.122.96.0/19", "194.225.12.0/22", "130.185.16.0/20"
        ]
    }
}

def clear_screen():
    """Forces the terminal screen to be completely wiped out (Fixes Windows terminal bugs)."""
    if os.name == 'nt':
        # Pure Windows command to wipe screen and scrollback buffer
        os.system('cls')
    else:
        # Linux/macOS standard clear
        os.system('clear')

def get_ascii_banner():
    """Returns the stylized ASCII logo string."""
    return """
    \033[95m████████╗\033[94m███████╗\033[96m██████╗\033[92m██╗  ██╗\033[93m███╗   ██╗\033[91m██████╗ \033[35m███████╗███████╗
    \033[95m╚══██╔══╝\033[94m██╔════╝\033[96m██╔══██╗██║  ██║\033[93m████╗  ██║\033[91m██╔══██╗\033[35m╚══███╔╝╚════██║
       \033[95m██║   \033[94m█████╗  \033[96m██║  ██║███████║\033[93m██╔██╗ ██║\033[91m██║  ██║\033[35m  ███╔╝     ██╔╝
       \033[95m██║   \033[94m██╔══╝  \033[96m██║  ██║██╔══██║\033[93m██║╚██╗██║\033[91m██║  ██║\033[35m ███╔╝     ██╔╝ 
       \033[95m██║   \033[94m███████╗\033[96m██████╔╝██║  ██║\033[93m██║ ╚████║\033[91m██████╔╝\033[35m███████╗  ██║   
       \033[95m╚═╝   \033[94m╚══════╝\033[96m╚═════╝ ╚═╝  ╚═╝\033[93m╚═╝  ╚═══╝\033[91m╚═════╝ \033[35m╚══════╝  ╚═╝   
    """

def show_welcome_banner():
    """Displays the logo with a 5-second delay for the initial app start."""
    clear_screen()
    print(get_ascii_banner())
    print("\033[90m=" * 77)
    print("\033[97m   [+] Network Scanner Tuned for Restricted Networks | Channel: TechNodeZ   ")
    print("\033[90m=" * 77)
    print("\033[93m\n[*] Initializing database and checking system cores... Please wait 3s.")
    time.sleep(3)
    clear_screen()

def show_static_banner():
    """Displays the logo instantly without delay for the manual menu loop."""
    clear_screen()
    print(get_ascii_banner())
    print("\033[90m=" * 77)
    print("\033[97m   [+] Network Scanner Tuned for Restricted Networks | Channel: TechNodeZ   ")
    print("\033[90m=" * 77)
    print("\033[0m") # Reset colors

def auto_detect_isp():
    """Tries to detect the user's ISP using an unblocked public API."""
    print("[*] Detecting your Network Provider (ISP)...")
    urls = [
        "http://ip-api.com/json/",
        "https://ipapi.co/json/"
    ]
    
    for url in urls:
        try:
            response = requests.get(url, timeout=3)
            if response.status_code == 200:
                data = response.json()
                org_name = data.get("org", "").lower() or data.get("isp", "").lower()
                user_ip = data.get("query") or data.get("ip")
                
                print(f"[+] Your Public IP: {user_ip}")
                print(f"[+] Network Info: {data.get('isp', 'Unknown')}")
                
                for isp_key, isp_info in ISP_DATABASE.items():
                    for keyword in isp_info["keywords"]:
                        if keyword in org_name:
                            return isp_key
        except Exception:
            continue
            
    return None

def get_random_ips(cidr_list, sample_per_cidr=35):
    """Generates a smart random subset of IPs from given CIDRs."""
    sampled_ips = []
    for cidr in cidr_list:
        try:
            network = ip_network(cidr)
            hosts = list(network.hosts())
            count = min(len(hosts), sample_per_cidr)
            sampled_ips.extend([str(ip) for ip in random.sample(hosts, count)])
        except Exception:
            continue
    return sampled_ips

def test_tcp_port(ip, port=443, timeout=1.0):
    """Performs a real TCP handshake check."""
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        result = sock.connect_ex((ip, port))
        sock.close()
        if result == 0:
            return True
    except Exception:
        return False
    return False

def verify_real_latency(ip, port=443):
    """Performs a real HTTP/TLS content fetch to bypass Fake Handshaking."""
    url = f"https://{ip}/cdn-cgi/trace"
    headers = {"Host": "www.cloudflare.com"}
    
    start_time = time.time()
    try:
        response = requests.get(url, headers=headers, timeout=1.5, verify=False)
        if response.status_code == 200 and "h=" in response.text:
            real_latency = round((time.time() - start_time) * 1000)
            return real_latency
    except Exception:
        return None
    return None

def worker_unit(ip):
    if test_tcp_port(ip, port=443, timeout=1.0):
        real_ping = verify_real_latency(ip, port=443)
        if real_ping and real_ping > 20:
            return {"IP": ip, "Port": "443", "Status": "Verified Clean", "RTT_MS": real_ping}
    return None

def run_scan_flow(force_manual=False):
    """Handles a single complete scan flow."""
    if force_manual:
        show_static_banner()
        detected_key = None
    else:
        print("====================================")
        print("    SMART IRAN ISP IP SCANNER       ")
        print("====================================\n")
        detected_key = auto_detect_isp()
        
    selected_isp = None

    if detected_key:
        selected_isp = ISP_DATABASE[detected_key]
        print(f"\n[SUCCESS] Auto-matched with: {selected_isp['name']}\n")
    else:
        if not force_manual:
            print("\n[-] Auto-detection failed or ISP not in database.")
        print("[*] Manual Selection Mode:\n")
        
        keys_list = list(ISP_DATABASE.keys())
        for idx, k in enumerate(keys_list, 1):
            print(f"{idx}. {ISP_DATABASE[k]['name']}")
            
        try:
            choice = input("\nSelect your ISP number: ")
            choice_idx = int(choice) - 1
            if 0 <= choice_idx < len(keys_list):
                selected_isp = ISP_DATABASE[keys_list[choice_idx]]
            else:
                print("[Error] Invalid selection.")
                return
        except ValueError:
            print("[Error] Invalid input.")
            return

    # Step 2: Extracting Samples and Scanning
    print(f"\n[+] Gathering target ranges for {selected_isp['name']}...")
    target_ips = get_random_ips(selected_isp["ranges"], sample_per_cidr=35)
    print(f"[+] Total generated sample size: {len(target_ips)} IPs.")
    print("[!] Scanning with Anti-Fake Ping engine. Please wait...\n")
    
    all_clean_ips = []
    
    with concurrent.futures.ThreadPoolExecutor(max_workers=60) as executor:
        futures = {executor.submit(worker_unit, ip): ip for ip in target_ips}
        for future in concurrent.futures.as_completed(futures):
            res = future.result()
            if res:
                all_clean_ips.append(res)

    print("\n================ TOP 20 BEST CLEAN IPs REPORT ================")
    if all_clean_ips:
        all_clean_ips.sort(key=lambda x: x['RTT_MS'])
        top_20_ips = all_clean_ips[:20]
        
        display_list = []
        for item in top_20_ips:
            display_list.append({
                "IP": item["IP"],
                "Port": item["Port"],
                "Status": item["Status"],
                "Real Ping (RTT)": f"{item['RTT_MS']}ms"
            })
            
        print(tabulate(display_list, headers="keys", tablefmt="grid"))
    else:
        print("[-] No genuinely clean IPs found in this batch. Run again to try another random pool.")
    print("==============================================================")

def main():
    # 1. Show the animated 5s intro on very first boot
    show_welcome_banner()
    
    # First execution attempt (uses auto-detect)
    run_scan_flow(force_manual=False)
    
    # 2. Main interactive application loop based on User Request
    while True:
        print("\n" + "="*45)
        user_input = input("Do you want to scan again? (y/n): ").strip().lower()
        print("="*45)
        
        # If user types N or No -> Exit the application
        if user_input in ['n', 'no']:
            print("\n[+] Thank you for using TechNodeZ Scanner. Exiting safely...")
            break
        # If user wants to scan again -> WIPE screen and enforce manual mode
        else:
            # Force manual mode, which triggers the brand new deep-clean clear_screen()
            run_scan_flow(force_manual=True)

if __name__ == "__main__":
    main()