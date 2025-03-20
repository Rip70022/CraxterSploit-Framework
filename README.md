# CraxterSploit-Framework

This is a comprehensive Python script designed to assist cybersecurity professionals in performing a variety of security assessments and penetration testing tasks. It supports a number of popular tools including Nmap, Metasploit, Hydra, Aircrack-ng, SQLMap, John the Ripper, Nikto, and others, offering users an easy-to-use command-line interface to interact with these tools.

The script automates the installation and execution of a number of security tools on Kali Linux. It allows users to perform network scans, password cracking, vulnerability assessments, and other penetration testing tasks with ease.

## Features

`Tool Installation`: Installs essential penetration testing tools if not already installed.

`Network Scanning`: Run nmap to perform basic, comprehensive, and vulnerability scans on target IPs.

`Penetration Testing`: Run Metasploit exploits, including the infamous EternalBlue.

`Brute Force Attacks`: Use Hydra to perform brute force attacks on various services such as SSH, FTP, and HTTP.

`Wireless Attacks`: Utilize Aircrack-ng for wireless network security assessments.

`SQL Injection Testing`: Use SQLMap to detect and exploit SQL injection vulnerabilities.

`Password Cracking`: Crack password hashes with John the Ripper.

`Web Server Scanning`: Perform security scanning on web servers using Nikto.


## Requirements

`Python 3.x`: This script requires Python 3.

`Kali Linux`: This script is optimized for Kali Linux. It will work on other Linux distributions, but you may encounter compatibility issues.

`Root Privileges`: Some functionalities require root privileges to install tools and perform network-related tasks.


## Dependencies

`colorama` - For terminal text colorization.

`terminaltables` - For displaying options and tool statuses in a table format.

`subprocess`, socket, os, shutil, argparse, re, signal - Python standard libraries.


## Installation

1. Clone the repository:
```
git clone https://github.com/Rip70022/CraxterSploit-Framework.git
cd CraxterSploit-Framework
```


## Usage

- Script Execution

- Run the script with root privileges:
```
sudo python3 CSF.py
```

## Main Features

1. Tool Installation: The script checks if each tool is installed and displays the status. You can use the command `install <tool_id>` to install any missing tool.


2. Scanning and Exploiting: The script provides an interactive menu where you can choose from different tools and actions (e.g., running Nmap scans, using Metasploit, etc.).


3. Command Options: The following commands are available:

`install <tool_id>`: Installs the tool specified by the ID.

`exit`: Exits the script.



4. Example Actions: Some of the actions include:

Nmap: Network scanning options like quick scan, vulnerability scan, etc.

Metasploit: Starting the console or running specific exploits.

Hydra: Running brute force attacks on SSH, FTP, etc.

Aircrack-ng: Capture WiFi handshakes and crack WPA keys.

SQLMap: Detect and exploit SQL injection vulnerabilities.

John the Ripper: Crack Linux, Windows, or ZIP password hashes.




## Displaying the Banner

The script displays a customized banner each time it is run, showing details like the target IP, version, and current time.

Example Output
```
[+] Nmap Scan Options:
[1] Quick Scan
[2] Comprehensive Scan
[3] Vulnerability Scan
[4] Custom Scan

[*] Select an option:

Example Command to Install a Tool

[*] Use 'install 1' to install nmap.
```

## Contributing

Feel free to fork, submit issues, and send pull requests. Contributions are always welcome.

## License

This project is licensed under the MIT License - see the LICENSE file for details.


## **AUTHOR:**
- `Rip70022/NAXROC/craxterpy`

## Disclaimer

This script is intended for `educational` and professional use only. Use it responsibly and only on networks and systems for which you have explicit authorization. Unauthorized use of these tools may be illegal and unethical.
