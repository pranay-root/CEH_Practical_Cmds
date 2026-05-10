# 🛡️ CEH Practical: Ultimate Command Handbook
[![Hacking](https://img.shields.io/badge/Focus-Ethical%20Hacking-red?style=for-the-badge&logo=kali-linux)](https://github.com/pranay-root/CEH_Practical_Cmds)
[![Tools](https://img.shields.io/badge/Tools-Kali_Linux-blue?style=for-the-badge&logo=linux)](https://github.com/pranay-root/CEH_Practical_Cmds)

> **The "Cheat Sheet" for the CEH Practical.** A streamlined collection of high-success commands for enumeration, exploitation, and post-exploitation.

---

## 📑 Table of Contents
* [🔍 Recon & Enumeration](#-recon--enumeration)
* [🌐 Web Vulnerability Scanning](#-web-vulnerability-scanning)
* [🔓 System Hacking & Cracking](#-system-hacking--cracking)
* [📈 Privilege Escalation](#-privilege-escalation)
* [🐚 Shells & File Transfers](#-shells--file-transfers)
* [📡 Network Analysis (Wireshark)](#-network-analysis-wireshark)

## 🔍 Recon & Enumeration

### 1. Nmap (Network Discovery)
*The gold standard for finding open ports and services.*

```bash
# Aggressive scan (OS detection, versioning, scripts, traceroute)
nmap -A -T4 <target-ip>

# Fast scan for all 65535 ports
nmap -p- --min-rate 5000 <target-ip>

# Vulnerability scan using Nmap scripts
nmap --script vuln <target-ip>

#general efficient scan for top 1000 ports with version detection
nmap -Pn -n <target-ip> -sV

# firewall evasion scans
nmap -f <target-ip>
nmap -D 10.0.0.1,10.0.0.2,ME <target-ip> (decoy scan)
nmap -S <spoofed-ip> <targt-ip> (spoofed scan)
nmap -g 53 10.0.0.1  (port manipulation scan)
nmap --proxies socks4://127.0.0.1:9050 <target-ip> (scan with proxy)
nmap --data-length 25 <target-ip> (Evading simple packet-size filters.)

```

### 2. Gobuster and ffuf (Directory/File Discovery)

*Essential for finding hidden admin panels or config files.*

```bash
# Common directory brute-force
gobuster dir -u http://<target-ip>/ -w /usr/share/wordlists/dirb/common.txt
ffuf -c -w wordlist -u "https://cyberblockz.org" -H "HOST: FUZZ.cyberblockz.org" -t 2 -mc 200,301

# Searching for specific file extensions
gobuster dir -u http://<target-ip>/ -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -x php,txt,html,zip

```

### 3. SMB Enumeration

*Most common entry point in Windows-based labs.*

```bash
# List shares using null session
smbclient -L //<target-ip>/ -N

# Enumerate users and shares with enum4linux
enum4linux -a <target-ip>

```

---

**How does this look for the start?** If you're happy with these, let me know and I'll give you the **Web Vulnerability & System Hacking** section next.

```

```
