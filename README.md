# Barricade 

Barricade is a lightweight Python-based packet filter and firewall CLI tool that lets you block IPs, ports, and protocols in real time — built with Scapy. Works on Linux environments with no hassle.

---

# Features

- Real-time packet inspection (IP, TCP, UDP, ICMP)
- Block traffic by:
  - IP address
  - TCP/UDP port
  - Protocol (e.g., ICMP)
- Logs all activity with timestamps
- Easy-to-use CLI (add/remove/list rules)
- Cross-platform install (Linux & Termux)

---

# Demo

$ barricade --list { "blocked_ips": ["192.168.1.100"], "blocked_ports": [22], "blocked_protocols": ["ICMP"] }

$ barricade --start Barricade started... press Ctrl+C to stop.

2025-06-24 10:05:01 | 192.168.1.100 -> 8.8.8.8 | Proto: 6 | BLOCKED (IP)

---

# Installation

On Linux

bash
git clone https://github.com/iann0/Barricade.git
cd Barricade
chmod +x install.sh
sudo ./install.sh

On Termux (Android)

git clone https://github.com/iann0/Barricade.git
cd Barricade 
chmod +x install.sh
./install.sh


---

Usage

# Start firewall
barricade --start

# Add rule
barricade --add blocked_ips "192.168.1.1"
barricade --add blocked_ports 80
barricade --add blocked_protocols "ICMP"

# Remove rule
barricade --remove blocked_ports 80

# List rules
barricade --list

---

# Requirements

- Python 3
- scapy library
- Root access on Android(for packet sniffing)

---

# Compatibility
Barricade was tested on the following systems:
  - Termux (Android)
  - Ubuntu 20+
  - Kali Linux
  - Debian 11+
---

# Notes

- This firewall does not block packets at the kernel level. 
- it’s a learning/project tool using Scapy’s sniffing.

Can be extended to drop packets using netfilterqueue + iptables.



---

# License

MIT License — Permission is granted for the use of this code. Enjoy.


---

# Author

Ian Akombe

Passionate about cybersecurity, networking and other fun tech stuff.

---
