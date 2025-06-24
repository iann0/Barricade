import json
from scapy.all import sniff, IP, TCP, UDP, ICMP
from datetime import datetime

RULES_FILE = "rules.json"
LOG_FILE = "log.txt"

def load_rules():
    try:
        with open(RULES_FILE, "r") as f:
            return json.load(f)
    except:
        return {"blocked_ips": [], "blocked_ports": [], "blocked_protocols": []}

def log_packet(pkt, reason="ALLOWED"):
    if pkt.haslayer(IP):
        ip = pkt[IP]
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        log_entry = f"{timestamp} | {ip.src} -> {ip.dst} | Proto: {ip.proto} | {reason}"
        print(log_entry)
        with open(LOG_FILE, "a") as f:
            f.write(log_entry + "\n")

def filter_packet(pkt):
    rules = load_rules()
    if pkt.haslayer(IP):
        ip_layer = pkt[IP]

        # Check IP
        if ip_layer.src in rules["blocked_ips"]:
            log_packet(pkt, reason="BLOCKED (IP)")
            return

        # Check protocol
        proto = ip_layer.proto
        if ICMP in pkt and "ICMP" in rules["blocked_protocols"]:
            log_packet(pkt, reason="BLOCKED (ICMP)")
            return

        if TCP in pkt:
            port = pkt[TCP].dport
            if port in rules["blocked_ports"]:
                log_packet(pkt, reason="BLOCKED (TCP port)")
                return

        if UDP in pkt:
            port = pkt[UDP].dport
            if port in rules["blocked_ports"]:
                log_packet(pkt, reason="BLOCKED (UDP port)")
                return

        log_packet(pkt)

def start_firewall():
    print("\nSimple Firewall started... press Ctrl+C to stop.\n")
    sniff(filter="ip", prn=filter_packet, store=0)


### Barricade/firewall.py

import json
import argparse
import os
from engine import start_firewall, RULES_FILE

def load_rules():
    if not os.path.exists(RULES_FILE):
        return {"blocked_ips": [], "blocked_ports": [], "blocked_protocols": []}
    with open(RULES_FILE, "r") as f:
        return json.load(f)

def save_rules(rules):
    with open(RULES_FILE, "w") as f:
        json.dump(rules, f, indent=4)

def add_rule(rule_type, value):
    rules = load_rules()
    if value not in rules[rule_type]:
        rules[rule_type].append(value)
        save_rules(rules)
        print(f"Rule added: {rule_type} → {value}")
    else:
        print("Already exists.")

def remove_rule(rule_type, value):
    rules = load_rules()
    if value in rules[rule_type]:
        rules[rule_type].remove(value)
        save_rules(rules)
        print(f"Rule removed: {rule_type} → {value}")
    else:
        print("Not found.")

def list_rules():
    rules = load_rules()
    print(json.dumps(rules, indent=4))

parser = argparse.ArgumentParser(description="Simple Python Firewall CLI")
parser.add_argument("--start", action="store_true", help="Start firewall")
parser.add_argument("--list", action="store_true", help="List current rules")
parser.add_argument("--add", nargs=2, metavar=('type', 'value'), help="Add a rule")
parser.add_argument("--remove", nargs=2, metavar=('type', 'value'), help="Remove a rule")

args = parser.parse_args()

if args.start:
    start_firewall()
elif args.list:
    list_rules()
elif args.add:
    add_rule(args.add[0], eval(args.add[1]))
elif args.remove:
    remove_rule(args.remove[0], eval(args.remove[1]))
else:
    parser.print_help()


### Barricade/rules.json (Initial)
{
  "blocked_ips": [],
  "blocked_ports": [],
  "blocked_protocols": []
}
