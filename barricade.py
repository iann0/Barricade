import json
import argparse
import os
from engine import start_firewall, RULES_FILE

# Load rules from file
def load_rules():
    if not os.path.exists(RULES_FILE):
        return {"blocked_ips": [], "blocked_ports": [], "blocked_protocols": []}
    with open(RULES_FILE, "r") as f:
        return json.load(f)

# Save rules to file
def save_rules(rules):
    with open(RULES_FILE, "w") as f:
        json.dump(rules, f, indent=4)

# Add a rule
def add_rule(rule_type, value):
    rules = load_rules()
    if value not in rules[rule_type]:
        rules[rule_type].append(value)
        save_rules(rules)
        print(f"Rule added: {rule_type} → {value}")
    else:
        print("Already exists.")

# Remove a rule
def remove_rule(rule_type, value):
    rules = load_rules()
    if value in rules[rule_type]:
        rules[rule_type].remove(value)
        save_rules(rules)
        print(f"Rule removed: {rule_type} → {value}")
    else:
        print("Not found.")

# Print all rules
def list_rules():
    rules = load_rules()
    print(json.dumps(rules, indent=4))


# CLI Argument Parser
parser = argparse.ArgumentParser(description="Barricade - A simple python firewall")
parser.add_argument("--start", action="store_true", help="Start firewall")
parser.add_argument("--list", action="store_true", help="List current rules")
parser.add_argument("--add", nargs=2, metavar=('type', 'value'), help="Add a rule")
parser.add_argument("--remove", nargs=2, metavar=('type', 'value'), help="Remove a rule")

args = parser.parse_args()

# Route actions
if args.start:
    start_firewall()
elif args.list:
    list_rules()
elif args.add:
    key, val = args.add
    val = eval(val) if key == "blocked_ports" else val  # Ports as int, rest as str
    add_rule(key, val)
elif args.remove:
    key, val = args.remove
    val = eval(val) if key == "blocked_ports" else val
    remove_rule(key, val)
else:
    parser.print_help()