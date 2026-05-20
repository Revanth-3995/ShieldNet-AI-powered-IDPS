import sys
import re

def patch_file():
    path = "working.md"
    with open(path, "r") as f:
        content = f.read()

    # The rule engine logic is exactly 8 rules.
    old_rules = """**1. The Rule Engine (Fast Path)**
The very first thing that happens is deterministic rule checking.
*   **What it does:** Looks for explicit attack signatures that don't need AI (e.g., 200 SYN packets per second from one IP, or a payload containing `UNION SELECT`).
*   **Action:** If a rule triggers with high confidence (>0.85), ShieldNet **skips the ML entirely**, drops the packet, and issues an immediate alert."""

    new_rules = """**1. The Rule Engine (Fast Path)**
The very first thing that happens is deterministic rule checking using O(1) deque sliding windows.
*   **Rules:** High Connection Rate, SSH Brute Force, Port Sweep, SYN Flood, HTTP Flood, ICMP Flood, Malformed Packets, and Sensitive Port Access / SQLi Signature.
*   **What it does:** Looks for explicit attack signatures that don't need AI.
*   **Action:** If a rule triggers with high confidence (>0.85), ShieldNet **skips the ML entirely**, drops the packet, and issues an immediate alert."""

    content = content.replace(old_rules, new_rules)

    # Response logic
    old_response = """**5. The Response Manager (Automated Action)**
Based on the final fused confidence score, ShieldNet takes action:
*   **Critical (>0.85):** Block IP at the firewall (iptables), write to blocklist DB.
*   **High (0.70 - 0.84):** Quarantine connection, redirect to the Honeypot.
*   **Medium (0.40 - 0.69):** Add IP to the watchlist for elevated scrutiny.
*   **Low (<0.40):** Allow traffic (Benign)."""

    new_response = """**5. The Response Manager (Automated Action)**
Based on the final fused confidence score, ShieldNet takes action dynamically via `iptables` or Windows `netsh`:
*   **Critical (>0.85):** Block IP at the firewall (iptables), write to blocklist DB. Triggers cross-pipeline Steg notification to lower threshold via `api/watch-endpoint`.
*   **High (0.70 - 0.84):** Quarantine connection, redirect to the Honeypot. Triggers Steg notification to lower threshold.
*   **Medium (0.40 - 0.69):** Add IP to the watchlist for elevated scrutiny (multiplier=0.7).
*   **Low (<0.40):** Allow traffic (Benign)."""

    content = content.replace(old_response, new_response)

    with open(path, "w") as f:
        f.write(content)

patch_file()
