#!/usr/bin/env python3
import os
import socket
import getpass
import platform
import hashlib
import sys

# --- GUARDRAIL CONFIGURATION SECTION ---
ALLOWED_USERS = ['secadmin', 'redteam']
ALLOWED_HOSTNAMES = ['target-vm1', 'labhost']
ALLOWED_IPS = ['10.130.10.4', '192.168.56.101']
ALLOWED_MAC_HASHES = [
    '5d41402abc4b2a76b9719d911017c592'  # Example MD5 of MAC address
]
ALLOWED_OS = ['Linux']
# ---------------------------------------

# --- FUNCTION: GET MAC ADDRESS HASH ---
def get_mac_hash():
    import uuid
    mac = uuid.getnode()
    return hashlib.md5(str(mac).encode()).hexdigest()

# --- FUNCTION: GUARDRAIL ENFORCEMENT ---
def check_guardrails():
    current_user = getpass.getuser()
    hostname = socket.gethostname()
    try:
        local_ip = socket.gethostbyname(hostname)
    except socket.gaierror:
        local_ip = '0.0.0.0'
    os_name = platform.system()
    mac_hash = get_mac_hash()

    print("[*] Checking guardrails...")

    if current_user not in ALLOWED_USERS:
        print(f"[!] User '{current_user}' not authorized.")
        return False
    if hostname not in ALLOWED_HOSTNAMES:
        print(f"[!] Hostname '{hostname}' not allowed.")
        return False
    if local_ip not in ALLOWED_IPS:
        print(f"[!] IP address '{local_ip}' not in scope.")
        return False
    if os_name not in ALLOWED_OS:
        print(f"[!] OS '{os_name}' not permitted.")
        return False
    if mac_hash not in ALLOWED_MAC_HASHES:
        print(f"[!] MAC address hash '{mac_hash}' not matched.")
        return False

    print("[+] All guardrails passed.")
    return True

# --- MAIN EXECUTION BLOCK ---
def main():
    if not check_guardrails():
        print("[-] Exiting: guardrails did not pass.")
        sys.exit(1)

    print("[+] Payload executing...")
    # ---- PAYLOAD CODE HERE ----
    # os.system("your command here")
    print("Hello from within guardrails!")

if __name__ == '__main__':
    main()
