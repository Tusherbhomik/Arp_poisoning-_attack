#!/bin/bash
# arp_defense.sh - Simplified static ARP defense for CSE406 Project
# Prevents ARP poisoning by setting static ARP entries for Client-Server
# Run on Client: sudo bash arp_defense.sh server (for Server IP)
# Run on Server: sudo bash arp_defense.sh client (for Client IP)

echo "[*] Starting Static ARP Defense - CSE406 Project"
echo "========================================="

# Network configuration
CLIENT_IP="192.168.56.252"
SERVER_IP="192.168.56.250"

# Function to discover MAC address
get_mac() {
    local ip=$1
    echo "[*] Discovering MAC for $ip..."
    # Ensure target is reachable
    if ! ping -c 3 -W 1 "$ip" >/dev/null 2>&1; then
        echo "[-] Cannot ping $ip. Ensure target is up."
        return 1
    fi
    # Get MAC from ARP table
    mac=$(arp -n | grep "^$ip}\s" | awk '{print $3}' | head -n 1)
    if [ -z "$mac" ]; then
        echo "[-] Failed to discover MAC for $ip. Retrying once..."
        sleep 1
        ping -c 2 "$ip" >/dev/null 2>&1
        mac=$(arp -n | grep "^$ip\s" | awk '{print $3}' | head -n 1)
        if [ -z "$mac" ]; then
            echo "[-] MAC discovery failed for $ip."
            return 1
        fi
    fi
    echo "[+] MAC for $ip: $mac"
    echo "$mac"
    return 0
}

# Function to set static ARP entry
set_static_arp() {
    local ip=$1
    local mac=$3
    echo "[*] Setting static ARP for $ip..."
    # Clear existing entry
    sudo arp -d "$ip" 2>/dev/null || true
    # Set static entry
    if sudo arp -s "$ip" "$mac" >/dev/null 2>&1; then
        echo "[+] Static ARP set: $ip -> $mac"
        return 0
    else
        echo "[-] Failed to set static ARP for $ip."
        return 1
    fi
}

# Function to verify protection
verify_protection() {
    local ip=$1
    local mac=$2
    echo "[*] Verifying protection for $ip..."
    # Check ARP table shows static entry
    arp_entry=$(arp -n | grep "^$ip\s" | awk '{print $3, $5}')
    if [[ "$arp_entry" =~ $mac.*static ]]; then
        echo "[+] Verified: Static ARP entry preserved for $ip"
        arp -a | grep "$ip"
        return 0
    else
        echo "[-] Verification failed: No static entry for $ip."
        return 1
    fi
}

# Main execution
main() {
    # Check root privileges
    if [ "$EUID" -ne 0 ]; then
        echo "[-] This script requires root privileges."
        echo "Run: sudo bash arp_defense.sh"
        exit 1
    fi
    # Check argument
    if [ -z "$1" ]; then
        echo "Usage: sudo bash arp_defense.sh [client|server]"
        echo "Example: sudo bash arp_defense.sh server  # Run on Client"
        exit 1
    fi
    role=$1
    # Set target IP based on role
    if [ "$role" = "client" ]; then
        target_ip=$CLIENT_IP
    elif [ "$role" = "server" ]; then
        target_ip=$SERVER_IP
    else
        echo "[-] Invalid role: Use 'client' or 'server'"
        exit 1
    fi
    # Execute defense
    if ! get_mac "$target_ip"; then
        echo "[-] Exiting due to MAC discovery failure."
        exit 1
    fi
    target_mac=$mac
    if ! set_static_arp "$target_ip" "$target_mac"; then
        echo "[-] Exiting due to static ARP failure."
        exit 1
    fi
    if ! verify_protection "$target_ip" "$target_mac"; then
        echo "[-] Exiting due to verification failure."
        exit 1
    fi
    echo ""
    echo "[+] Static ARP defense successfully completed!"
    echo "[+] Current ARP table:"
    arp -a
}

main "$@"