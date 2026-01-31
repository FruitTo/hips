from scapy.all import *
import time

TARGET_IP = "192.168.122.109"
TARGET_PORT = 80

print(f"Starting Scan Test against {TARGET_IP}...")

print(f"️Sending TCP NULL Scan (Flags=0)...")
pkt_null = IP(dst=TARGET_IP)/TCP(dport=TARGET_PORT, flags=0)
send(pkt_null, verbose=0)
time.sleep(1)

print(f"Sending TCP FULL XMAS Scan (Flags=63)...")
pkt_full = IP(dst=TARGET_IP)/TCP(dport=TARGET_PORT, flags=63)
send(pkt_full, verbose=0)
time.sleep(1)

print(f"Sending Standard Nmap Xmas Scan (Flags=41)...")
pkt_std_xmas = IP(dst=TARGET_IP)/TCP(dport=TARGET_PORT, flags=41)
send(pkt_std_xmas, verbose=0)

print("\nTest Completed! Check your C++ console output.")
