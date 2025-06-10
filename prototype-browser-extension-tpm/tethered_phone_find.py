import subprocess
import re

print("Finding Bluetooth-tethered mobile phone (name, MAC, IP if available)...\n")

# 1. List paired/connected Bluetooth devices (shows MAC in InstanceId)
print("[1] Paired/Connected Bluetooth Devices:")
result = subprocess.run(['powershell', '-Command', 'Get-PnpDevice -Class Bluetooth | Select-Object Name,Status,InstanceId'], capture_output=True, text=True)
print(result.stdout)

# 2. List Bluetooth network adapters
print("[2] Bluetooth Network Adapters:")
result = subprocess.run(['powershell', '-Command', 'Get-NetAdapter | Where-Object {$_.InterfaceDescription -like "*Bluetooth*"}'], capture_output=True, text=True)
print(result.stdout)

# 3. List ARP table to find IP/MAC of devices on the PAN
print("[3] ARP Table (for PAN IP/MAC):")
result = subprocess.run(['arp', '-a'], capture_output=True, text=True)
print(result.stdout)

# 4. Try to extract likely phone MAC addresses from InstanceId
print("[4] Likely Phone Bluetooth MACs:")
pattern = re.compile(r'DEV_([0-9A-F]{12})', re.IGNORECASE)
for line in result.stdout.splitlines():
    match = pattern.search(line)
    if match:
        mac = match.group(1)
        mac_str = ':'.join(mac[i:i+2] for i in range(0,12,2))
        print(f"  Found MAC: {mac_str}")

print("\nTip: The phone's Bluetooth MAC is usually visible in [1] (InstanceId as DEV_xxx), and its IP/MAC on the PAN in [3].")
