import subprocess
import re
import json
import argparse

parser = argparse.ArgumentParser()
parser.add_argument('--debug', action='store_true', help='Print debug information')
args = parser.parse_args()

if args.debug:
    print("Finding Bluetooth-tethered mobile phone (name, MAC/BD_ADDR, PAN IP if available)...\n")

# 1. List paired/connected Bluetooth devices (Name, Status, InstanceId)
if args.debug:
    print("[1] Paired/Connected Bluetooth Devices:")
result = subprocess.run([
    'powershell',
    '-Command',
    'Get-PnpDevice -Class Bluetooth | Select-Object Name,Status,InstanceId | ConvertTo-Json'
], capture_output=True, text=True)
if args.debug:
    print(result.stdout)

devices = []
try:
    devices = json.loads(result.stdout)
    if isinstance(devices, dict):
        devices = [devices]
except Exception:
    devices = []

# 2. List Bluetooth network adapters
if args.debug:
    print("[2] Bluetooth Network Adapters:")
result = subprocess.run([
    'powershell',
    '-Command',
    'Get-NetAdapter | Where-Object { $_.InterfaceDescription -like "*Bluetooth*" }'
], capture_output=True, text=True)
if args.debug:
    print(result.stdout)

# 3. Show PAN IP using robust PowerShell method
if args.debug:
    print("[3] Bluetooth PAN IP (if any):")
ps_cmd = (
    "$pan = Get-NetAdapter | "
    "Where-Object { $_.InterfaceDescription -match 'Personal Area Network' -and $_.Status -eq 'Up' } | "
    "Select-Object -First 1; "
    "if ($pan) { Get-NetIPAddress -InterfaceIndex $pan.IfIndex -AddressFamily IPv4 -ErrorAction SilentlyContinue | "
    "Select-Object -First 1 -ExpandProperty IPAddress }"
)
result = subprocess.run([
    'powershell',
    '-Command',
    ps_cmd
], capture_output=True, text=True)
pan_ip = result.stdout.strip()
if args.debug:
    if pan_ip:
        print(f"  PAN IP: {pan_ip}")
    else:
        print("  No active Bluetooth PAN IP found.")

# 4. Print summary table of Bluetooth devices with MAC (BD_ADDR) and PAN IP
if args.debug:
    print("\n[4] Summary Table (Name, BD_ADDR, PAN IP if available):")
mac_pattern = re.compile(r'(?:DEV_|&|_)([0-9A-F]{12})(?:_|$)', re.IGNORECASE)
if args.debug:
    for dev in devices:
        name = dev.get('Name', '')
        status = dev.get('Status', '')
        instanceid = dev.get('InstanceId', '')
        mac = None
        m = mac_pattern.search(instanceid)
        if m:
            mac = m.group(1)
            mac_str = ':'.join(mac[i:i+2] for i in range(0,12,2))
        else:
            mac_str = "(not found)"
        print(f"  Name: {name:30} | Status: {status:8} | BD_ADDR: {mac_str} | PAN IP: {pan_ip if pan_ip else '-'}")
    print("\nTip: The phone's Bluetooth MAC (BD_ADDR) is unique and stable. PAN IP is only present if Bluetooth tethering is active.")

# 5. Suggest tethered_phone_info.json entry for likely mobile phones WITH PAN IP (filter to real phones only and match PAN IP MAC)
phone_keywords = ["iphone", "android", "phone"]
exclude_keywords = ["mouse", "hid", "service", "profile", "driver", "enumerator"]
# Get the MAC address of the active PAN IP adapter (from [2] Bluetooth Network Adapters)
pan_mac = None
result = subprocess.run([
    'powershell',
    '-Command',
    'Get-NetAdapter | Where-Object { $_.InterfaceDescription -match "Personal Area Network" -and $_.Status -eq "Up" } | Select-Object -First 1 -ExpandProperty MacAddress'
], capture_output=True, text=True)
pan_mac_raw = result.stdout.strip()
if pan_mac_raw:
    pan_mac = pan_mac_raw.replace('-', ':').upper()

# Get ARP table to check for liveness (phone MAC seen as gateway for PAN IP subnet)
arp_mac = None
if pan_ip:
    arp_result = subprocess.run(['arp', '-a'], capture_output=True, text=True)
    arp_lines = arp_result.stdout.splitlines()
    pan_subnet = '.'.join(pan_ip.split('.')[:3]) + '.'
    for line in arp_lines:
        if pan_subnet in line:
            parts = line.split()
            if len(parts) >= 2:
                ip, mac = parts[0], parts[1]
                # Only consider ARP entries for the PAN subnet, and skip incomplete entries
                if ip.startswith(pan_subnet) and mac != 'ff-ff-ff-ff-ff-ff' and mac != '00-00-00-00-00-00':
                    arp_mac = mac.replace('-', ':').upper()
                    break

likely_phones = []
liveness_confirmed = None
for dev in devices:
    name = dev.get('Name', '').strip()
    if dev.get('Status', '').upper() != 'OK':
        continue
    if not name:
        continue
    if not any(k in name.lower() for k in phone_keywords):
        continue
    if any(x in name.lower() for x in exclude_keywords):
        continue
    m = mac_pattern.search(dev.get('InstanceId', ''))
    if not m:
        continue
    mac = m.group(1)
    mac_str = ':'.join(mac[i:i+2] for i in range(0,12,2)).upper()
    likely_phones.append((name, mac_str))
    # Check liveness: does this MAC match the ARP MAC?
    if arp_mac and (mac_str.replace(':', '').upper()[-10:] == arp_mac.replace(':', '').upper()[-10:] or mac_str.replace(':', '').upper() == arp_mac.replace(':', '').upper()):
        liveness_confirmed = (name, mac_str)

if pan_ip and likely_phones:
    if liveness_confirmed:
        print(json.dumps({"name": liveness_confirmed[0], "mac_address": liveness_confirmed[1], "liveness_confirmed": True, "note": "Copy this entry to tethered_phone_info.json."}, indent=2))
    else:
        print(json.dumps({
            "likely_phones": [
                {"name": n, "mac_address": m} for n, m in likely_phones
            ],
            "liveness_confirmed": False,
            "note": "Liveness could not be confirmed via ARP; this is a Windows limitation. On your iPhone, go to Settings > General > About > Bluetooth to find your Bluetooth MAC address. Choose the matching entry from the list above and copy it to tethered_phone_info.json."
        }, indent=2))
else:
    print("No likely mobile phone with Status=OK, valid MAC, and active PAN IP found. Please check your Bluetooth tethering connection.")
