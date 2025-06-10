def is_tethered_phone_present(latitude=None, longitude=None):
    try:
        # First, check if phone is physically connected via Bluetooth
        with open(os.path.join(SCRIPT_DIR, "tethered_phone_info.json"), "r") as f:
            info = json.load(f)
        phone_name = info.get("name", "Unknown Phone")
        phone_mac_original = info.get("mac_address", "")
        phone_mac = phone_mac_original.replace(":", "").upper()
        
        # Use PowerShell to list paired/connected Bluetooth devices
        result = subprocess.run([
            'powershell',
            '-Command',
            'Get-PnpDevice -Class Bluetooth | Select-Object InstanceId'
        ], capture_output=True, text=True)
        
        phone_connected = False
        for line in result.stdout.splitlines():
            if phone_mac and phone_mac in line:
                phone_connected = True
                log(f"Found tethered phone: {phone_name} ({phone_mac_original})")
                break
          # If no physical connection, return False immediately
        if not phone_connected:
            log("Tethered phone not physically connected via Bluetooth")
            return False
            
        # If we have location data, verify it's within acceptable range
        # NOTE: Commented out until we can get the phone's actual GPS coordinates
        """
        if latitude is not None and longitude is not None:
            # You can customize these ranges based on your requirements
            # This is a simplified example that "trusts" the location range
            # In a real app, you might get the phone's GPS coordinates via an API
            acceptable_lat_range = (37.30, 37.33)  # Example range
            acceptable_lon_range = (-122.06, -122.04)  # Example range
            
            if (acceptable_lat_range[0] <= latitude <= acceptable_lat_range[1] and
                acceptable_lon_range[0] <= longitude <= acceptable_lon_range[1]):
                log(f"Phone location verified: ({latitude}, {longitude})")
                return True
            else:
                log(f"Phone outside acceptable location range: ({latitude}, {longitude})")
                return False
        """
        # Just log the location that was passed in, but don't verify it yet
        if latitude is not None and longitude is not None:
            log(f"Phone location received but not verified: ({latitude}, {longitude})")
          # If no location data provided, just return the Bluetooth connection status
        return phone_connected
    except Exception as e:
        log(f"Error checking tethered phone: {e}")
        return False

def get_phone_pan_ip(phone_mac):
    # Convert MAC to Windows ARP format (lowercase, dash-separated)
    mac = phone_mac.replace(":", "-").lower()
    try:
        result = subprocess.run(["arp", "-a"], capture_output=True, text=True)
        for line in result.stdout.splitlines():
            if mac in line:
                parts = line.split()
                if len(parts) >= 2:
                    return parts[0]  # IP address
    except Exception as e:
        log(f"Error finding phone PAN IP: {e}")
    return None

def keep_pan_alive_thread():
    while True:
        try:
            with open("tethered_phone_info.json", "r") as f:
                info = json.load(f)
            phone_mac = info.get("mac_address", "")
            if not phone_mac:
                time.sleep(60)
                continue
            pan_ip = get_phone_pan_ip(phone_mac)
            if pan_ip:
                # Send a single ping to the phone's PAN IP
                log(f"[KeepAlive] Pinging phone PAN IP: {pan_ip}")
                subprocess.run(["ping", "-n", "1", "-w", "1000", pan_ip], capture_output=True)
            else:
                log("[KeepAlive] Phone PAN IP not found in ARP table.")
        except Exception as e:
            log(f"[KeepAlive] Error in keep-alive thread: {e}")
        time.sleep(60)  # Wait 1 minute

# Start keep-alive thread at startup
threading.Thread(target=keep_pan_alive_thread, daemon=True).start()
