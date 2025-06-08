#!/usr/bin/env python3
import sys
import struct
import json
import subprocess
import time
import os

# (We don’t really use cached_thumbprint since we filter by subject.)
cached_thumbprint = None

# Define a log file location that is writable.
log_dir = os.environ.get("LOCALAPPDATA", os.getcwd())
log_file = os.path.join(log_dir, "win_app.log")

def log(message):
    """Log with timestamp."""
    timestamp = time.strftime("%Y-%m-%d %H:%M:%S")
    log_entry = f"{timestamp} - {message}\n"
    sys.stderr.write(log_entry)
    sys.stderr.flush()
    try:
        with open(log_file, "a", encoding="utf-8") as f:
            f.write(log_entry)
    except Exception as e:
        sys.stderr.write(f"Error writing to log file: {e}\n")

def get_message():
    """Read a native messaging host message from stdin using a 4-byte length prefix."""
    while True:
        raw_length = sys.stdin.buffer.read(4)
        if not raw_length:
            log("No message length read. Waiting for new input...")
            time.sleep(1)
            continue
        if len(raw_length) < 4:
            log(f"Incomplete header received ({len(raw_length)} bytes). Waiting...")
            time.sleep(1)
            continue
        message_length = struct.unpack("I", raw_length)[0]
        message_bytes = b""
        while len(message_bytes) < message_length:
            chunk = sys.stdin.buffer.read(message_length - len(message_bytes))
            if not chunk:
                log(f"Waiting for full message body: received {len(message_bytes)} of {message_length} bytes...")
                time.sleep(1)
                continue
            message_bytes += chunk
        try:
            message = message_bytes.decode("utf-8")
        except Exception as e:
            log(f"Error decoding message: {e}. Waiting...")
            continue
        log(f"Received message: {message}")
        try:
            return json.loads(message)
        except Exception as e:
            log(f"Error parsing JSON message: {e}. Waiting...")
            continue

def send_message(message):
    """Send a native messaging host message with a 4-byte length prefix."""
    encoded = json.dumps(message).encode("utf-8")
    sys.stdout.buffer.write(struct.pack("I", len(encoded)))
    sys.stdout.buffer.write(encoded)
    sys.stdout.buffer.flush()
    log(f"Sent message: {json.dumps(message)}")

def tpm_attest(payload):
    """
    Sign the payload with the TPM certificate.
    This uses the older snippet filtering by subject and calling
    RSACertificateExtensions.GetRSAPrivateKey.
    """
    ps_command = f"""
        $ErrorActionPreference = "Stop";
        $cert = Get-ChildItem -Path Cert:\\CurrentUser\\My | Where-Object {{ $_.Subject -like "*TPMTestCertificate*" }} | Select-Object -First 1;
        if ($cert -eq $null) {{
             Write-Error "No TPM-backed certificate found.";
             exit 1;
        }}
        $bytes = [System.Text.Encoding]::UTF8.GetBytes("{payload}");
        $rsa = [System.Security.Cryptography.X509Certificates.RSACertificateExtensions]::GetRSAPrivateKey($cert);
        if ($rsa -eq $null) {{
             Write-Error "RSA private key not found.";
             exit 1;
        }}
        $signatureBytes = $rsa.SignData($bytes, [System.Security.Cryptography.HashAlgorithmName]::SHA256, [System.Security.Cryptography.RSASignaturePadding]::Pkcs1);
        [System.Convert]::ToBase64String($signatureBytes)
    """
    ps_command = " ".join(ps_command.split())
    log("Running PowerShell for TPM attestation:")
    log(ps_command)
    try:
        result = subprocess.run(
            ["powershell", "-NoProfile", "-Command", ps_command],
            capture_output=True,
            text=True,
            timeout=10,  # Adjust timeout here if needed.
            check=True
        )
        signature = result.stdout.strip()
        log(f"TPM Signature obtained: {signature}")
        return signature
    except subprocess.CalledProcessError as cpe:
        log(f"TPM attestation failed. Return code: {cpe.returncode}. Stdout: {cpe.stdout}. Stderr: {cpe.stderr}")
        raise RuntimeError(f"TPM attestation failed: {cpe.stderr.strip()}")
    except Exception as e:
        log(f"TPM attestation failed: {e}")
        raise RuntimeError(f"TPM attestation failed: {e}")

def parse_payload(payload_string):
    """
    Split a comma-separated key=value string into a dictionary.
    Expected: "lat=...,lon=...,accuracy=...,source=...,time=...,nonce=..."
    """
    data = {}
    for pair in payload_string.split(","):
        if "=" in pair:
            key, value = pair.split("=", 1)
            data[key.strip()] = value.strip()
    return data

def process_geolocation(lat, lon, accuracy, source, timestamp, nonce):
    """
    Build a payload including time and nonce, sign it, and return the token.
    """
    log(f"Processing: lat={lat}, lon={lon}, accuracy={accuracy}, source={source}, time={timestamp}, nonce={nonce}")
    payload = f"lat={lat},lon={lon},accuracy={accuracy},source={source},time={timestamp},nonce={nonce}"
    log(f"Constructed payload: {payload}")
    signature = tpm_attest(payload)
    token = f"{payload}|sig={signature}"
    log(f"Constructed token: {token}")
    return {"lat": lat, "lon": lon, "accuracy": accuracy, "token": token}

def main():
    log("Native Messaging App started (long-lived).")
    # Optionally cache certificate here.
    while True:
        try:
            message = get_message()
            if message.get("command") == "attest":
                payload_str = message.get("payload")
                if not payload_str:
                    error_msg = "Missing payload in message."
                    log(error_msg)
                    send_message({"error": error_msg})
                    continue
                parsed = parse_payload(payload_str)
                try:
                    lat = float(parsed.get("lat"))
                    lon = float(parsed.get("lon"))
                    accuracy = float(parsed.get("accuracy"))
                    source = parsed.get("source", "unknown")
                    timestamp = parsed.get("time", "")
                    nonce_value = parsed.get("nonce", "")
                except Exception as e:
                    error_msg = f"Error parsing payload values: {e}"
                    log(error_msg)
                    send_message({"error": error_msg})
                    continue
                log("Valid geolocation parameters received from payload.")
                response = process_geolocation(lat, lon, accuracy, source, timestamp, nonce_value)
                send_message(response)
            else:
                # Fallback: if not an attest command.
                if "lat" in message and "lon" in message and "accuracy" in message:
                    lat = message.get("lat")
                    lon = message.get("lon")
                    accuracy = message.get("accuracy")
                    source = message.get("source", "unknown")
                    timestamp = message.get("time", "")
                    nonce_value = message.get("nonce", "")
                    log("Valid geolocation parameters received directly.")
                    response = process_geolocation(lat, lon, accuracy, source, timestamp, nonce_value)
                    send_message(response)
                else:
                    error_msg = "Missing geolocation parameters."
                    log(error_msg)
                    send_message({"error": error_msg})
        except Exception as e:
            error_msg = f"Error in main loop: {str(e)}"
            log(error_msg)
            send_message({"error": error_msg})
            time.sleep(1)

if __name__ == "__main__":
    main()
