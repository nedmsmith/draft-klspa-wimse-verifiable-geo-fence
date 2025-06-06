#!/usr/bin/env python3
import sys
import struct
import json
import subprocess
import time
import os

# Define a log file location that is writable.
log_dir = os.environ.get("LOCALAPPDATA", os.getcwd())
log_file = os.path.join(log_dir, "win_app.log")

def log(message):
    """Logs a message with a timestamp to stderr and to a log file."""
    timestamp = time.strftime('%Y-%m-%d %H:%M:%S')
    log_entry = f"{timestamp} - {message}\n"
    sys.stderr.write(log_entry)
    sys.stderr.flush()
    try:
        with open(log_file, "a", encoding="utf-8") as f:
            f.write(log_entry)
    except Exception as e:
        sys.stderr.write(f"Error writing to log file: {e}\n")

def get_message():
    """
    Reads a native messaging host message from stdin using a 4-byte length prefix.
    Exits gracefully if an incomplete header or body is encountered.
    """
    raw_length = sys.stdin.buffer.read(4)
    if not raw_length:
        log("No message length read. Exiting.")
        sys.exit(0)
    if len(raw_length) < 4:
        log(f"Incomplete header received ({len(raw_length)} bytes). Exiting.")
        sys.exit(0)
    message_length = struct.unpack("I", raw_length)[0]

    message_bytes = sys.stdin.buffer.read(message_length)
    if len(message_bytes) < message_length:
        log(f"Incomplete message body read: expected {message_length} bytes, got {len(message_bytes)}. Exiting.")
        sys.exit(0)
    try:
        message = message_bytes.decode("utf-8")
    except Exception as e:
        log(f"Error decoding message: {e}. Exiting.")
        sys.exit(0)
    log(f"Received message: {message}")
    try:
        return json.loads(message)
    except Exception as e:
        log(f"Error parsing JSON message: {e}. Exiting.")
        sys.exit(0)

def send_message(message):
    """
    Sends a native messaging host message to stdout with a 4-byte length prefix.
    """
    encoded = json.dumps(message).encode("utf-8")
    sys.stdout.buffer.write(struct.pack("I", len(encoded)))
    sys.stdout.buffer.write(encoded)
    sys.stdout.buffer.flush()
    log(f"Sent message: {json.dumps(message)}")

def tpm_attest(payload):
    """
    Uses PowerShell to sign the given payload using a TPM-backed certificate.
    This version filters for a certificate whose subject contains "TPMTestCertificate"
    and then explicitly uses the RSACertificateExtensions method to retrieve the RSA key.
    
    Returns:
        The base64‑encoded signature if successful.
        Raises a RuntimeError if the attestation fails.
    """
    ps_command = f"""
        $ErrorActionPreference = "Stop";
        $cert = Get-ChildItem -Path Cert:\\CurrentUser\\My |
                 Where-Object {{ $_.Subject -like "*TPMTestCertificate*" }} |
                 Select-Object -First 1;
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
        $signatureBytes = $rsa.SignData($bytes,
                           [System.Security.Cryptography.HashAlgorithmName]::SHA256,
                           [System.Security.Cryptography.RSASignaturePadding]::Pkcs1);
        [System.Convert]::ToBase64String($signatureBytes)
    """
    # Normalize whitespace in the command.
    ps_command = " ".join(ps_command.split())
    log("Running PowerShell command for TPM attestation.")
    try:
        result = subprocess.run(
            ["powershell", "-NoProfile", "-Command", ps_command],
            capture_output=True,
            text=True,
            check=True
        )
        signature = result.stdout.strip()
        log(f"TPM Signature obtained: {signature}")
        return signature
    except Exception as e:
        log(f"TPM attestation failed: {e}")
        raise RuntimeError(f"TPM attestation failed: {e}")

def process_geolocation(lat, lon, accuracy, source):
    """
    Processes geolocation data by constructing a payload, signing it with TPM attestation,
    and returning a token with the signature.
    """
    log(f"Processing geolocation: lat={lat}, lon={lon}, accuracy={accuracy}, source={source}")
    payload = f"lat={lat},lon={lon},accuracy={accuracy},source={source}"
    log(f"Constructed payload: {payload}")
    signature = tpm_attest(payload)
    token = f"{payload}|sig={signature}"
    log(f"Constructed token: {token}")
    return {
        "lat": lat,
        "lon": lon,
        "accuracy": accuracy,
        "token": token
    }

def parse_payload(payload_string):
    """
    Parses a comma‑separated key=value string into a dictionary.
    Expected format: "lat=<value>,lon=<value>,accuracy=<value>,source=<value>"
    """
    data = {}
    for pair in payload_string.split(","):
        if "=" in pair:
            key, value = pair.split("=", 1)
            data[key.strip()] = value.strip()
    return data

def main():
    log("Native Messaging App started.")
    while True:
        try:
            message = get_message()
            # Check for the new JSON format with a "command" and "payload" field.
            if "command" in message and message["command"] == "attest":
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
                except Exception as e:
                    error_msg = f"Error parsing payload values: {e}"
                    log(error_msg)
                    send_message({"error": error_msg})
                    continue
                log("Valid geolocation parameters received from payload.")
                response = process_geolocation(lat, lon, accuracy, source)
                send_message(response)
            else:
                # Fallback: expect geolocation parameters directly in the message.
                lat = message.get("lat")
                lon = message.get("lon")
                accuracy = message.get("accuracy")
                source = message.get("source", "unknown")
                if lat is not None and lon is not None and accuracy is not None:
                    log("Valid geolocation parameters received directly.")
                    response = process_geolocation(lat, lon, accuracy, source)
                    send_message(response)
                else:
                    error_msg = "Missing geolocation parameters"
                    log(error_msg)
                    send_message({"error": error_msg})
        except Exception as e:
            error_msg = f"Error in main loop: {str(e)}"
            log(error_msg)
            send_message({"error": error_msg})
            break

if __name__ == "__main__":
    main()
