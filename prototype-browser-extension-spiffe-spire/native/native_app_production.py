#!/usr/bin/env python
import sys
import struct
import json
import subprocess
import reverse_geocoder as rg  # pip install reverse_geocoder

def get_message():
    """
    Reads a native messaging host message from stdin.
    Each message is prefixed with a 4-byte message length.
    """
    raw_length = sys.stdin.buffer.read(4)
    if not raw_length:
        sys.exit(0)
    message_length = struct.unpack("I", raw_length)[0]
    message = sys.stdin.buffer.read(message_length).decode("utf-8")
    return json.loads(message)

def send_message(message):
    """
    Sends a native messaging host message to stdout,
    prefixing it with a 4-byte length.
    """
    encoded_content = json.dumps(message).encode("utf-8")
    sys.stdout.buffer.write(struct.pack("I", len(encoded_content)))
    sys.stdout.buffer.write(encoded_content)
    sys.stdout.buffer.flush()

def spire_tpm_sign(payload):
    """
    Delegates TPM-based signing of 'payload' to the local SPIRE agent via a dedicated tool.

    Production environments should provide a signing tool (e.g. 'spire-tpm-sign')
    that interacts with the SPIRE agent configured with the TPM plugin.
    The tool must accept the payload (for instance via a command-line parameter)
    and return the signature as its stdout.

    Adjust the command and parameters as needed for your deployment.
    """
    try:
        # Example: The tool is invoked with --payload and returns the signature.
        result = subprocess.run(
            ["spire-tpm-sign", "--payload", payload],
            capture_output=True, text=True, check=True
        )
        signature = result.stdout.strip()
        if not signature:
            raise ValueError("Received empty signature")
        return signature
    except Exception as e:
        raise RuntimeError(f"SPIRE TPM signing failed: {e}")

def process_geolocation(lat, lon, accuracy):
    """
    Given geolocation values, reverse-geocode to get a geographic region,
    create a payload string, and then sign it via the SPIRE TPM attestation flow.
    """
    # Reverse-geocode: obtain country code (or region) from the coordinates.
    results = rg.search((lat, lon))
    region = results[0].get("cc", "unknown")

    # Build the payload string.
    payload = f"lat={lat},lon={lon},accuracy={accuracy},region={region}"
    
    # Delegate payload signing to the local TPM attestation (SPIRE agent).
    signature = spire_tpm_sign(payload)
    
    # Construct a token that includes the payload and signature.
    token = f"{payload}|sig={signature}"
    return {
        "lat": lat,
        "lon": lon,
        "accuracy": accuracy,
        "region": region,
        "signature": signature,
        "token": token
    }

def main():
    while True:
        try:
            message = get_message()  # Expecting keys: lat, lon, accuracy
            lat = message.get("lat")
            lon = message.get("lon")
            accuracy = message.get("accuracy")
            if lat is not None and lon is not None and accuracy is not None:
                response = process_geolocation(lat, lon, accuracy)
                send_message(response)
            else:
                send_message({"error": "Missing geolocation parameters"})
        except Exception as e:
            send_message({"error": str(e)})

if __name__ == "__main__":
    main()
