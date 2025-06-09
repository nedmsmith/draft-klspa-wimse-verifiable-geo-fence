#!/usr/bin/env python3
import sys
import struct
import json
import subprocess
import time
import os
# --- Key Hierarchy for Signing ---
import base64
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization, hashes
from cryptography import x509
from cryptography.x509.oid import NameOID
import datetime

# (We don’t really use cached_thumbprint since we filter by subject.)
cached_thumbprint = None

# Define a log file location that is writable.
log_dir = os.environ.get("LOCALAPPDATA", os.getcwd())
log_file = os.path.join(log_dir, "win_app.log")

# Always use the script's directory for key/cert files
SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
X_PRIV_KEY_PATH = os.path.join(SCRIPT_DIR, "x_private_key.pem")
X_CERT_PATH = os.path.join(SCRIPT_DIR, "x_cert.pem")
TPM_CERT_PATH = os.path.join(SCRIPT_DIR, "tpm_cert.pem")  # TPM certificate (public, PEM)
TPM_PRIV_KEY_PATH = os.path.join(SCRIPT_DIR, "tpm_private_key.pem")

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
    Split a semicolon-separated key=value string into a dictionary.
    Expected: "lat=...;lon=...;accuracy=...;source=...;time=...;nonce=..."
    """
    data = {}
    for pair in payload_string.split(";"):
        if "=" in pair:
            key, value = pair.split("=", 1)
            data[key.strip()] = value.strip()
    return data

# --- Key Hierarchy for Signing ---
# X_PRIV_KEY_PATH = os.path.join(log_dir, "x_private_key.pem")
# X_CERT_PATH = os.path.join(log_dir, "x_cert.pem")
# TPM_CERT_PATH = os.path.join(log_dir, "tpm_cert.pem")  # TPM certificate (public, PEM)

def generate_tpm_key_and_cert():
    """Generate TPM keypair and self-signed certificate if not exist."""
    if not os.path.exists(TPM_PRIV_KEY_PATH):
        tpm_private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
        )
        with open(TPM_PRIV_KEY_PATH, "wb") as f:
            f.write(tpm_private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.NoEncryption(),
            ))
    else:
        with open(TPM_PRIV_KEY_PATH, "rb") as f:
            tpm_private_key = serialization.load_pem_private_key(f.read(), password=None)

    if not os.path.exists(TPM_CERT_PATH):
        subject = issuer = x509.Name([
            x509.NameAttribute(NameOID.COMMON_NAME, u"TPMTestCertificate"),
        ])
        tpm_public_key = tpm_private_key.public_key()
        tpm_cert = x509.CertificateBuilder().subject_name(
            subject
        ).issuer_name(
            issuer
        ).public_key(
            tpm_public_key
        ).serial_number(
            x509.random_serial_number()
        ).not_valid_before(
            datetime.datetime.utcnow()
        ).not_valid_after(
            datetime.datetime.utcnow() + datetime.timedelta(days=365)
        ).sign(
            private_key=tpm_private_key,
            algorithm=hashes.SHA256(),
        )
        with open(TPM_CERT_PATH, "wb") as f:
            f.write(tpm_cert.public_bytes(serialization.Encoding.PEM))
    else:
        with open(TPM_CERT_PATH, "rb") as f:
            tpm_cert = x509.load_pem_x509_certificate(f.read())
    return tpm_private_key, tpm_cert

def generate_x_key_and_cert():
    # Generate TPM keypair and cert if needed
    tpm_private_key, tpm_cert = generate_tpm_key_and_cert()
    # Generate private key "x" if it doesn't exist
    if not os.path.exists(X_PRIV_KEY_PATH):
        x_private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
        )
        with open(X_PRIV_KEY_PATH, "wb") as f:
            f.write(x_private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.NoEncryption(),
            ))
    else:
        with open(X_PRIV_KEY_PATH, "rb") as f:
            x_private_key = serialization.load_pem_private_key(
                f.read(),
                password=None,
            )
    # Generate a certificate for "x" signed by the TPM private key
    if not os.path.exists(X_CERT_PATH):
        subject = x509.Name([
            x509.NameAttribute(NameOID.COMMON_NAME, u"GeoLocation Signing Key X"),
        ])
        issuer = tpm_cert.subject  # Issuer is TPM cert subject
        x_public_key = x_private_key.public_key()
        cert_builder = x509.CertificateBuilder().subject_name(
            subject
        ).issuer_name(
            issuer
        ).public_key(
            x_public_key
        ).serial_number(
            x509.random_serial_number()
        ).not_valid_before(
            datetime.datetime.utcnow()
        ).not_valid_after(
            datetime.datetime.utcnow() + datetime.timedelta(days=365)
        )
        # Sign with TPM private key
        x_cert = cert_builder.sign(
            private_key=tpm_private_key,
            algorithm=hashes.SHA256(),
        )
        with open(X_CERT_PATH, "wb") as f:
            f.write(x_cert.public_bytes(serialization.Encoding.PEM))
    # Return loaded keys and certs
    with open(X_PRIV_KEY_PATH, "rb") as f:
        x_private_key = serialization.load_pem_private_key(f.read(), password=None)
    with open(X_CERT_PATH, "rb") as f:
        x_cert = x509.load_pem_x509_certificate(f.read())
    with open(TPM_CERT_PATH, "rb") as f:
        tpm_cert = x509.load_pem_x509_certificate(f.read())
    return x_private_key, x_cert, tpm_cert

# Initialize key hierarchy at startup
try:
    x_private_key, x_cert, tpm_cert = generate_x_key_and_cert()
    # Check that x_private_key matches x_cert
    if x_private_key and x_cert:
        priv_pub = x_private_key.public_key().public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
        cert_pub = x_cert.public_key().public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
        if priv_pub != cert_pub:
            log("[ERROR] x_private_key.pem and x_cert.pem do NOT match! Delete both files and restart to regenerate.")
        else:
            log("[INFO] x_private_key.pem and x_cert.pem match.")
except Exception as e:
    log(f"Key hierarchy initialization failed: {e}")
    x_private_key = x_cert = tpm_cert = None

def sign_with_x(payload_bytes):
    if not x_private_key:
        raise RuntimeError("Private key x not initialized")
    signature = x_private_key.sign(
        payload_bytes,
        padding.PKCS1v15(),
        hashes.SHA256()
    )
    return signature

def get_certificate_chain_pem():
    if not x_cert or not tpm_cert:
        return b""
    return x_cert.public_bytes(serialization.Encoding.PEM) + tpm_cert.public_bytes(serialization.Encoding.PEM)

def process_geolocation(lat, lon, accuracy, source, timestamp, nonce):
    """
    Build a payload including time and nonce, sign it, and return the token.
    """
    log(f"Processing: lat={lat}, lon={lon}, accuracy={accuracy}, source={source}, time={timestamp}, nonce={nonce}")
    # Format floats to 6 decimal places for consistency
    lat_str = f"{float(lat):.6f}"
    lon_str = f"{float(lon):.6f}"
    accuracy_str = f"{float(accuracy):.6f}"
    payload = f"lat={lat_str},lon={lon_str},accuracy={accuracy_str},source={source},time={timestamp},nonce={nonce}"
    log(f"Constructed payload: {payload}")
    log(f"Payload repr: {repr(payload)}")
    try:
        signature = sign_with_x(payload.encode("utf-8"))
        signature_b64 = base64.b64encode(signature).decode()
        log(f"Signature (base64): {signature_b64}")
        log(f"x_cert.pem (PEM):\n{x_cert.public_bytes(serialization.Encoding.PEM).decode()}")
        cert_chain_b64 = base64.b64encode(get_certificate_chain_pem()).decode()
        token = f"{payload}|sig={signature_b64}"
        log(f"Constructed token: {token}")
        return {
            "lat": lat,
            "lon": lon,
            "accuracy": accuracy,
            "token": token,
            "certificate_chain": cert_chain_b64
        }
    except Exception as e:
        log(f"Signing with key x failed: {e}")
        return {"error": f"Signing failed: {e}"}

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
