#!/usr/bin/env python3
import sys
import json
import struct
import logging
import subprocess
import time
import os
import re
# --- Key Hierarchy for Signing ---
import base64
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization, hashes
from cryptography import x509
from cryptography.x509.oid import NameOID
import datetime
import threading

# Set up more detailed logging
logging.basicConfig(
    filename='win-app.log',
    level=logging.DEBUG,
    format='%(asctime)s - %(levelname)s: %(message)s'
)

# (We don’t really use cached_thumbprint since we filter by subject.)
cached_thumbprint = None

# Always use the script's directory for key/cert files and logs
SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
log_file = os.path.join(SCRIPT_DIR, "win-app.log")
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
    """Read a native messaging host message from stdin using a 4-byte length prefix. Never exit on EOF; always wait for new input."""
    log("[DEBUG] get_message() called, waiting for message from stdin...")
    while True:
        try:
            raw_length = sys.stdin.buffer.read(4)
            if not raw_length or len(raw_length) < 4:
                log("No message length read or incomplete header. Waiting for new input...")
                time.sleep(0.5)
                continue
            message_length = struct.unpack("I", raw_length)[0]
            message_bytes = b""
            while len(message_bytes) < message_length:
                chunk = sys.stdin.buffer.read(message_length - len(message_bytes))
                if not chunk:
                    log(f"Waiting for full message body: received {len(message_bytes)} of {message_length} bytes...")
                    time.sleep(0.5)
                    continue
                message_bytes += chunk
            try:
                message = message_bytes.decode("utf-8")
            except Exception as e:
                log(f"Error decoding message: {e}. Waiting...")
                continue
            log(f"[DEBUG] Raw message bytes received: {message_bytes!r}")
            log(f"Received message: {message}")
            try:
                parsed = json.loads(message)
                log(f"[DEBUG] Parsed JSON message: {parsed}")
                return parsed
            except Exception as e:
                log(f"Error parsing JSON message: {e}. Waiting...")
                continue
        except Exception as e:
            log(f"Exception in get_message: {e}. Waiting...")
            time.sleep(0.5)
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

# --- Tethered Phone Liveness Detection (PowerShell-based) ---
TETHERED_PHONE_LIVENESS_POLL_INTERVAL = 30  # seconds, change as needed
_tethered_phone_liveness = {
    "present": False,
    "name": None,
    "bluetooth_bd_addr": None,
    "bluetooth_pan_ip": None
}
_tethered_phone_liveness_lock = threading.Lock()

TETHERED_PHONE_CHECK_SCRIPT = os.path.join(SCRIPT_DIR, "tethered_phone_check.ps1")
TETHERED_PHONE_INFO_FILE = os.path.join(SCRIPT_DIR, "tethered_phone_info.json")


def phone_liveness_worker():
    while True:
        try:
            # Run the PowerShell script
            result = subprocess.run([
                "powershell.exe", "-NoProfile", "-ExecutionPolicy", "Bypass", "-File", TETHERED_PHONE_CHECK_SCRIPT,
                "-InfoFile", TETHERED_PHONE_INFO_FILE
            ], capture_output=True, text=True, timeout=30)
            exit_code = result.returncode
            # Load phone info from JSON for name/MAC
            try:
                with open(TETHERED_PHONE_INFO_FILE, "r", encoding="utf-8") as f:
                    phone_info = json.load(f)
                phone_name = phone_info.get("name")
                phone_mac = phone_info.get("mac_address")
            except Exception as e:
                phone_name = None
                phone_mac = None
                log(f"[Liveness] Error loading phone info JSON: {e}")
            # Update liveness cache based on exit code
            with _tethered_phone_liveness_lock:
                if exit_code == 0:
                    _tethered_phone_liveness["present"] = True
                    _tethered_phone_liveness["name"] = phone_name
                    _tethered_phone_liveness["bluetooth_bd_addr"] = phone_mac
                    # PAN IP not available from script, leave as None
                    _tethered_phone_liveness["bluetooth_pan_ip"] = None
                    log(f"[Liveness] Phone present: {phone_name} [{phone_mac}]")
                else:
                    _tethered_phone_liveness["present"] = False
                    _tethered_phone_liveness["name"] = None
                    _tethered_phone_liveness["bluetooth_bd_addr"] = None
                    _tethered_phone_liveness["bluetooth_pan_ip"] = None
                    log(f"[Liveness] Phone not present (exit code {exit_code})")
        except Exception as e:
            log(f"[Liveness] Exception in liveness worker: {e}")
            with _tethered_phone_liveness_lock:
                _tethered_phone_liveness["present"] = False
                _tethered_phone_liveness["name"] = None
                _tethered_phone_liveness["bluetooth_bd_addr"] = None
                _tethered_phone_liveness["bluetooth_pan_ip"] = None
        # Wait before next check
        time.sleep(TETHERED_PHONE_LIVENESS_POLL_INTERVAL)

# --- TOP-LEVEL DEBUG LOGGING FOR NATIVE MESSAGING HOST STARTUP/EXIT ---
try:
    log('[NATIVE HOST] win-app.py starting up (PID: %s)' % os.getpid())

    # Place the main loop in a try/except/finally to log all exits
    def main():
        log('[NATIVE HOST] Entering main() loop')
        # Start the phone liveness worker thread
        threading.Thread(target=phone_liveness_worker, daemon=True).start()
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

        # Main message loop
        while True:
            try:
                message = get_message()
                log(f"[NATIVE HOST] Received message: {message}")
                request_id = message.get("requestId")
                command = message.get("command")
                if command == "attest":
                    payload = message.get("payload", "")
                    # Parse payload for lat/lon/accuracy/source/time/nonce
                    payload_dict = parse_payload(payload)
                    # Check phone liveness (read from cache)
                    with _tethered_phone_liveness_lock:
                        phone_present = _tethered_phone_liveness.get("present", False)
                        phone_name = _tethered_phone_liveness.get("name")
                        bluetooth_bd_addr = _tethered_phone_liveness.get("bluetooth_bd_addr")
                        bluetooth_pan_ip = _tethered_phone_liveness.get("bluetooth_pan_ip")
                    # TPM sign the payload (using x key)
                    try:
                        signature = base64.b64encode(sign_with_x(payload.encode("utf-8"))).decode("ascii")
                        cert_chain_pem = get_certificate_chain_pem().decode("utf-8")
                        cert_chain_b64 = base64.b64encode(get_certificate_chain_pem()).decode("ascii")
                    except Exception as e:
                        log(f"[NATIVE HOST] TPM signing error: {e}")
                        send_message({"error": f"TPM signing error: {e}", "requestId": request_id})
                        continue
                    # Compose response with separate fields
                    response = {
                        "requestId": request_id,
                        "payload": payload,
                        "sig": signature,
                        "cert_chain": cert_chain_b64,
                        # For browser header compatibility
                        "tethered_phone_name": phone_name if phone_present else None,
                        "tethered_phone_mac": bluetooth_bd_addr if phone_present else None,
                        "bluetooth_bd_addr": bluetooth_bd_addr if phone_present else None,
                        "bluetooth_pan_ip": bluetooth_pan_ip if phone_present else None,
                        "mobile_phone_identity": {
                            "name": phone_name if phone_present else None,
                            "bluetooth_bd_addr": bluetooth_bd_addr if phone_present else None
                        },
                        "mobile_phone_liveness_session": {
                            "bluetooth_pan_ip": bluetooth_pan_ip if phone_present else None
                        }
                    }
                    send_message(response)
                else:
                    send_message({"error": f"Unknown command: {command}", "requestId": request_id})
            except Exception as e:
                log(f'[NATIVE HOST] Exception in main loop: {e}')
                time.sleep(1)

    if __name__ == '__main__':
        try:
            main()
        except Exception as e:
            log(f'[NATIVE HOST] Uncaught exception at top level: {e}')
        finally:
            log('[NATIVE HOST] win-app.py exiting (PID: %s)' % os.getpid())
except Exception as e:
    log(f'[NATIVE HOST] Exception during startup: {e}')
