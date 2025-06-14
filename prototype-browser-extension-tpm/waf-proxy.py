from flask import Flask, request, Response, jsonify, send_from_directory
import requests
import logging
import math
import os
import base64
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.x509.base import load_pem_x509_certificate
from urllib.parse import unquote

app = Flask(__name__)
# Ensure all logs are visible in the console
logging.basicConfig(level=logging.INFO)

# Global variable for nonce checking.
current_nonce = None

# Upstream backend URL (must be TLS-enabled).
UPSTREAM_SERVER = "https://127.0.0.1:9443"

# -----------------------
# Utility Functions
# -----------------------

def load_tpm_cert():
    """Load the TPM certificate from 'tpm_cert.pem'."""
    try:
        with open("tpm_cert.pem", "rb") as f:
            pem_data = f.read()
        cert = x509.load_pem_x509_certificate(pem_data)
        return cert
    except Exception as e:
        app.logger.error(f"Error loading TPM certificate: {e}")
        return None

def verify_tpm_signature_with_cert(payload, signature_b64, cert):
    """Verify the TPM signature for the payload using the provided certificate."""
    try:
        signature = base64.b64decode(signature_b64)
    except Exception as e:
        app.logger.error(f"Error decoding signature: {e}")
        return False
    try:
        public_key = cert.public_key()
        public_key.verify(
            signature,
            payload.encode("utf-8"),
            padding.PKCS1v15(),
            hashes.SHA256()
        )
        return True
    except Exception as e:
        app.logger.error(f"Signature verification error: {e}")
        return False

def parse_nonce(geo_header):
    """
    Given an X-Custom-Geolocation header value, extract the 'nonce' field.
    Expected format is semicolon-separated key-value pairs:
      "lat=...;lon=...;accuracy=...;time=...;nonce=1;source=..."
    Returns the integer nonce if found; otherwise, None.
    """
    try:
        parts = geo_header.split(";")
        for part in parts:
            part = part.strip()
            if part.startswith("nonce="):
                return int(part.split("=", 1)[1])
    except Exception as e:
        app.logger.error(f"Error parsing nonce from header '{geo_header}': {e}")
    return None

def parse_geolocation_header(geo_header):
    """
    Parse the X-Custom-Geolocation header into a dictionary.
    For example, given:
      "lat=37.314843;lon=-122.052589;accuracy=212;time=2025-06-08T19:08:24.963Z;
       nonce=1;source=Cellular;sig=lat=37.314843,lon=-122.052589,accuracy=212.0,
       source=Cellular,time=2025-06-08T19:08:24.963Z,nonce=1|sig=BASE64_SIG"
    returns a dict with keys "lat", "lon", "accuracy", "time", "nonce", "source", and "sig".
    """
    fields = {}
    try:
        parts = geo_header.split(";")
        for part in parts:
            if "=" in part:
                k, v = part.split("=", 1)
                fields[k.strip()] = v.strip()
    except Exception as e:
        app.logger.error(f"Error parsing geolocation header: {e}")
    return fields

def parse_geolocation_header_multi(geo_header):
    """
    Parse the X-Custom-Geolocation header into a dictionary, supporting multiple fields with the same name.
    Returns a dict mapping field names to values (or lists of values if repeated).
    """
    from collections import defaultdict
    fields = defaultdict(list)
    try:
        parts = geo_header.split(";")
        for part in parts:
            if "=" in part:
                k, v = part.split("=", 1)
                fields[k.strip()].append(v.strip())
    except Exception as e:
        app.logger.error(f"Error parsing geolocation header (multi): {e}")
    # flatten singletons
    return {k: v[0] if len(v) == 1 else v for k, v in fields.items()}

def verify_certificate_chain_and_signature(token, cert_chain_b64=None):
    # Hardcoded certificate chain for dev/test (use real newlines, not \n)
    hardcoded_chain = b"""-----BEGIN CERTIFICATE-----
MIICzTCCAbWgAwIBAgIUCO+pSNMjARQXT+GiAhHCIr5UgnQwDQYJKoZIhvcNAQEL
BQAwHTEbMBkGA1UEAwwSVFBNVGVzdENlcnRpZmljYXRlMB4XDTI1MDYwOTA0NDMw
OFoXDTI2MDYwOTA0NDMwOFowJDEiMCAGA1UEAwwZR2VvTG9jYXRpb24gU2lnbmlu
ZyBLZXkgWDCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBALUvzUqd/yDr
MMpFofcmbZEhh8DVzh7UDxZUgu8d5UArdV0cGBFIrb2+w9yhVPY3MVATKy3BXL+Q
jCBohycShQqvBJ8YuSrxSqfav2X8JL/78udQImevaT7d8dxDVtKL4YEGKJhK0CwG
Vzeqk1xU13RDCXOGA6Q8IyxsexyEvEM8zbYRaTJjTRxcuatoTvi0aMlvRqbzhc6K
wo4faR+KXK/DfdHy77yZnR/yd+sSAVDQ9f5r3QZO8ulq3se4umtr0Zvtv307X6QM
YC9W+pVEM1NqkXbWXD+ei3zQFEdIoTT1lUS8ZxI6S7PxbMGv0n3/9HnWmcUufoLW
zboCO8B3658CAwEAATANBgkqhkiG9w0BAQsFAAOCAQEAcr0l60lgxlLJxzjm49Kd
o92BrPNlcbGtUIMpsSImBStl3tEEFV1zDDjpEZZIkznzNMxLpGwQDPOUb683DaAa
dQWZoYLPtECyJ4Ry55yYdugDwc9iJ42Bwf16FNnP9phhXxUqW4WZ4mptrNm2xg3u
sADUr8YpPxY7OfiTT+pQUCQ2wW7vMOQebQa/zf/u4uukddyNwrK726LBWUKanjew
GJaj3X2g12YXoY+HWh1A99AKS0BnmuoTjOtqKlOP76Yk9P80ulj000Tue2ZKT8E0
+aoHD7eLPVH6ihU1ntmfXuG7dt1K/KwT6URlAnSEFD6Gr/m91g939NdpZToi8QPl
Hw==
-----END CERTIFICATE-----
-----BEGIN CERTIFICATE-----
MIICxjCCAa6gAwIBAgIUASBt2l02uuaSczMdfJnu7thrnE0wDQYJKoZIhvcNAQEL
BQAwHTEbMBkGA1UEAwwSVFBNVGVzdENlcnRpZmljYXRlMB4XDTI1MDYwOTA0NDMw
OFoXDTI2MDYwOTA0NDMwOFowHTEbMBkGA1UEAwwSVFBNVGVzdENlcnRpZmljYXRl
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA0vm1nGQEbCEivhhM2L+Y
k0gOV48f/aMHmFs06Hg65yIig49VsZ8cpoPJHWMIkjAw5pBZ9OcywCWcwWmnQ8dJ
i8Ov8OzFZ/rN2XaZwd0Va74lerZjACE1TfZlOpDj6XWCis4ol0QgTXuXRnMaRJth
ViVaJej+ktffsaczm0j6kN0gh7Zgq7m8t6BhWhFPsDT6iSSrXOuL8seKTA4PN7WQ
SplKhqRPSzZCIG67ReS0a9Lv00tLKINSRs82Z6EGWV2ZPEWykIJ0Nx8S3hj9DP7m
02BiY54xawABwYJHNuSmWSdTTknCNwj6T8v3e3pFwnbkRgH9XXdeTe1snZfar4WF
VwIDAQABMA0GCSqGSIb3DQEBCwUAA4IBAQAU3oOHKUIla/yWxffV38XlPj4uACOw
DWcp5+USBz0JcPNrceLW1B/ywuWQzaBEHupQPSEJ4/jYDHL3lyDUujBw7BmDpXuK
DmRI4zME8XvT0WBeZUvkWNW62d6QIc3vwM7PpqY98SKeTT2kRMdXYbV0vWMjAzC3
HqG5bSQJnc/sqVTIOUBobB9zhZ2HQ+DPt6d4SHuZnrC3Z/B24hUXeafPKt4niRVd
JOFai3j6lNdYkmC8cS7/hkEHYzWGlTpXrrJT1tqo6gE+/pFDdtKVs1KshWXmMsbK
+Y0en8sRorqgZiAKTq/R+5XNSa1PFXoiw2PtjTdNTNmB9Ef6vikrjwzq
-----END CERTIFICATE-----
"""
    cert_chain_pem = hardcoded_chain
    # Split payload and signature
    if '|sig=' not in token:
        app.logger.error('[SIGFAIL] Invalid token format: missing |sig=')
        return False, 'Invalid token format'
    payload, sig_b64 = token.rsplit('|sig=', 1)
    try:
        signature = base64.b64decode(sig_b64)
    except Exception as e:
        app.logger.error(f'[SIGFAIL] Error decoding signature: {e}, sig_b64={sig_b64}')
        return False, f'Error decoding signature: {e}'
    # Split the chain into x_cert and tpm_cert
    certs = []
    for cert in cert_chain_pem.split(b'-----END CERTIFICATE-----'):
        if b'-----BEGIN CERTIFICATE-----' in cert:
            cert = cert + b'-----END CERTIFICATE-----\n'
            certs.append(x509.load_pem_x509_certificate(cert))
    if len(certs) != 2:
        app.logger.error(f'[SIGFAIL] Certificate chain must contain 2 certs (x and TPM), got {len(certs)}')
        return False, 'Certificate chain must contain 2 certs (x and TPM)'
    x_cert, tpm_cert = certs

    # Verify x_cert is signed by tpm_cert (issuer check and signature)
    if x_cert.issuer != tpm_cert.subject:
        app.logger.error(f'[SIGFAIL] x_cert issuer does not match tpm_cert subject')
        app.logger.error(f'[SIGFAIL] x_cert.pem (PEM):\n{x_cert.public_bytes(serialization.Encoding.PEM).decode()}')
        return False, 'x_cert not issued by TPM cert'
    try:
        tpm_cert.public_key().verify(
            x_cert.signature,
            x_cert.tbs_certificate_bytes,
            padding.PKCS1v15(),
            x_cert.signature_hash_algorithm,
        )
    except Exception as e:
        app.logger.error(f'[SIGFAIL] x_cert signature invalid: {e}')
        app.logger.error(f'[SIGFAIL] x_cert.pem (PEM):\n{x_cert.public_bytes(serialization.Encoding.PEM).decode()}')
        return False, f'x_cert signature invalid: {e}'

    # Verify signature on payload using x_cert
    try:
        x_cert.public_key().verify(
            signature,
            payload.encode('utf-8'),
            padding.PKCS1v15(),
            hashes.SHA256()
        )
    except Exception as e:
        app.logger.error(f'[SIGFAIL] Payload signature invalid: {e}')
        app.logger.error(f'[SIGFAIL] Payload: {payload}')
        app.logger.error(f'[SIGFAIL] Payload repr: {repr(payload)}')
        app.logger.error(f'[SIGFAIL] Signature (base64): {sig_b64}')
        app.logger.error(f'[SIGFAIL] Signature (hex): {signature.hex()}')
        return False, f'Payload signature invalid: {e}'
    return True, 'OK'

# -----------------------
# WAF Proxy Route
# -----------------------

@app.route('/', defaults={'path': ''}, methods=['GET', 'POST', 'PUT', 'DELETE', 'PATCH', 'OPTIONS'])
@app.route('/<path:path>', methods=['GET', 'POST', 'PUT', 'DELETE', 'PATCH', 'OPTIONS'])
def proxy(path):
    tethered_phone_name = None
    tethered_phone_mac = None
    # Special-case: handle /get_access_token_with_initial_nonce requests without WAF header processing.
    if path.lower() == "get_access_token_with_initial_nonce":
        app.logger.info("Processing /get_access_token_with_initial_nonce request without WAF header modifications.")
    else:
        original_geo_header = request.headers.get("X-Custom-Geolocation")
        if original_geo_header:
            # Log the received X-Custom-Geolocation header and all request headers at DEBUG level only
            app.logger.debug(f"Received X-Custom-Geolocation header: {original_geo_header}")
            app.logger.debug(f"[DEBUG] Full X-Custom-Geolocation header dump: {original_geo_header}")
            app.logger.debug(f"[DEBUG] All request headers: {dict(request.headers)}")
            parsed_fields = parse_geolocation_header_multi(original_geo_header)
            # New attestation format detection
            has_new = all(f in parsed_fields for f in ("payload", "sig", "cert_chain"))
            has_legacy = "sig" in parsed_fields and "payload" not in parsed_fields
            # Extract phone fields from mobile_phone_identity if present
            phone_identity = parsed_fields.get("mobile_phone_identity")
            if phone_identity:
                import json
                if isinstance(phone_identity, str):
                    try:
                        phone_identity = json.loads(phone_identity)
                    except Exception:
                        phone_identity = {}
                tethered_phone_name = phone_identity.get("name")
                tethered_phone_mac = phone_identity.get("tethered_phone_mac") or phone_identity.get("bluetooth_bd_addr")
                tethered_phone_match_type = phone_identity.get("tethered_phone_match_type")
            else:
                tethered_phone_name = parsed_fields.get("tethered_phone_name")
                tethered_phone_mac = parsed_fields.get("tethered_phone_mac")
                tethered_phone_match_type = parsed_fields.get("tethered_phone_match_type")
            if tethered_phone_match_type:
                app.logger.info(f"Tethered phone match type: {tethered_phone_match_type}")
            # Decode percent-encoding for human-readable logs and API
            if tethered_phone_name:
                tethered_phone_name = unquote(tethered_phone_name)
            if tethered_phone_mac:
                tethered_phone_mac = unquote(tethered_phone_mac)
                mac = tethered_phone_mac.replace('-', ':').replace('.', ':').replace(' ', ':')
                mac_hex = ''.join(c for c in mac if c.isalnum())
                if len(mac_hex) == 12:
                    tethered_phone_mac = ':'.join([mac_hex[i:i+2] for i in range(0, 12, 2)])
                else:
                    tethered_phone_mac = mac
            if tethered_phone_name or tethered_phone_mac:
                app.logger.info(f"Tethered phone info: name={tethered_phone_name}, mac={tethered_phone_mac}")
            # Remove nonce logging/validation entirely
            # Attestation validation
            if has_new:
                payload = parsed_fields["payload"]
                sig_b64 = parsed_fields["sig"]
                cert_chain_b64 = parsed_fields["cert_chain"]
                # Decode cert chain (base64 or PEM)
                try:
                    # Always decode from base64 (browser always sends base64)
                    cert_chain_pem = base64.b64decode(cert_chain_b64)
                    # Split PEMs
                    certs = []
                    for cert in cert_chain_pem.split(b'-----END CERTIFICATE-----'):
                        if b'-----BEGIN CERTIFICATE-----' in cert:
                            cert = cert + b'-----END CERTIFICATE-----\n'
                            certs.append(x509.load_pem_x509_certificate(cert))
                    if len(certs) != 2:
                        app.logger.error(f'[SIGFAIL] Certificate chain must contain 2 certs (x and TPM), got {len(certs)}')
                        valid = False
                        reason = 'Certificate chain must contain 2 certs (x and TPM)'
                    else:
                        x_cert, tpm_cert = certs
                        # Verify x_cert is signed by tpm_cert
                        if x_cert.issuer != tpm_cert.subject:
                            app.logger.error(f'[SIGFAIL] x_cert issuer does not match tpm_cert subject')
                            valid = False
                            reason = 'x_cert not issued by TPM cert'
                        else:
                            try:
                                tpm_cert.public_key().verify(
                                    x_cert.signature,
                                    x_cert.tbs_certificate_bytes,
                                    padding.PKCS1v15(),
                                    x_cert.signature_hash_algorithm,
                                )
                                # Percent-decode and pad sig before base64-decode
                                sig_b64_decoded = unquote(sig_b64)
                                # Add base64 padding if needed
                                missing_padding = len(sig_b64_decoded) % 4
                                if missing_padding:
                                    sig_b64_decoded += '=' * (4 - missing_padding)
                                sig_bytes = base64.b64decode(sig_b64_decoded)
                                # Verify signature on payload using x_cert
                                # Always percent-decode the payload before parsing
                                raw_payload = payload
                                payload = unquote(payload)
                                app.logger.debug(f"[PAYLOAD] Raw payload from header: {raw_payload}")
                                app.logger.debug(f"[PAYLOAD] Decoded payload for parsing: {payload}")
                                # Robust payload parsing for signature verification
                                payload_fields = {}
                                for part in payload.split(';'):
                                    if '=' in part:
                                        k, v = part.split('=', 1)
                                        payload_fields[k.strip()] = v.strip()
                                # Ensure all required fields are present
                                required_keys = ["lat", "lon", "accuracy", "source", "time", "nonce"]
                                if not all(k in payload_fields for k in required_keys):
                                    app.logger.error(f"[SIGFAIL] Payload missing required fields: {payload_fields}")
                                    valid = False
                                    reason = f"Payload missing required fields: {payload_fields}"
                                else:
                                    # Format accuracy as integer if possible to match client
                                    try:
                                        accuracy_float = float(payload_fields["accuracy"])
                                        accuracy_str = str(int(accuracy_float)) if accuracy_float == int(accuracy_float) else str(accuracy_float)
                                    except Exception:
                                        accuracy_str = payload_fields["accuracy"]
                                    payload_str = f"lat={payload_fields['lat']};lon={payload_fields['lon']};accuracy={accuracy_str};source={payload_fields['source']};time={payload_fields['time']};nonce={payload_fields['nonce']}"
                                    app.logger.debug(f"[PAYLOAD] Payload string used for verification: {payload_str}")
                                    x_cert.public_key().verify(
                                        sig_bytes,
                                        payload_str.encode('utf-8'),
                                        padding.PKCS1v15(),
                                        hashes.SHA256()
                                    )
                                    valid = True
                                    reason = 'OK'
                            except Exception as e:
                                app.logger.error(f'[SIGFAIL] Signature/cert validation error: {e}')
                                valid = False
                                reason = f'Signature/cert validation error: {e}'
                except Exception as e:
                    app.logger.error(f'[SIGFAIL] Error decoding/validating cert chain: {e}')
                    valid = False
                    reason = f'Error decoding/validating cert chain: {e}'
                if not valid:
                    app.logger.error(f"[SIGFAIL] Invalid signature/cert chain in X-Custom-Geolocation header: {reason}")
                else:
                    app.logger.info("Signature and certificate chain validated successfully (new format).")
            elif has_legacy:
                tpm_token = parsed_fields["sig"]
                if "|sig=" in tpm_token:
                    try:
                        valid, reason = verify_certificate_chain_and_signature(tpm_token)
                        if not valid:
                            app.logger.error(f"[SIGFAIL] Invalid signature/cert chain in X-Custom-Geolocation header: {reason}")
                        else:
                            app.logger.info("Signature and certificate chain validated successfully (legacy format).")
                    except Exception as ex:
                        app.logger.error(f"Error verifying signature/cert chain from header: {ex}")
                else:
                    app.logger.error("sig not in expected format (missing '|sig=' delimiter).")
        else:
            app.logger.info("No X-Custom-Geolocation header in request.")

    # Build upstream URL.
    upstream_url = f"{UPSTREAM_SERVER}/{path}"
    if request.query_string:
        upstream_url += "?" + request.query_string.decode("utf-8")
    
    # Copy incoming headers.
    headers = dict(request.headers)
    headers.pop("Host", None)
    # Forward attestation header in new format if present
    if "X-Custom-Geolocation" in headers and path.lower() != "get_access_token_with_initial_nonce":
        # Rebuild header to forward only one set of attestation fields, and append WAF marker
        parsed_fields = parse_geolocation_header_multi(headers["X-Custom-Geolocation"])
        has_new = all(f in parsed_fields for f in ("payload", "sig", "cert_chain"))
        has_legacy = "sig" in parsed_fields and "payload" not in parsed_fields
        header_parts = []
        for k in ["lat", "lon", "accuracy", "time", "nonce", "source", "tethered_phone_name", "tethered_phone_mac", "tethered_phone_match_type", "bluetooth_bd_addr", "bluetooth_pan_ip", "mobile_phone_identity", "mobile_phone_liveness_session"]:
            if k in parsed_fields:
                v = parsed_fields[k]
                if isinstance(v, list):
                    v = v[0]
                header_parts.append(f"{k}={v}")
        if has_new:
            for k in ["payload", "sig", "cert_chain"]:
                v = parsed_fields[k]
                if isinstance(v, list):
                    v = v[0]
                header_parts.append(f"{k}={v}")
        elif has_legacy:
            v = parsed_fields["sig"]
            if isinstance(v, list):
                v = v[0]
            header_parts.append(f"sig={v}")
        header_parts.append("waf=processed_by_proxy")
        headers["X-Custom-Geolocation"] = ";".join(header_parts)
        # Log the updated header at DEBUG level only
        app.logger.debug(f"Updated X-Custom-Geolocation header for forwarding: {headers['X-Custom-Geolocation']}")

    try:
        # Forward the request upstream.
        upstream_response = requests.request(
            method=request.method,
            url=upstream_url,
            headers=headers,
            data=request.get_data(),
            cookies=request.cookies,
            allow_redirects=False,
            verify=False  # For self-signed certificates.
        )
    except Exception as e:
        app.logger.error(f"Error connecting to upstream server: {e}")
        return jsonify({"error": "Upstream server error"}), 502

    # If this is an /get_access_token_with_initial_nonce request, update our internal nonce based on the response.
    if path.lower() == "get_access_token_with_initial_nonce":
        try:
            resp_json = None
            try:
                resp_json = upstream_response.json()
            except Exception as ex:
                app.logger.error(f"Error decoding JSON from /get_access_token_with_initial_nonce response: {ex}")
            if resp_json and "nonce" in resp_json:
                global current_nonce
                current_nonce = int(resp_json["nonce"])
                app.logger.info(f"Updated nonce from /get_access_token_with_initial_nonce response: {current_nonce}")
            else:
                app.logger.error("No nonce field in /get_access_token_with_initial_nonce response.")
        except Exception as ex:
            app.logger.error(f"Error parsing /get_access_token_with_initial_nonce response: {ex}")

    # Build the final response.
    response = Response(upstream_response.content, status=upstream_response.status_code)
    for key, value in upstream_response.headers.items():
        response.headers[key] = value
    # If the upstream response is JSON, add tethered phone info if present, but avoid duplicates
    try:
        if upstream_response.headers.get('Content-Type', '').startswith('application/json'):
            import json
            resp_json = upstream_response.json()
            if (tethered_phone_name or tethered_phone_mac) and isinstance(resp_json, dict):
                if tethered_phone_name and "tethered_phone_name" not in resp_json:
                    resp_json["tethered_phone_name"] = tethered_phone_name
                if tethered_phone_mac and "tethered_phone_mac" not in resp_json:
                    resp_json["tethered_phone_mac"] = tethered_phone_mac
                response.set_data(json.dumps(resp_json))
    except Exception as e:
        app.logger.error(f"Error injecting tethered phone info into response: {e}")
    return response

@app.route("/favicon.ico")
def favicon():
    return send_from_directory(os.path.join(app.root_path, "static"),
                               "favicon.ico",
                               mimetype="image/vnd.microsoft.icon")

@app.after_request
def add_divider(response):
    response.call_on_close(lambda: app.logger.info("\n----------------------------------------------------\n"))
    return response

if __name__ == "__main__":
    # Run the WAF proxy with TLS termination.
    ssl_context = ("cert.pem", "key.pem")
    app.run(host="0.0.0.0", port=8443, ssl_context=ssl_context)
