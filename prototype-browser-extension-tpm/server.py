from flask import Flask, request, jsonify, send_from_directory, make_response
import os
import base64
import reverse_geocode
import math
import logging
import random
import traceback
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.x509.base import load_pem_x509_certificate
from urllib.parse import unquote

# Ensure all logs are visible in the console
logging.basicConfig(level=logging.INFO)

app = Flask(__name__)

# ----- Global In-Memory Nonce Store -----

# LCG implementation for deterministic random nonce
class LCG:
    def __init__(self, seed):
        self.m = 2147483648
        self.a = 1103515245
        self.c = 12345
        self.state = seed
    def next(self):
        self.state = (self.a * self.state + self.c) % self.m
        return self.state

# Global LCG instance for nonce validation
nonce_lcg = None
nonce_seed = None

def load_tpm_cert():
    """Load the TPM certificate from a PEM file."""
    pem_file = "tpm_cert.pem"
    try:
        with open(pem_file, "rb") as f:
            pem_data = f.read()
        cert = x509.load_pem_x509_certificate(pem_data, default_backend())
        return cert
    except Exception as e:
        app.logger.error("Error loading TPM certificate from PEM file: " + str(e))
        return None

def verify_tpm_signature_with_cert(payload, signature_b64, cert):
    """
    Verify the TPM signature for the payload using the provided certificate.
    Returns True if valid; False otherwise.
    """
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

@app.route("/get_access_token_with_initial_nonce", methods=["GET"])
def get_access_token_with_initial_nonce():
    """Endpoint for background.js to fetch the initial nonce value."""
    global nonce_lcg, nonce_seed
    # Generate a random seed for the LCG
    nonce_seed = random.randint(100000, 999999)
    nonce_lcg = LCG(nonce_seed)
    return jsonify({"nonce": nonce_seed})

@app.route("/")
def index():
    global nonce_lcg, nonce_seed
    geo_header = request.headers.get("X-Custom-Geolocation", "")
    app.logger.debug(f"[DEBUG] Full X-Custom-Geolocation header dump: {geo_header}")
    location_data = {}
    app.logger.debug(f"Received X-Custom-Geolocation header: {geo_header}")
    app.logger.debug(f"[DEBUG] Full X-Custom-Geolocation header dump: {geo_header}")
    app.logger.debug(f"[DEBUG] All request headers: {dict(request.headers)}")

    if geo_header == "Not Provided":
        return jsonify({
            "message": "No X-Custom-Geolocation header provided",
            "geolocation": None
        })

    # Ensure that the WAF marker is present.
    if "waf=processed_by_proxy" in geo_header:
        app.logger.info("WAF marker waf=processed_by_proxy is present.")
    else:
        app.logger.error("Missing WAF marker in X-Custom-Geolocation header.")

    try:
        # Parse the header (semicolon-separated key=value pairs)
        parts = geo_header.split(";")
        header_dict = {}
        for part in parts:
            if "=" in part:
                key, value = part.split("=", 1)
                header_dict[key.strip()] = value.strip()

        lat = float(header_dict.get("lat", "0"))
        lon = float(header_dict.get("lon", "0"))
        accuracy = float(header_dict.get("accuracy", "-1"))
        time_value = header_dict.get("time", "undefined")
        nonce_value = header_dict.get("nonce", "undefined")
        source = header_dict.get("source", "N/A")
        tpm_token = header_dict.get("sig", None)
        cert_chain_b64 = header_dict.get("cert_chain", None)
        tethered_phone_name = header_dict.get("tethered_phone_name", None)
        tethered_phone_mac = header_dict.get("tethered_phone_mac", None)
        tethered_phone_match_type = header_dict.get("tethered_phone_match_type", None)
        # Decode percent-encoding for human-readable logs and API
        if tethered_phone_name:
            tethered_phone_name = unquote(tethered_phone_name)
        if tethered_phone_mac:
            tethered_phone_mac = unquote(tethered_phone_mac)
            # Format MAC as colon-separated (e.g., 98:60:CA:4E:7E:BF)
            mac = tethered_phone_mac.replace('-', ':').replace('.', ':').replace(' ', ':')
            mac_hex = ''.join(c for c in mac if c.isalnum())
            if len(mac_hex) == 12:
                tethered_phone_mac = ':'.join([mac_hex[i:i+2] for i in range(0, 12, 2)])
            else:
                tethered_phone_mac = mac
        if tethered_phone_name or tethered_phone_mac:
            app.logger.info(f"Tethered phone info: name={tethered_phone_name}, mac={tethered_phone_mac}")
        # Always log presence/absence of tethered_phone_match_type
        if tethered_phone_match_type:
            app.logger.info(f"Tethered phone match type: {tethered_phone_match_type}")
        else:
            app.logger.info("Tethered phone match type: not present in header")

        app.logger.info(f"Header parsed: lat={lat}, lon={lon}, accuracy={accuracy}, "
                        f"time={time_value}, nonce={nonce_value}, source={source}")

        # Validate nonce from the header using LCG
        try:
            received_nonce = int(nonce_value)
        except Exception as ex:
            app.logger.error(f"Invalid nonce received: {nonce_value}. Error: {ex}")
            return jsonify({"error": "Invalid nonce received"}), 400

        if nonce_lcg is None:
            app.logger.error("LCG not initialized. Client should reinitialize nonce via /get_access_token_with_initial_nonce")
            response = jsonify({"error": "LCG not initialized; client should reinitialize nonce via /get_access_token_with_initial_nonce"})
            response.status_code = 400
            response.headers["X-Nonce-Error"] = "LCG not initialized; please reinitialize nonce via /get_access_token_with_initial_nonce"
            response.headers["Access-Control-Expose-Headers"] = "X-Nonce-Error"
            return response

        # Validate nonce from the header using LCG
        expected_nonce = nonce_lcg.state
        app.logger.debug(f"[NONCE] Server LCG state: {nonce_lcg.state}, expected nonce: {expected_nonce}, received nonce: {received_nonce}")
        if received_nonce != expected_nonce:
            app.logger.error(f"Nonce mismatch: expected {expected_nonce}, received {received_nonce}")
            response = jsonify({"error": f"Nonce mismatch: expected {expected_nonce}, received {received_nonce}"})
            response.status_code = 400
            response.headers["X-Nonce-Error"] = "Nonce out-of-sync; please reinitialize nonce via /get_access_token_with_initial_nonce"
            response.headers["Access-Control-Expose-Headers"] = "X-Nonce-Error"
            return response
        else:
            app.logger.info(f"Nonce match: {received_nonce} is as expected.")
            app.logger.info("Nonce verification passed.")
            app.logger.debug(f"[NONCE] Advancing server LCG from state {nonce_lcg.state}")

        # Validate TPM signature and all other checks before advancing LCG
        verified = None
        if tpm_token and cert_chain_b64:
            # New format: sig and cert_chain are separate fields
            try:
                # Percent-decode cert_chain first
                cert_chain_b64_decoded = unquote(cert_chain_b64)
                # Add base64 padding if needed
                missing_padding = len(cert_chain_b64_decoded) % 4
                if missing_padding:
                    cert_chain_b64_decoded += '=' * (4 - missing_padding)
                # Now base64-decode
                cert_chain_pem = base64.b64decode(cert_chain_b64_decoded)
                certs = []
                for cert in cert_chain_pem.split(b'-----END CERTIFICATE-----'):
                    if b'-----BEGIN CERTIFICATE-----' in cert:
                        cert = cert + b'-----END CERTIFICATE-----\n'
                        certs.append(x509.load_pem_x509_certificate(cert, default_backend()))
                if len(certs) != 2:
                    app.logger.error(f'[SIGFAIL] Certificate chain must contain 2 certs (x and TPM), got {len(certs)}')
                    return jsonify({"error": 'Certificate chain must contain 2 certs (x and TPM)'}), 400
                x_cert, tpm_cert = certs
                # Verify x_cert is signed by tpm_cert (issuer check and signature)
                if x_cert.issuer != tpm_cert.subject:
                    app.logger.error(f'[SIGFAIL] x_cert issuer does not match tpm_cert subject')
                    return jsonify({"error": 'x_cert not issued by TPM cert'}), 400
                tpm_cert.public_key().verify(
                    x_cert.signature,
                    x_cert.tbs_certificate_bytes,
                    padding.PKCS1v15(),
                    x_cert.signature_hash_algorithm,
                )
                # Verify signature on payload using x_cert
                sig_b64_decoded = unquote(tpm_token)
                missing_padding = len(sig_b64_decoded) % 4
                if missing_padding:
                    sig_b64_decoded += '=' * (4 - missing_padding)
                signature = base64.b64decode(sig_b64_decoded)
                # Format accuracy as integer if possible to match client
                accuracy_str = str(int(accuracy)) if accuracy == int(accuracy) else str(accuracy)
                payload_str = f"lat={lat};lon={lon};accuracy={accuracy_str};source={source};time={time_value};nonce={nonce_value}"
                app.logger.debug(f"[PAYLOAD] Payload string used for verification: {payload_str}")
                x_cert.public_key().verify(
                    signature,
                    payload_str.encode('utf-8'),
                    padding.PKCS1v15(),
                    hashes.SHA256()
                )
                app.logger.info("Certificate chain and signature verified successfully.")
                verified = True
            except Exception as e:
                app.logger.error(f"[SIGFAIL] Error verifying new-format signature/cert chain: {e}")
                app.logger.error(traceback.format_exc())
                return jsonify({"error": f"Certificate chain and signature verification failed: {e}"}), 400
        elif tpm_token:
            # Legacy format (for backward compatibility)
            if "|sig=" in tpm_token:
                att_payload, signature_b64 = tpm_token.split("|sig=", 1)
                att_dict = {}
                for pair in att_payload.split(","):
                    if "=" in pair:
                        k, v = pair.split("=", 1)
                        att_dict[k.strip()] = v.strip()
                lat_match = math.isclose(float(att_dict.get("lat", "0")), lat, rel_tol=1e-6)
                lon_match = math.isclose(float(att_dict.get("lon", "0")), lon, rel_tol=1e-6)
                acc_match = math.isclose(float(att_dict.get("accuracy", "0")), accuracy, rel_tol=1e-6)
                time_match = (att_dict.get("time", "") == time_value)
                nonce_match = (att_dict.get("nonce", "") == nonce_value)
                if not (lat_match and lon_match and acc_match and time_match and nonce_match):
                    app.logger.error("Attestation payload mismatch.")
                    return jsonify({"error": "Attestation payload mismatch."}), 400
                # Use the robust certificate chain and signature verification
                valid, msg = verify_certificate_chain_and_signature(tpm_token)
                if not valid:
                    app.logger.error(f"Certificate chain and signature verification failed: {msg}")
                    return jsonify({"error": f"Certificate chain and signature verification failed: {msg}"}), 400
                else:
                    app.logger.info("Certificate chain and signature verified successfully.")
                    verified = True
            else:
                app.logger.error("TPM token not in expected format.")
                return jsonify({"error": "TPM token not in expected format."}), 400
        else:
            app.logger.info("No TPM token provided in header.")

        # Only now advance the LCG after all validation passes
        nonce_lcg.next()
        app.logger.debug(f"[NONCE] Server LCG advanced to state: {nonce_lcg.state}")

        coord = (lat, lon)
        geo = reverse_geocode.get(coord)
        location_data = {
            "latitude": lat,
            "longitude": lon,
            "accuracy_meters": accuracy,
            "time": time_value,
            "nonce": nonce_value,
            "source": source,
            "City": geo.get("city", "Unknown"),
            "State": geo.get("state", "Unknown"),
            "Country": geo.get("country", "Unknown")
        }
        # Only add tethered_phone_name and tethered_phone_mac if not already present in the response
        # (Assume upstream proxy or client may already inject these fields)
        if tpm_token:
            location_data["TPM_signature_Verified"] = True
        # Extract phone fields from mobile_phone_identity only (no legacy fallback)
        import json
        phone_identity = header_dict.get("mobile_phone_identity")
        tethered_phone_name = None
        tethered_phone_mac = None
        tethered_phone_match_type = None
        # Debug: log the raw mobile_phone_identity header
        app.logger.info(f"Raw mobile_phone_identity header: {header_dict.get('mobile_phone_identity')}")
        if phone_identity:
            if isinstance(phone_identity, str):
                try:
                    phone_identity = json.loads(unquote(phone_identity))
                except Exception as e:
                    app.logger.error(f"Failed to decode/parse phone_identity: {e}")
                    phone_identity = {}
            app.logger.info(f"Parsed phone_identity: {phone_identity}")
            tethered_phone_name = phone_identity.get("name")
            tethered_phone_mac = phone_identity.get("tethered_phone_mac") or phone_identity.get("bluetooth_bd_addr")
            tethered_phone_match_type = phone_identity.get("tethered_phone_match_type")

        # Add phone liveness fields to response if present, and remove any accidental duplicates
        for key, value in [
            ("tethered_phone_name", tethered_phone_name),
            ("tethered_phone_mac", tethered_phone_mac),
            ("tethered_phone_match_type", tethered_phone_match_type)
        ]:
            if value is not None:
                location_data[key] = value
        app.logger.info(f"Final location_data for response: {location_data}")

    except Exception as e:
        app.logger.error(f"Failed to parse geolocation: {e}")
        return jsonify({"error": f"Failed to parse geolocation: {str(e)}"}), 400

    return jsonify({
        "message": "Verified TPM signature and geolocation converted to geographic region",
        "geolocation": location_data
    })

@app.route("/favicon.ico")
def favicon():
    return send_from_directory(os.path.join(app.root_path, "static"),
                               "favicon.ico",
                               mimetype="image/vnd.microsoft.icon")

@app.after_request
def add_divider(response):
    response.call_on_close(lambda: app.logger.info("\n----------------------------------------------------\n"))
    return response

@app.after_request
def add_cors_headers(response):
    response.headers['Access-Control-Allow-Origin'] = '*'
    response.headers['Access-Control-Allow-Methods'] = 'GET, POST, OPTIONS'
    response.headers['Access-Control-Allow-Headers'] = 'Content-Type, X-Custom-Geolocation'
    return response

if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)
    app.run(host="0.0.0.0",
            port=9443,
            ssl_context=("cert.pem", "key.pem"))
