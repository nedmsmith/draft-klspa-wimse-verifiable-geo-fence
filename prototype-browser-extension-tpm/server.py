from flask import Flask, request, jsonify, send_from_directory, make_response
import os
import base64
import reverse_geocode
import math
import logging
import random
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.x509.base import load_pem_x509_certificate

# Ensure all logs are visible in the console
logging.basicConfig(level=logging.DEBUG)

app = Flask(__name__)

# ----- Global In-Memory Nonce Store -----
# current_nonce is incremented only when a request is valid.
current_nonce = random.randint(100000, 999999)

# ----- Helper Functions and Configuration -----

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
    global current_nonce
    return jsonify({"nonce": current_nonce})

@app.route("/")
def index():
    global current_nonce
    geo_header = request.headers.get("X-Custom-Geolocation", "Not Provided")
    location_data = {}
    app.logger.info(f"Received X-Custom-Geolocation header: {geo_header}")

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
        # For dev/test, ignore cert_chain_b64 and always use hardcoded chain

        app.logger.info(f"Header parsed: lat={lat}, lon={lon}, accuracy={accuracy}, "
                        f"time={time_value}, nonce={nonce_value}, source={source}")

        # Validate nonce from the header.
        try:
            received_nonce = int(nonce_value)
        except Exception as ex:
            app.logger.error(f"Invalid nonce received: {nonce_value}. Error: {ex}")
            return jsonify({"error": "Invalid nonce received"}), 400

        # Check for nonce out-of-sync due to a server restart.
        if current_nonce == 1 and received_nonce > 1:
            app.logger.error("Server nonce is 1 and client nonce is greater than 1. Please reinitialize nonce via /get_access_token_with_initial_nonce.")
            response = jsonify({"error": "Nonce out-of-sync due to server restart; client should reinitialize nonce via /get_access_token_with_initial_nonce"})
            response.status_code = 400
            response.headers["X-Nonce-Error"] = "Nonce out-of-sync; please reinitialize nonce via /get_access_token_with_initial_nonce"
            response.headers["Access-Control-Expose-Headers"] = "X-Nonce-Error"
            return response

        if received_nonce != current_nonce:
            app.logger.error(f"Nonce mismatch: expected {current_nonce}, received {received_nonce}")
            return jsonify({"error": f"Nonce mismatch: expected {current_nonce}, received {received_nonce}"}), 400
        else:
            app.logger.info(f"Nonce match: {received_nonce} is as expected.")
            app.logger.info("Nonce verification passed.")  # Explicit log for successful nonce verification
            # Valid request: increment nonce.
            current_nonce += 1

        verified = None
        if tpm_token:
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
        if tpm_token:
            location_data["TPM_signature_Verified"] = True

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
