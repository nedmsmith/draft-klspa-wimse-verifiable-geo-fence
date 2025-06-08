from flask import Flask, request, Response, jsonify, send_from_directory
import requests
import logging
import math
import os
import base64
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding

app = Flask(__name__)
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
        cert = x509.load_pem_x509_certificate(pem_data, default_backend())
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

# -----------------------
# DPI Proxy Route
# -----------------------

@app.route('/', defaults={'path': ''}, methods=['GET', 'POST', 'PUT', 'DELETE', 'PATCH', 'OPTIONS'])
@app.route('/<path:path>', methods=['GET', 'POST', 'PUT', 'DELETE', 'PATCH', 'OPTIONS'])
def proxy(path):
    global current_nonce

    # Special-case: handle /init_nonce requests without DPI header processing.
    if path.lower() == "init_nonce":
        app.logger.info("Processing /init_nonce request without DPI header modifications.")
    else:
        original_geo_header = request.headers.get("X-Custom-Geolocation")
        if original_geo_header:
            app.logger.info(f"Received X-Custom-Geolocation header: {original_geo_header}")
            parsed_fields = parse_geolocation_header(original_geo_header)
            # Nonce checking logic (mirroring server.py):
            try:
                received_nonce = int(parsed_fields.get("nonce", ""))
            except Exception as ex:
                app.logger.error(f"Invalid nonce received: {parsed_fields.get('nonce','')}. Error: {ex}")
                return jsonify({"error": "Invalid nonce received"}), 400

            if current_nonce is None:
                # If no nonce has been set yet, initialize it with the received nonce.
                current_nonce = received_nonce
                app.logger.info(f"Initial nonce set to: {current_nonce}")

            if current_nonce == 1 and received_nonce > 1:
                app.logger.error("Nonce out-of-sync: expected nonce 1 but received a nonce greater than 1. Please reinitialize nonce via /init_nonce.")
                response = jsonify({"error": "Nonce out-of-sync; please reinitialize nonce via /init_nonce"})
                response.status_code = 400
                response.headers["X-Nonce-Error"] = "Nonce out-of-sync; please reinitialize nonce via /init_nonce"
                response.headers["Access-Control-Expose-Headers"] = "X-Nonce-Error"
                return response

            if received_nonce != current_nonce:
                app.logger.error(f"Nonce mismatch: expected {current_nonce}, received {received_nonce}")
                return jsonify({"error": f"Nonce mismatch: expected {current_nonce}, received {received_nonce}"}), 400
            else:
                app.logger.info(f"Nonce match: {received_nonce} is as expected.")
                current_nonce += 1

            # Validate TPM signature if present.
            if "sig" in parsed_fields:
                tpm_token = parsed_fields["sig"]
                if "|sig=" in tpm_token:
                    try:
                        att_payload, signature_b64 = tpm_token.split("|sig=", 1)
                        att_payload = att_payload.strip()
                        signature_b64 = signature_b64.strip()
                        app.logger.info(f"Extracted attestation payload: {att_payload}")
                        app.logger.info(f"Extracted signature (base64): {signature_b64}")
                        tpm_cert = load_tpm_cert()
                        if tpm_cert:
                            valid = verify_tpm_signature_with_cert(att_payload, signature_b64, tpm_cert)
                            if not valid:
                                app.logger.error("Invalid TPM signature in X-Custom-Geolocation header.")
                            else:
                                app.logger.info("TPM signature validated successfully.")
                        else:
                            app.logger.error("Failed to load TPM certificate for signature validation.")
                    except Exception as ex:
                        app.logger.error(f"Error parsing TPM signature from header: {ex}")
                else:
                    app.logger.error("TPM token not in expected format (missing '|sig=' delimiter).")
        else:
            app.logger.info("No X-Custom-Geolocation header in request.")

    # Build upstream URL.
    upstream_url = f"{UPSTREAM_SERVER}/{path}"
    if request.query_string:
        upstream_url += "?" + request.query_string.decode("utf-8")
    
    # Copy incoming headers.
    headers = dict(request.headers)
    headers.pop("Host", None)
    
    # For non-/init_nonce requests, append a DPI processing marker.
    if "X-Custom-Geolocation" in headers and path.lower() != "init_nonce":
        original_value = headers["X-Custom-Geolocation"]
        headers["X-Custom-Geolocation"] = original_value + ";dpi=processed_by_proxy"
        app.logger.info(f"Updated X-Custom-Geolocation header for forwarding: {headers['X-Custom-Geolocation']}")

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

    # If this is an /init_nonce request, update our internal nonce based on the response.
    if path.lower() == "init_nonce":
        try:
            data = upstream_response.json()
            new_nonce = data.get("nonce")
            if new_nonce is not None:
                current_nonce = new_nonce
                app.logger.info(f"Updated nonce from /init_nonce response: {current_nonce}")
            else:
                app.logger.error("No nonce field in /init_nonce response.")
        except Exception as ex:
            app.logger.error(f"Error parsing /init_nonce response: {ex}")

    # Build the final response.
    response = Response(upstream_response.content, status=upstream_response.status_code)
    for key, value in upstream_response.headers.items():
        response.headers[key] = value

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
    # Run the DPI proxy with TLS termination.
    ssl_context = ("cert.pem", "key.pem")
    app.run(host="0.0.0.0", port=8443, ssl_context=ssl_context)
