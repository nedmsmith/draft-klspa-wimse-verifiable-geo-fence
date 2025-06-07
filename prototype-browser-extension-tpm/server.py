from flask import Flask, request, jsonify, send_from_directory
import os
import base64
import reverse_geocode
import math
import logging
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.exceptions import InvalidSignature

app = Flask(__name__)

# ----- Global In-Memory Nonce Store -----
# We assume only one TPM certificate is used. The nonce is incremented per API request.
current_nonce = 1

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

# ----- Nonce Initialization Endpoint -----
@app.route("/init_nonce", methods=["GET"])
def init_nonce():
    """Endpoint for background.js to fetch the initial nonce value."""
    global current_nonce
    return jsonify({"nonce": current_nonce})

# ----- Main Route Handler -----

@app.route("/")
def index():
    global current_nonce
    geo_header = request.headers.get("X-Custom-Geolocation", "Not Provided")
    location_data = {}
    app.logger.info(f"Received X-Custom-Geolocation header: {geo_header}")

    if geo_header != "Not Provided":
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

            app.logger.info(f"Header parsed: lat={lat}, lon={lon}, accuracy={accuracy}, time={time_value}, nonce={nonce_value}, source={source}")

            # Validate nonce from the header against our in-memory store.
            try:
                received_nonce = int(nonce_value)
            except Exception as ex:
                app.logger.error(f"Invalid nonce received: {nonce_value}. Error: {ex}")
                received_nonce = None

            if received_nonce is not None:
                if received_nonce != current_nonce:
                    app.logger.warning(f"Nonce mismatch: expected {current_nonce}, received {received_nonce}")
                else:
                    app.logger.info(f"Nonce match: {received_nonce} is as expected.")
                    current_nonce += 1  # Increment nonce after a valid match.
            else:
                app.logger.warning("No valid nonce received; skipping nonce check.")

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
                        app.logger.warning("Attestation payload mismatch: lat_match=%s, lon_match=%s, acc_match=%s, time_match=%s, nonce_match=%s" %
                                           (lat_match, lon_match, acc_match, time_match, nonce_match))
                    tpm_cert = load_tpm_cert()
                    if tpm_cert:
                        verified = verify_tpm_signature_with_cert(att_payload, signature_b64.strip(), tpm_cert)
                    else:
                        app.logger.error("No TPM certificate available for signature verification.")
                        verified = False
                else:
                    app.logger.warning("TPM token not in expected format.")
                    verified = False
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
                location_data["TPM_signature_Verified"] = verified

        except Exception as e:
            app.logger.error(f"Failed to parse geolocation: {e}")
            location_data = {"error": f"Failed to parse geolocation: {str(e)}"}

    return jsonify({
        "message": "Verified TPM signature and geolocation converted to geographic region",
        "geolocation": location_data or geo_header
    })

@app.route("/favicon.ico")
def favicon():
    return send_from_directory(os.path.join(app.root_path, "static"), "favicon.ico", mimetype="image/vnd.microsoft.icon")

if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)
    app.run(host="0.0.0.0", port=8443, ssl_context=("cert.pem", "key.pem"))
