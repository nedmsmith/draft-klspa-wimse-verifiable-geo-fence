from flask import Flask, request, jsonify, send_from_directory
import os
import base64
import reverse_geocode

from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.exceptions import InvalidSignature

app = Flask(__name__)

# ----- Helper Functions and Configuration -----

def load_tpm_cert():
    """Load the TPM certificate from a PEM file."""
    try:
        with open("tpm_cert.pem", "rb") as cert_file:
            cert_data = cert_file.read()
            return x509.load_pem_x509_certificate(cert_data, default_backend())
    except Exception as e:
        app.logger.error(f"Error loading TPM certificate: {e}")
        return None

TPM_CERT = load_tpm_cert()

def verify_tpm_signature(payload, signature_b64):
    """
    Verify the TPM signature (base64‑encoded) against the payload string 
    using the public key extracted from the TPM certificate.
    Returns True if the signature is valid; otherwise, False.
    """
    if TPM_CERT is None:
        app.logger.error("TPM certificate not loaded.")
        return False

    public_key = TPM_CERT.public_key()
    try:
        signature = base64.b64decode(signature_b64)
    except Exception as e:
        app.logger.error(f"Error decoding signature: {e}")
        return False

    try:
        public_key.verify(
            signature,
            payload.encode("utf-8"),
            padding.PKCS1v15(),
            hashes.SHA256()
        )
        return True
    except InvalidSignature:
        app.logger.error("TPM signature is invalid.")
        return False
    except Exception as e:
        app.logger.error(f"Error during signature verification: {e}")
        return False

# ----- Flask Routes -----

@app.route("/")
def index():
    # Retrieve the custom header.
    geo_header = request.headers.get("X-Custom-Geolocation", "Not Provided")
    location_data = {}

    if geo_header != "Not Provided":
        try:
            # Expected header format:
            # "lat=<value>;lon=<value>;accuracy=<value>[;sig=<TPM token>]"
            header_parts = geo_header.split(";")
            parsed = {}
            for part in header_parts:
                if "=" in part:
                    key, value = part.split("=", 1)
                    parsed[key.strip()] = value.strip()

            # Extract basic geolocation values.
            accuracy_str = parsed.get("accuracy", "-1")
            lat = float(parsed.get("lat", "0"))
            lon = float(parsed.get("lon", "0"))
            accuracy = float(accuracy_str)
            tpm_token = parsed.get("sig", None)

            # If a TPM token is provided, extract the attestation payload and signature.
            source = "N/A"
            verified = None
            if tpm_token:
                if "|sig=" in tpm_token:
                    attestation_payload, signature_b64 = tpm_token.split("|sig=", 1)
                    # Parse the attestation payload fields.
                    att_parts = {}
                    for part in attestation_payload.split(","):
                        if "=" in part:
                            k, v = part.split("=", 1)
                            att_parts[k.strip()] = v.strip()
                    # Extract the source from the attestation payload.
                    source = att_parts.get("source", "unknown")
                    
                    # Compare the fields numerically (or as strings for source).
                    lat_match = abs(float(att_parts.get("lat", 0)) - lat) < 1e-6
                    lon_match = abs(float(att_parts.get("lon", 0)) - lon) < 1e-6
                    acc_match = abs(float(att_parts.get("accuracy", 0)) - accuracy) < 1e-6
                    source_match = att_parts.get("source", "").strip() == source
                    if not (lat_match and lon_match and acc_match and source_match):
                        app.logger.warning("Attestation payload does not match header values.")
                    verified = verify_tpm_signature(attestation_payload.strip(), signature_b64.strip())
                else:
                    # Fallback if token is not in expected format.
                    app.logger.warning("TPM token is not in the expected format.")
                    source = "unknown"
                    expected_payload = f"lat={lat},lon={lon},accuracy={accuracy_str},source={source}"
                    verified = verify_tpm_signature(expected_payload, tpm_token.strip())
            else:
                # If no TPM token, source remains unavailable.
                source = "N/A"

            # Use reverse_geocode to convert coordinates to geographic details.
            coord = (lat, lon)
            geo = reverse_geocode.get(coord)
            location_data = {
                "latitude": lat,
                "longitude": lon,
                "accuracy_meters": accuracy,
                "source": source,
                "City": geo.get("city", "Unknown"),
                "State": geo.get("state", "Unknown"),
                "Country": geo.get("country", "Unknown")
            }
            if tpm_token:
                location_data["TPM_signature_Verified"] = verified

        except Exception as e:
            location_data = {"error": f"Failed to parse geolocation: {str(e)}"}

    return jsonify({
        "message": "Verified TPM signature of geolocation (lat/lon) and converted to geographic region (city/state/country)",
        "geolocation": location_data or geo_header
    })

@app.route('/favicon.ico')
def favicon():
    return send_from_directory(
        os.path.join(app.root_path, 'static'),
        'favicon.ico',
        mimetype='image/vnd.microsoft.icon'
    )

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=8443, ssl_context=("cert.pem", "key.pem"))
