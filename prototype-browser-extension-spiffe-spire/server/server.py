from flask import Flask, request, jsonify

app = Flask(__name__)

@app.route('/favicon.ico')
def favicon():
    return send_from_directory(
        os.path.join(app.root_path, 'static'),
        'favicon.ico',
        mimetype='image/vnd.microsoft.icon'
    )

@app.route("/", methods=["GET", "POST"])
def index():
    geo_header = request.headers.get("X-Geo-Sign")
    if geo_header:
        # In production, you would verify the TPM-backed signature.
        print(jsonify(geo_header))
        return jsonify({
            "message": "Geo header received",
            "X-Geo-Sign": geo_header
        }), 200
    else:
        return jsonify({
            "message": "X-Geo-Sign header not provided."
        }), 400

if __name__ == "__main__":
    # IMPORTANT: Before running, make sure you have generated SSL certificate and key files.
    # For testing on Windows, you can create a self-signed certificate. For example, using OpenSSL:
    #   openssl req -x509 -newkey rsa:4096 -keyout key.pem -out cert.pem -days 365 -nodes
    #
    # Then, run this script. The server will be accessible via:
    #   https://localhost:443/
    app.run(host="0.0.0.0", port=443, ssl_context=("cert.pem", "key.pem"))

