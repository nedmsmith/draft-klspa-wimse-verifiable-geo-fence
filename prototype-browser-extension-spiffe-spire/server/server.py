from flask import Flask, request, jsonify, send_from_directory
import os
import reverse_geocode

app = Flask(__name__)

def infer_location_source(accuracy):
    if accuracy < 10:
        return "GPS (likely outdoor)"
    elif accuracy < 20:
        return "Wi-Fi"
    elif accuracy < 100:
        return "Cell Tower"
    else:
        return "IP-based or coarse location"

@app.route("/")
def index():
    geo_header = request.headers.get("X-Custom-Geolocation", "Not Provided")
    location_data = {}

    if geo_header != "Not Provided":
        try:
            parts = dict(item.split("=") for item in geo_header.split(";"))
            lat = float(parts.get("lat", 0))
            lon = float(parts.get("lon", 0))
            accuracy = float(parts.get("accuracy", -1))
            source = infer_location_source(accuracy)

            location_data = {
                "latitude": lat,
                "longitude": lon,
                "accuracy_meters": accuracy,
                "inferred_source": source
            }

            print("GeoLocation data:", location_data)

            coord = lat, lon
            print("Geographic boundary data:", reverse_geocode.get(coord))

        except Exception as e:
            location_data = {"error": f"Failed to parse geolocation: {str(e)}"}

    return jsonify({
        "message": "Received request from browser",
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
    app.run(
        host="0.0.0.0",
        port=8443,
        ssl_context=("cert.pem", "key.pem")
    )

