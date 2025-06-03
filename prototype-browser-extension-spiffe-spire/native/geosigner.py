import sys
import json
import struct
import geocoder
import reverse_geocoder as rg

def get_geolocation():
    g = geocoder.ip('me')
    coords = g.latlng
    region = rg.search(coords)[0]
    return coords, region

def sign_data(data):
    # Placeholder for TPM-backed signing
    return "signed_with_tpm_placeholder"

def read_message():
    raw_length = sys.stdin.buffer.read(4)
    if not raw_length:
        sys.exit(0)
    message_length = struct.unpack("=I", raw_length)[0]
    message = sys.stdin.buffer.read(message_length).decode("utf-8")
    return json.loads(message)

def send_message(message):
    encoded = json.dumps(message).encode("utf-8")
    sys.stdout.buffer.write(struct.pack("=I", len(encoded)))
    sys.stdout.buffer.write(encoded)
    sys.stdout.buffer.flush()

while True:
    try:
        msg = read_message()
        if msg.get("action") == "get_signed_geo":
            coords, region = get_geolocation()
            signed = sign_data({"coords": coords, "region": region})
            send_message({
                "coords": coords,
                "region": region,
                " except Exception as e:
        send_message({"error": str(e)})
