#!/usr/bin/env python3
import sys
import struct
import json

def main():
    # Prepare a dummy test message (simulate geolocation data)
    test_message = {"lat": 37.314843, "lon": -122.052589, "accuracy": 212, "source": "IP-based"}
    encoded = json.dumps(test_message).encode("utf-8")
    # Write the 4-byte length prefix
    sys.stdout.buffer.write(struct.pack("I", len(encoded)))
    # Write the JSON message bytes
    sys.stdout.buffer.write(encoded)
    sys.stdout.buffer.flush()
    # End the script immediately to prevent any extra output
    sys.exit(0)

if __name__ == '__main__':
    main()
