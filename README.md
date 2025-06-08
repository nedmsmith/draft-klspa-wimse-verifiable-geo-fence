<!-- regenerate: on (set to off if you edit this file) -->

# TODO - Your title- test from ramki

This is the working area for the individual Internet-Draft, "TODO - Your title".

* [Editor's Copy](https://nedmsmith.github.io/draft-klspa-wimse-verifiable-geo-fence/#go.draft-lkspa-wimse-verifiable-geo-fence.html)
* [Datatracker Page](https://datatracker.ietf.org/doc/draft-lkspa-wimse-verifiable-geo-fence)
* [Individual Draft](https://datatracker.ietf.org/doc/html/draft-lkspa-wimse-verifiable-geo-fence)
* [Compare Editor's Copy to Individual Draft](https://nedmsmith.github.io/draft-klspa-wimse-verifiable-geo-fence/#go.draft-lkspa-wimse-verifiable-geo-fence.diff)


## Contributing

See the
[guidelines for contributions](https://github.com/nedmsmith/draft-klspa-wimse-verifiable-geo-fence/blob/main/CONTRIBUTING.md).

Contributions can be made by creating pull requests.
The GitHub interface supports creating pull requests using the Edit (✏) button.


## Command Line Usage

Formatted text and HTML versions of the draft can be built using `make`.

```sh
$ make
```

Command line usage requires that you have the necessary software installed.  See
[the instructions](https://github.com/martinthomson/i-d-template/blob/main/doc/SETUP.md).

# TPM-Backed Geolocation Attestation Prototype

This directory implements a prototype for secure, verifiable geolocation attestation using TPM-backed certificates. It is designed to work with a browser extension that collects geolocation data and communicates with this backend.

## Components

- **server.py**  
  Flask server that:
  - Receives geolocation data and TPM-signed tokens via HTTP headers.
  - Verifies the TPM signature using a certificate (`tpm_cert.pem`).
  - Checks nonce freshness to prevent replay attacks.
  - Converts coordinates to city/state/country using reverse geocoding.
  - Provides an endpoint (`/init_nonce`) for nonce initialization.

- **win-app.py**  
  Windows native messaging host that:
  - Reads geolocation data from stdin (from the browser extension).
  - Constructs a payload including latitude, longitude, accuracy, time, and nonce.
  - Signs the payload using a TPM-backed certificate via PowerShell.
  - Returns the signed token to the browser extension.

- **win-app.bat**  
  Batch file to launch `win-app.py` with the correct Python interpreter.

- **test-win-app.py**  
  Script to send a test geolocation message to the native messaging host for development/testing.

## Usage

### 1. TPM Certificate

Place your TPM-backed certificate in PEM format as `tpm_cert.pem` in this directory for the server to verify signatures.

### 2. Running the Server

```sh
python server.py
```
The server listens on port 8443 with TLS enabled (requires `cert.pem` and `key.pem`).

### 3. Running the Native Messaging Host

The browser extension should launch `win-app.py` (or use `win-app.bat`) as a native messaging host. It expects JSON messages with geolocation data and returns signed tokens.

### 4. Testing

You can use `test-win-app.py` to simulate sending geolocation data to the native messaging host.

## Protocol

- The browser extension collects geolocation data and sends it to the native messaging host.
- The host signs the data (with time and nonce) using the TPM and returns a token.
- The extension sends the token to the Flask server in the `X-Custom-Geolocation` HTTP header.
- The server verifies the signature, checks the nonce, and responds with region info.

## Files

- [`server.py`](server.py)
- [`win-app.py`](win-app.py)
- [`win-app.bat`](win-app.bat)
- [`test-win-app.py`](test-win-app.py)

---

**Note:** This is a prototype and not production-ready. Use for research and experimentation only.

