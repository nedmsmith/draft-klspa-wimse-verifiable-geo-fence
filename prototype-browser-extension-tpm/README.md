# Verifiable Geo-Fence with TPM Attestation

This project implements a verifiable geolocation system using TPM (Trusted Platform Module) attestation. It provides cryptographically verifiable proof of a device's location through a browser extension, native messaging host, and server architecture.

## Project Overview

This is a prototype implementation of a system that:
1. Captures geolocation data in a browser extension
2. Sends it to a native messaging host for TPM attestation
3. Injects the signed attestation into HTTP headers
4. Verifies and processes the attestation via a proxy and server

## Components

### Browser Extension
- **[`background.js`](background.js )**: Background script that captures geolocation, sends it for attestation, and injects it into HTTP headers
- **[`popup.js`](popup.js )**: Simple UI for configuring domains for header injection
- **[`manifest.json`](manifest.json )**: Extension configuration

### Native Messaging Host
- **[`win-app.py`](win-app.py )**: Python script that receives location data, signs it using TPM-backed keys, and returns attestation tokens
- **[`win-app.bat`](win-app.bat )**: Windows batch file to launch the native messaging host
- **[`com.mycompany.geosign.json`](com.mycompany.geosign.json )**: Native messaging host manifest for browser integration

### Server Components
- **[`server.py`](server.py )**: Flask server that validates TPM attestations and processes geolocation data
- **[`waf-proxy.py`](waf-proxy.py )**: Web Application Firewall (WAF) proxy that validates headers before forwarding requests

### Cryptographic Components
- **Key hierarchy**:
  - TPM certificate: Root of trust (tpm_cert.pem)
  - X certificate: Signed by TPM certificate for geolocation signing (x_cert.pem)
- **Attestation flow**: Browser → Native Host → TPM signing → HTTP headers → Proxy validation → Server processing

## Setup and Usage

### Prerequisites
- A Windows system with TPM capability
- Python 3.x
- Firefox or Chrome browser
- Required Python packages (see requirements.txt)

### Installation
1. Install Python dependencies:
   ```
   pip install -r requirements.txt
   ```

2. Register the native messaging host:
   ```
   REG ADD "HKCU\Software\Mozilla\NativeMessagingHosts\com.mycompany.geosign" /ve /t REG_SZ /d "<path>\com.mycompany.geosign.json" /f

   Example: REG ADD "HKCU\Software\Mozilla\NativeMessagingHosts\com.mycompany.geosign" /ve /t REG_SZ /d "C:\Users\ramkr\draft-klspa-wimse-verifiable-geo-fence\prototype-browser-extension-tpm\com.mycompany.geosign.json" /f
   ```

3. Install the browser extension:
   - Load the extension in developer mode
   - Configure domains in the extension popup

### Running the System
1. Start the proxy server:
   ```
   python dpi-proxy.py
   ```

2. Start the backend server:
   ```
   python server.py
   ```

3. Visit a configured website through the proxy to test the system

## Technical Details

### Security Features
- TPM-backed attestation ensures hardware-level trust
- Certificate chain validation verifies the signing hierarchy
- Nonce-based replay protection prevents reuse of old attestations
- Proxy validation adds an additional verification layer

### Protocol Flow
1. Browser extension obtains location and timestamp
2. Native host signs data with TPM-backed keys
3. Signed attestation is added to HTTP headers
4. Proxy validates signatures and adds WAF marker
5. Server performs final validation and processes the verified location

## Development and Testing
- Use **[`test-win-app.py`](test-win-app.py )** to simulate the native messaging flow
- Check **[`win_app.log`](win_app.log )** for native host logs
- Monitor Flask server logs for validation status

## Limitations
This is a prototype implementation with several limitations:
- Currently Windows-specific due to TPM integration approach
- Requires browser permission for geolocation access
- Self-signed certificates used for development

## Future Work
- Cross-platform TPM attestation support
- Hardware-based geolocation verification (cellular, GPS)
- Dynamic security policy enforcement based on verified location
- Improved certificate management and revocation

---

*Note: This prototype demonstrates the concept of verifiable geolocation with TPM attestation and is not intended for production use without further security review and hardening.*
