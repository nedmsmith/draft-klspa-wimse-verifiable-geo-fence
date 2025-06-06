let targetDomains = ["localhost"];

// Load domains from storage
browser.storage.sync.get("domains").then((data) => {
  targetDomains = data.domains || targetDomains;
});

// Update domains if changed
browser.storage.onChanged.addListener((changes) => {
  if (changes.domains) {
    targetDomains = changes.domains.newValue;
  }
});

/**
 * Heuristically determines the likely location source based on geolocation accuracy.
 *
 * @param {number} accuracy - The geolocation accuracy in meters.
 * @returns {string} - One of: "GPS", "Wi-Fi", "Cellular", or "IP-based".
 */
function guessLocationSource(accuracy) {
  if (accuracy <= 10) {
    return "GPS";
  } else if (accuracy <= 100) {
    return "Wi-Fi";
  } else if (accuracy <= 250) {
    return "Cellular";
  } else {
    return "IP-based";
  }
}

/**
 * Connects to the native messaging host and sends geolocation data to request a TPM attestation token.
 *
 * @param {number} lat - Latitude.
 * @param {number} lon - Longitude.
 * @param {number} accuracy - Geolocation accuracy in meters.
 * @param {string} source - The derived geolocation source.
 * @returns {Promise<string>} - A promise that resolves with the attestation token.
 */
function getTPMAttestation(lat, lon, accuracy, source) {
  console.log(
    `[Background] Requesting TPM Attestation for lat:${lat}, lon:${lon}, accuracy:${accuracy}, source:${source}`
  );
  return new Promise((resolve, reject) => {
    // IMPORTANT: Use the exact same host name as in your native messaging host manifest.
    const nativePort = browser.runtime.connectNative("com.mycompany.geosign");
    console.log("[Background] New native messaging connection created.");

    // Increase timeout to 15 seconds.
    const timeoutId = setTimeout(() => {
      nativePort.onMessage.removeListener(responseListener);
      console.error("[Background] Timeout waiting for TPM attestation.");
      reject("Timeout waiting for TPM attestation");
    }, 15000);

    // Define a listener for the response.
    function responseListener(response) {
      console.log("[Background] Received response from native host:", response);
      if (response.token) {
        clearTimeout(timeoutId);
        nativePort.onMessage.removeListener(responseListener);
        console.log("[Background] TPM Attestation token received.");
        resolve(response.token);
      } else if (response.error) {
        clearTimeout(timeoutId);
        nativePort.onMessage.removeListener(responseListener);
        console.error("[Background] Error from native host:", response.error);
        reject(response.error);
      }
    }
    nativePort.onMessage.addListener(responseListener);

    // Create a payload string that includes geolocation data and a source.
    // (Using commas here for the TPM process; the returned token will be incorporated into the header.)
    const payloadString = `lat=${lat},lon=${lon},accuracy=${accuracy},source=${source}`;

    // Send the message with the "command" and the "payload" field.
    nativePort.postMessage({
      command: "attest",
      payload: payloadString
    });
    console.log("[Background] Posted geolocation data (as payload) to native host.");
  });
}

// Intercept outgoing HTTP requests to inject the custom header.
// This version obtains geolocation (plus TPM attestation token if available) and builds a header
// in the expected format for the Flask server.
browser.webRequest.onBeforeSendHeaders.addListener(
  async (details) => {
    const url = new URL(details.url);
    if (!targetDomains.includes(url.hostname)) return;

    try {
      // Obtain geolocation with a 5-second timeout.
      const position = await new Promise((resolve, reject) => {
        navigator.geolocation.getCurrentPosition(resolve, reject, { timeout: 5000 });
      });
      const { latitude, longitude, accuracy } = position.coords;
      console.log(`[Background] Geolocation obtained: lat=${latitude}, lon=${longitude}, accuracy=${accuracy}`);

      // Determine the likely source based on accuracy.
      const source = guessLocationSource(accuracy);

      // Build the header value with required geolocation data.
      let headerValue = `lat=${latitude};lon=${longitude};accuracy=${accuracy}`;

      // Attempt to obtain a TPM attestation token.
      try {
        const tpmToken = await getTPMAttestation(latitude, longitude, accuracy, source);
        // Append the signature to the header value.
        headerValue += `;sig=${tpmToken}`;
      } catch (attestError) {
        console.warn("[Background] TPM attestation failed:", attestError);
      }

      // Inject the constructed header.
      details.requestHeaders.push({
        name: "X-Custom-Geolocation",
        value: headerValue
      });
      console.log("[Background] Injected X-Custom-Geolocation header:", headerValue);
    } catch (err) {
      console.warn("Geolocation error:", err);
    }

    return { requestHeaders: details.requestHeaders };
  },
  { urls: ["<all_urls>"] },
  ["blocking", "requestHeaders"]
);
