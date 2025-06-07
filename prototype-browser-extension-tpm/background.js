let targetDomains = ["localhost"];
let latestPosition = null;  // Global cache for the current geolocation

// Retrieve domains from storage.
browser.storage.sync.get("domains").then((data) => {
  targetDomains = data.domains || targetDomains;
});

// Listen for storage changes.
browser.storage.onChanged.addListener((changes) => {
  if (changes.domains) {
    targetDomains = changes.domains.newValue;
  }
});

/**
 * Determines the likely location source based on accuracy.
 * Returns "GPS" if ≤10, "Wi-Fi" if ≤100, "Cellular" if ≤250, else "IP-based".
 */
function guessLocationSource(accuracy) {
  if (accuracy <= 10) return "GPS";
  else if (accuracy <= 100) return "Wi-Fi";
  else if (accuracy <= 250) return "Cellular";
  else return "IP-based";
}

/**
 * Retrieves an incremental nonce from persistent storage.
 */
function getIncrementalNonce() {
  return browser.storage.local.get("nonceCounter").then((data) => {
    let nonce = data.nonceCounter || 1;
    const currentNonce = nonce;
    return browser.storage.local.set({ nonceCounter: nonce + 1 }).then(() => currentNonce);
  });
}

/**
 * Polls for geolocation using high-accuracy options.
 * This function updates the global `latestPosition` variable.
 */
function updatePosition() {
  navigator.geolocation.getCurrentPosition(
    (position) => {
      latestPosition = position;
      console.log(
        `[Background] Position updated: lat=${position.coords.latitude}, lon=${position.coords.longitude}, accuracy=${position.coords.accuracy}`
      );
    },
    (error) => {
      console.warn("[Background] Error updating position:", error);
    },
    {
      enableHighAccuracy: true,
      timeout: 10000, // 10 seconds timeout for precise location
      maximumAge: 0
    }
  );
}

// Update geolocation immediately and then every 30 seconds.
updatePosition();
setInterval(updatePosition, 30000);

/**
 * Requests a TPM attestation from the native messaging host for the provided values.
 */
function getTPMAttestation(lat, lon, accuracy, source, timestamp, nonce) {
  console.log(
    `[Background] Requesting TPM Attestation for lat:${lat}, lon:${lon}, accuracy:${accuracy}, source:${source}, time:${timestamp}, nonce:${nonce}`
  );
  return new Promise((resolve, reject) => {
    const nativePort = browser.runtime.connectNative("com.mycompany.geosign");
    console.log("[Background] Native messaging connection created.");
    
    let resolved = false;
    const timeoutId = setTimeout(() => {
      if (!resolved) {
        resolved = true;
        nativePort.onMessage.removeListener(responseListener);
        console.error("[Background] Timeout waiting for TPM attestation.");
        reject("Timeout waiting for TPM attestation");
      }
    }, 30000); // 30-second timeout

    function responseListener(response) {
      if (resolved) return;
      if (response && response.token) {
        resolved = true;
        clearTimeout(timeoutId);
        nativePort.onMessage.removeListener(responseListener);
        console.log("[Background] TPM Attestation received.");
        resolve({ token: response.token });
      } else if (response && response.error) {
        resolved = true;
        clearTimeout(timeoutId);
        nativePort.onMessage.removeListener(responseListener);
        console.error("[Background] TPM error:", response.error);
        reject(response.error);
      }
    }
    nativePort.onMessage.addListener(responseListener);

    const payloadString = `lat=${lat},lon=${lon},accuracy=${accuracy},source=${source},time=${timestamp},nonce=${nonce}`;
    nativePort.postMessage({ command: "attest", payload: payloadString });
    console.log("[Background] Posted payload to native host:", payloadString);
  });
}

/**
 * Intercepts outgoing requests to inject the custom geolocation header.
 * Uses the cached global position (updated every 30 seconds) for efficiency.
 */
browser.webRequest.onBeforeSendHeaders.addListener(
  async (details) => {
    const url = new URL(details.url);
    if (!targetDomains.includes(url.hostname)) return;
    
    if (!latestPosition) {
      console.warn("[Background] No cached position available; skipping header injection.");
      return { requestHeaders: details.requestHeaders };
    }
    
    const { latitude, longitude, accuracy } = latestPosition.coords;
    console.log(`[Background] Using cached position: lat=${latitude}, lon=${longitude}, accuracy=${accuracy}`);
    
    const timestamp = new Date().toISOString();
    console.log(`[Background] Timestamp: ${timestamp}`);
    
    const nonce = await getIncrementalNonce();
    console.log(`[Background] Nonce: ${nonce}`);
    
    const source = guessLocationSource(accuracy);
    console.log(`[Background] Computed source: ${source}`);
    
    let headerValue = `lat=${latitude};lon=${longitude};accuracy=${accuracy};time=${timestamp};nonce=${nonce};source=${source}`;
    
    try {
      const attestation = await getTPMAttestation(latitude, longitude, accuracy, source, timestamp, nonce);
      headerValue += `;sig=${attestation.token}`;
      console.log("[Background] Attestation appended to header.");
    } catch (attestError) {
      console.warn("[Background] TPM attestation error:", attestError);
    }
    
    details.requestHeaders.push({ name: "X-Custom-Geolocation", value: headerValue });
    console.log("[Background] Injected X-Custom-Geolocation header:", headerValue);
    return { requestHeaders: details.requestHeaders };
  },
  { urls: ["<all_urls>"] },
  ["blocking", "requestHeaders"]
);
