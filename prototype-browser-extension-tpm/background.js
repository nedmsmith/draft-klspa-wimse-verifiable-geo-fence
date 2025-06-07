let targetDomains = ["localhost"];
let latestPosition = null; // Global cache for the latest geolocation.
let currentNonce = null;   // Global nonce, retrieved once from the server.

//
// Retrieve target domains from storage.
browser.storage.sync.get("domains").then((data) => {
  targetDomains = data.domains || targetDomains;
});
browser.storage.onChanged.addListener((changes) => {
  if (changes.domains) {
    targetDomains = changes.domains.newValue;
  }
});

//
// Fetch initial nonce from the server's /init_nonce endpoint.
function fetchInitialNonce() {
  // Adjust the URL to point to your server (e.g., using https://127.0.0.1:8443/init_nonce).
  fetch("https://127.0.0.1:8443/init_nonce")
    .then((response) => response.json())
    .then((data) => {
      currentNonce = data.nonce;
      console.log("[Background] Initial nonce fetched from server:", currentNonce);
    })
    .catch((err) => {
      console.error("[Background] Error fetching initial nonce:", err);
    });
}
fetchInitialNonce();

//
// Determine the likely location source based on accuracy.
function guessLocationSource(accuracy) {
  if (accuracy <= 10) return "GPS";
  else if (accuracy <= 100) return "Wi-Fi";
  else if (accuracy <= 250) return "Cellular";
  else return "IP-based";
}

//
// Poll for geolocation using high-accuracy options and update the global position.
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
      timeout: 10000, // 10 sec timeout for precise location.
      maximumAge: 0,
    }
  );
}
updatePosition();
setInterval(updatePosition, 30000); // Update every 30 seconds.

//
// Request TPM attestation from the native messaging host.
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
    }, 30000); // 30-sec timeout.

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

//
// Intercept outgoing requests to inject the custom geolocation header.
// Uses the cached global position and the in-memory nonce.
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

    // Use the in-memory nonce fetched from the server.
    if (currentNonce === null) {
      console.warn("[Background] No nonce available; skipping header injection.");
      return { requestHeaders: details.requestHeaders };
    }
    // Save the value to use and then increment locally.
    let nonceToUse = currentNonce;
    currentNonce++; 
    console.log(`[Background] Nonce used: ${nonceToUse}, new local nonce: ${currentNonce}`);

    const source = guessLocationSource(accuracy);
    console.log(`[Background] Computed source: ${source}`);

    let headerValue = `lat=${latitude};lon=${longitude};accuracy=${accuracy};time=${timestamp};nonce=${nonceToUse};source=${source}`;

    try {
      const attestation = await getTPMAttestation(latitude, longitude, accuracy, source, timestamp, nonceToUse);
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
