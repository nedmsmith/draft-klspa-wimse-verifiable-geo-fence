console.log("[Background] Background script loaded.");

let targetDomains = ["localhost"];
let latestPosition = null; // Global cache for the latest geolocation.
let currentNonce = null;   // Global nonce, retrieved once from the server.
let nonceReady = null;

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

// LCG implementation for deterministic random nonce
function LCG(seed) {
  this.m = 2147483648n;  // modulus 2^31 as BigInt
  this.a = 1103515245n;  // multiplier as BigInt
  this.c = 12345n;       // increment as BigInt
  this.state = BigInt(seed);
}
LCG.prototype.next = function() {
  this.state = (this.a * this.state + this.c) % this.m;
  if (this.state < 0n) this.state += this.m;
  return Number(this.state); // Return as Number for compatibility
};

let nonceGenerator = null;

//
// Fetch initial nonce from the server's /get_access_token_with_initial_nonce endpoint.
function fetchInitialNonce() {
  console.log("[Background] Fetching initial nonce...");
  nonceReady = new Promise((resolve) => {
    fetch("https://localhost:8443/get_access_token_with_initial_nonce")
      .then((response) => {
        if (!response.ok) {
          console.error(`[Background] Initial nonce fetch failed: HTTP ${response.status} ${response.statusText}`);
          throw new Error(`HTTP ${response.status} ${response.statusText}`);
        }
        return response.json();
      })
      .then((data) => {
        currentNonce = data.nonce;
        // Initialize LCG with the initial nonce
        nonceGenerator = new LCG(currentNonce);
        console.log("[Background] Initial nonce fetched from server:", currentNonce);
        resolve();
      })
      .catch((err) => {
        console.error("[Background] Error fetching initial nonce:", err);
        if (err instanceof TypeError) {
          console.error("[Background] This may be a network, CORS, or certificate trust issue.");
        }
        resolve(); // Still resolve to avoid blocking forever
      });
  });
}
fetchInitialNonce();

//
// Listen for responses from the server via onHeadersReceived.
// We’re broadening the URL filter to <all_urls> (since your extension has <all_urls> permission)
// so that we catch any 400 responses coming back. Then we log details and check if the response
// contains the custom header "X-Nonce-Error" with the expected content. If so, we call fetchInitialNonce().
browser.webRequest.onHeadersReceived.addListener(
  (details) => {
    console.log("[Background] onHeadersReceived fired for URL:", details.url, "statusCode:", details.statusCode);
    if (details.statusCode === 400) {
      const headers = details.responseHeaders || [];
      let foundHeader = false;
      for (let header of headers) {
        console.log("[Background] Checking header:", header.name, header.value);
        if (
          header.name.toLowerCase() === "x-nonce-error" &&
          header.value.includes("Nonce out-of-sync; please reinitialize nonce via /get_access_token_with_initial_nonce")
        ) {
          foundHeader = true;
          console.warn("[Background] Detected nonce out-of-sync error in response for URL:", details.url);
          fetchInitialNonce();
          break;
        }
      }
      if (!foundHeader) {
        console.log("[Background] 400 response did not contain the expected X-Nonce-Error header for URL:", details.url);
      }
    }
  },
  { urls: ["<all_urls>"] },
  ["responseHeaders"]
);

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
// Wait for latestPosition to become non-null.
// Poll every 'interval' ms and reject after 'timeout' ms.
function waitForPosition(timeout = 10000, interval = 500) {
  return new Promise((resolve, reject) => {
    const start = Date.now();
    const check = () => {
      if (latestPosition) {
        resolve(latestPosition);
      } else if (Date.now() - start > timeout) {
        reject(new Error("Timed out waiting for position"));
      } else {
        setTimeout(check, interval);
      }
    };
    check();
  });
}

// Persistent native messaging port
let nativePort = null;

// Request/response queue for TPM attestation
let tpmRequestId = 0;
const tpmPendingRequests = new Map();

function setupNativePort() {
  nativePort = browser.runtime.connectNative("com.mycompany.geosign");
  console.log("[Background] Persistent native messaging connection created.");

  nativePort.onMessage.addListener((response) => {
    console.log("[Background][NativePort] Received message from native host:", response);
    if (response && response.requestId !== undefined && tpmPendingRequests.has(response.requestId)) {
      const { resolve, reject, timeoutId } = tpmPendingRequests.get(response.requestId);
      clearTimeout(timeoutId);
      tpmPendingRequests.delete(response.requestId);
      if (response.token || (response.sig && response.cert_chain)) {
        // Accept either legacy token or new sig/cert_chain format
        console.log("[Background][NativePort] Response contains attestation, resolving.");
        resolve(response);
      } else if (response.error) {
        console.warn("[Background][NativePort] Response contains error:", response.error);
        reject(response.error);
      } else {
        console.warn("[Background][NativePort] Unknown response from native host:", response);
        reject("Unknown response from native host");
      }
    } else {
      console.warn("[Background][NativePort] Received message with unknown or missing requestId:", response);
    }
  });

  nativePort.onDisconnect.addListener(() => {
    console.warn("[Background][NativePort] Native messaging port disconnected! Attempting to reconnect in 1s...");
    setTimeout(() => {
      setupNativePort();
    }, 1000);
  });
}

setupNativePort();

//
// Intercept outgoing requests to inject the custom geolocation header.
// Uses the cached global position and the in-memory nonce.
// In onBeforeSendHeaders, move nonceGenerator.next() to after a successful server response
// We'll use a flag to track if the last request succeeded
let lastRequestSucceeded = true;

let useSeedNonce = true; // Use the seed for the very first request

let requestInFlight = false; // Prevent parallel requests

let requestCounter = 0; // Unique request ID for debugging

// Helper to get the correct nonce for each request
function getCurrentNonce() {
  requestCounter++;
  const stack = new Error().stack;
  console.debug(`[NONCE][DEBUG] getCurrentNonce() called. Request #${requestCounter}. Current LCG state: ${nonceGenerator ? nonceGenerator.state : 'N/A'}`);
  console.debug(`[NONCE][DEBUG] Stack trace for getCurrentNonce() call #${requestCounter}:\n${stack}`);
  if (useSeedNonce && nonceGenerator) {
    // Use the seed (initial state) for the first request, do NOT call .next()
    useSeedNonce = false;
    console.debug(`[NONCE] [Client] Using initial seed nonce: ${nonceGenerator.state}`);
    return nonceGenerator.state;
  } else if (nonceGenerator) {
    const before = nonceGenerator.state;
    const next = nonceGenerator.next();
    console.debug(`[NONCE] [Client] LCG advanced from state: ${before} to state: ${nonceGenerator.state}, nonce for request: ${next}`);
    return next;
  }
  return null;
}

browser.webRequest.onBeforeSendHeaders.addListener(
  async (details) => {
    const url = new URL(details.url);
    if (!targetDomains.includes(url.hostname)) return;

    if (requestInFlight) {
      console.warn("[Background] Request blocked: another geolocation request is already in flight. Skipping this request to prevent LCG desync.");
      return { requestHeaders: details.requestHeaders };
    }
    requestInFlight = true;
    try {
      // Wait for latestPosition if not available.
      if (!latestPosition) {
        try {
          console.log("[Background] Waiting for a valid position...");
          await waitForPosition();
          console.log("[Background] Position obtained after waiting.");
        } catch (err) {
          console.warn("[Background] Position not available after waiting; skipping header injection.");
          return { requestHeaders: details.requestHeaders };
        }
      }
      // Wait for nonce to be ready
      if (nonceReady) await nonceReady;
      if (currentNonce === null) {
        console.warn("[Background] No nonce available after waiting; skipping header injection.");
        return { requestHeaders: details.requestHeaders };
      }
      const { latitude, longitude, accuracy } = latestPosition.coords;
      console.log(`[Background] Using cached position: lat=${latitude}, lon=${longitude}, accuracy=${accuracy}`);
      const timestamp = new Date().toISOString();
      console.log(`[Background] Timestamp: ${timestamp}`);
      
      // Always use next nonce for outgoing requests
      let nonceToUse = getCurrentNonce();
      console.log(`[Background] Nonce used: ${nonceToUse}`);
      if (nonceGenerator) {
        console.debug(`[NONCE] [Client] LCG state after getCurrentNonce(): ${nonceGenerator.state}`);
      }
      const source = guessLocationSource(accuracy);
      console.log(`[Background] Computed source: ${source}`);
      let headerValue = `lat=${latitude};lon=${longitude};accuracy=${accuracy};time=${timestamp};nonce=${nonceToUse};source=${source}`;
      try {
        const attestation = await getTPMAttestation(latitude, longitude, accuracy, source, timestamp, nonceToUse);
        console.log("[Background][DEBUG] Full attestation object before header append:", attestation);
        // Append payload, sig, and cert_chain as separate fields (new protocol)
        if (attestation.payload) {
          headerValue += `;payload=${encodeURIComponent(attestation.payload)}`;
        }
        if (attestation.sig) {
          headerValue += `;sig=${encodeURIComponent(attestation.sig)}`;
        }
        if (attestation.cert_chain) {
          headerValue += `;cert_chain=${encodeURIComponent(attestation.cert_chain)}`;
        }
        // Extract phone fields from mobile_phone_identity if present
        const phoneIdentity = attestation.mobile_phone_identity || {};
        if (phoneIdentity.name && !headerValue.includes('tethered_phone_name=')) {
          headerValue += `;tethered_phone_name=${encodeURIComponent(phoneIdentity.name)}`;
        }
        if (phoneIdentity.tethered_phone_mac && !headerValue.includes('tethered_phone_mac=')) {
          headerValue += `;tethered_phone_mac=${encodeURIComponent(phoneIdentity.tethered_phone_mac)}`;
        } else if (phoneIdentity.bluetooth_bd_addr && !headerValue.includes('tethered_phone_mac=')) {
          headerValue += `;tethered_phone_mac=${encodeURIComponent(phoneIdentity.bluetooth_bd_addr)}`;
        }
        if (phoneIdentity.tethered_phone_match_type && !headerValue.includes('tethered_phone_match_type=')) {
          headerValue += `;tethered_phone_match_type=${encodeURIComponent(phoneIdentity.tethered_phone_match_type)}`;
        }
        // Always include mobile_phone_identity as a JSON string in the header
        if (Object.keys(phoneIdentity).length > 0 && !headerValue.includes('mobile_phone_identity=')) {
          headerValue += `;mobile_phone_identity=${encodeURIComponent(JSON.stringify(phoneIdentity))}`;
        }
        console.log("[Background][DEBUG] After appending phone info: headerValue=", headerValue);
        console.log("[Background] Attestation appended to header.");

        // Extra debug: log attestation object and headerValue before sending
        console.log("[Background][DEBUG][EXTRA] Attestation object:", JSON.stringify(attestation, null, 2));
        console.log("[Background][DEBUG][EXTRA] Final headerValue before send:", headerValue);
      } catch (attestError) {
        console.warn("[Background] TPM attestation error:", attestError);
      }
      details.requestHeaders.push({ name: "X-Custom-Geolocation", value: headerValue });
      console.log("[Background] Injected X-Custom-Geolocation header:", headerValue);
      return { requestHeaders: details.requestHeaders };
    } finally {
      requestInFlight = false;
    }
  },
  { urls: ["<all_urls>"] },
  ["blocking", "requestHeaders"]
);

function getTPMAttestation(lat, lon, accuracy, source, timestamp, nonce) {
  console.log(
    `[Background] Requesting TPM Attestation for lat:${lat}, lon:${lon}, accuracy:${accuracy}, source:${source}, time:${timestamp}, nonce:${nonce}`
  );
  return new Promise((resolve, reject) => {
    const requestId = tpmRequestId++;
    const timeoutId = setTimeout(() => {
      if (tpmPendingRequests.has(requestId)) {
        tpmPendingRequests.delete(requestId);
        reject("Timeout waiting for TPM attestation");
      }
    }, 30000);
    tpmPendingRequests.set(requestId, { resolve, reject, timeoutId });
    const payloadString = `lat=${lat};lon=${lon};accuracy=${accuracy};source=${source};time=${timestamp};nonce=${nonce}`;
    nativePort.postMessage({ command: "attest", payload: payloadString, requestId });
    console.log("[Background][NativePort] Sent postMessage to native host:", { command: "attest", payload: payloadString, requestId });
  });
}

// Remove lastUsedNonce and onCompleted nonce advancement logic

// If you check for 'dpi=processed_by_proxy' in any logic, change to 'waf=processed_by_proxy'.
// This includes any header checks, comments, or related logic.
