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
    }, 30000);
    
    function responseListener(response) {
      if (resolved) return;
      if (response && response.token) {
        resolved = true;
        clearTimeout(timeoutId);
        nativePort.onMessage.removeListener(responseListener);
        console.log("[Background] TPM Attestation received.");
        // Return both token and certificate_chain if present
        resolve({ token: response.token, certificate_chain: response.certificate_chain });
      } else if (response && response.error) {
        resolved = true;
        clearTimeout(timeoutId);
        nativePort.onMessage.removeListener(responseListener);
        console.error("[Background] TPM error:", response.error);
        reject(response.error);
      }
    }
    nativePort.onMessage.addListener(responseListener);
    // Use semicolons (;) instead of commas (,) in the payload string for attestation
    const payloadString = `lat=${lat};lon=${lon};accuracy=${accuracy};source=${source};time=${timestamp};nonce=${nonce}`;
    nativePort.postMessage({ command: "attest", payload: payloadString });
    console.log("[Background] Posted payload to native host:", payloadString);
  });
}

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
        headerValue += `;sig=${attestation.token}`;
        console.log("[Background] Attestation appended to header.");
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

// Remove lastUsedNonce and onCompleted nonce advancement logic

// If you check for 'dpi=processed_by_proxy' in any logic, change to 'waf=processed_by_proxy'.
// This includes any header checks, comments, or related logic.
