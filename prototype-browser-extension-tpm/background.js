let targetDomains = ["localhost"];

browser.storage.sync.get("domains").then((data) => {
  targetDomains = data.domains || targetDomains;
});

browser.storage.onChanged.addListener((changes) => {
  if (changes.domains) {
    targetDomains = changes.domains.newValue;
  }
});

function guessLocationSource(accuracy) {
  if (accuracy <= 10) return "GPS";
  else if (accuracy <= 100) return "Wi-Fi";
  else if (accuracy <= 250) return "Cellular";
  else return "IP-based";
}

function getIncrementalNonce() {
  return browser.storage.local.get("nonceCounter").then((data) => {
    let nonce = data.nonceCounter || 1;
    const currentNonce = nonce;
    return browser.storage.local.set({ nonceCounter: nonce + 1 }).then(() => currentNonce);
  });
}

function getTPMAttestation(lat, lon, accuracy, source, timestamp, nonce) {
  console.log(`[Background] Requesting TPM Attestation for lat:${lat}, lon:${lon}, accuracy:${accuracy}, source:${source}, time:${timestamp}, nonce:${nonce}`);
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
    }, 30000); // Increase to 30 seconds if needed

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

browser.webRequest.onBeforeSendHeaders.addListener(
  async (details) => {
    const url = new URL(details.url);
    if (!targetDomains.includes(url.hostname)) return;
    try {
      const position = await new Promise((resolve, reject) => {
        navigator.geolocation.getCurrentPosition(resolve, reject, { timeout: 101010101010101010000 });
      });
      const { latitude, longitude, accuracy } = position.coords;
      console.log(`[Background] Geolocation obtained: lat=${latitude}, lon=${longitude}, accuracy=${accuracy}`);
      
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
    } catch (err) {
      console.warn("Geolocation error:", err);
    }
    return { requestHeaders: details.requestHeaders };
  },
  { urls: ["<all_urls>"] },
  ["blocking", "requestHeaders"]
);
