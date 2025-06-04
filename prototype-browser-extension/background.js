let targetDomains = [];

// Load domains from storage
browser.storage.sync.get("domains").then((data) => {
  targetDomains = data.domains || [];
});

// Update domains if changed
browser.storage.onChanged.addListener((changes) => {
  if (changes.domains) {
    targetDomains = changes.domains.newValue;
  }
});

// Intercept outgoing requests
browser.webRequest.onBeforeSendHeaders.addListener(
  async (details) => {
    const url = new URL(details.url);
    if (!targetDomains.includes(url.hostname)) return;

    try {
      const position = await new Promise((resolve, reject) => {
        navigator.geolocation.getCurrentPosition(resolve, reject, { timeout: 5000 });
      });

      const { latitude, longitude, accuracy } = position.coords;
      const geoHeader = `lat=${latitude};lon=${longitude};accuracy=${accuracy}`;

      details.requestHeaders.push({
        name: "X-Custom-Geolocation",
        value: geoHeader
      });
    } catch (err) {
      console.warn("Geolocation error:", err);
    }

    return { requestHeaders: details.requestHeaders };
  },
  { urls: ["<all_urls>"] },
  ["blocking", "requestHeaders"]
);
