let geoHeaderDomains = [];

chrome.storage.sync.get(["geoDomains"], (result) => {
  geoHeaderDomains = result.geoDomains || [];
});

chrome.storage.onChanged.addListener((changes) => {
  if (changes.geoDomains) {
    geoHeaderDomains = changes.geoDomains.newValue;
  }
});

chrome.webRequest.onBeforeSendHeaders.addListener(
  async (details) => {
    const url = new URL(details.url);
    if (!geoHeaderDomains.includes(url.hostname)) return;

    return new Promise((resolve) => {
      navigator.geolocation.getCurrentPosition((position) => {
        const { latitude, longitude, accuracy } = position.coords;
        const geoValue = `${latitude},${longitude};accuracy=${accuracy}`;
        details.requestHeaders.push({
          name: "X-Geo-Location",
          value: geoValue
        });
        resolve({ requestHeaders: details.requestHeaders });
      }, () => {
        resolve({ requestHeaders: details.requestHeaders });
      });
    });
  },
  { urls: ["<all_urls>"] },
  ["blocking", "requestHeaders", "extraHeaders"]
);
