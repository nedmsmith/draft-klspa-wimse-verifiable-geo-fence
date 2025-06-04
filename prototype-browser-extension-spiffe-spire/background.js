// Initialize with a default list; this will be overwritten if stored values exist.
let allowedDomains = ["localhost", "api.example.com"];
let currentGeoToken = ""; // Will hold the signed geolocation value

// Load allowedDomains from storage on startup.
function loadAllowedDomains() {
  browser.storage.local.get("allowedDomains").then((result) => {
    if (result.allowedDomains && result.allowedDomains.length > 0) {
      allowedDomains = result.allowedDomains;
    }
    console.log("Loaded allowedDomains:", allowedDomains);
  });
}
loadAllowedDomains();

// Listen for changes to update allowedDomains when the user configures them.
browser.storage.onChanged.addListener((changes, area) => {
  if (area === "local" && changes.allowedDomains) {
    allowedDomains = changes.allowedDomains.newValue;
    console.log("Updated allowedDomains:", allowedDomains);
  }
});

// Open a connection to the native messaging host.
let nativePort = browser.runtime.connectNative("com.mycompany.geosign");

// Listen for messages from native host, which send back a signed payload.
nativePort.onMessage.addListener((response) => {
  if (response.token) {
    currentGeoToken = response.token;
    console.log("Received updated geo token:", currentGeoToken);
  }
});

// Periodically update geolocation and refresh token every 60 seconds.
function updateGeoToken() {
  navigator.geolocation.getCurrentPosition((position) => {
    const { latitude, longitude, accuracy } = position.coords;
    let message = { lat: latitude, lon: longitude, accuracy: accuracy };
    nativePort.postMessage(message);
  }, (error) => {
    console.error("Error obtaining geolocation:", error);
  }, {
    enableHighAccuracy: true,
    timeout: 5000,
    maximumAge: 10000
  });
}

updateGeoToken();
setInterval(updateGeoToken, 60000); // update every 60 seconds

// Intercept outgoing HTTPS requests and inject the header if the domain is allowed.
function onBeforeSendHeaders(details) {
  try {
    let url = new URL(details.url);
    if (allowedDomains.some(domain => url.host.endsWith(domain))) {
      if (currentGeoToken && currentGeoToken.length > 0) {
        details.requestHeaders.push({
          name: "X-Geo-Sign",
          value: currentGeoToken
        });
      }
    }
  } catch (e) {
    console.error("Error processing URL", details.url, e);
  }
  return { requestHeaders: details.requestHeaders };
}

browser.webRequest.onBeforeSendHeaders.addListener(
  onBeforeSendHeaders,
  { urls: ["https://*/*"] },
  ["blocking", "requestHeaders"]
);
