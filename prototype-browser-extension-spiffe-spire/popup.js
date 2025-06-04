document.addEventListener('DOMContentLoaded', () => {
  const domainsTextarea = document.getElementById('domains');
  const saveButton = document.getElementById('save');
  const statusDiv = document.getElementById('status');

  // Load stored allowedDomains and update the textarea.
  browser.storage.local.get("allowedDomains").then((result) => {
    let domains = result.allowedDomains;
    if (!domains || domains.length === 0) {
      domains = ["example.com", "api.example.com"];
    }
    domainsTextarea.value = domains.join('\n');
  });

  // Save the domains back to storage when the button is clicked.
  saveButton.addEventListener('click', () => {
    let domains = domainsTextarea.value.split('\n')
      .map(domain => domain.trim())
      .filter(domain => domain.length > 0);
    browser.storage.local.set({ allowedDomains: domains })
      .then(() => {
        statusDiv.textContent = "Saved!";
        setTimeout(() => { statusDiv.textContent = ""; }, 2000);
      })
      .catch((error) => {
        statusDiv.textContent = "Error saving domains.";
        console.error("Error saving allowedDomains:", error);
      });
  });
});
