document.getElementById("save").onclick = () => {
  const domains = document.getElementById("domains").value
    .split("\n")
    .map(d => d.trim())
    .filter(Boolean);
  browser.storage.sync.set({ domains });
};

browser.storage.sync.get("domains").then((data) => {
  document.getElementById("domains").value = (data.domains || []).join("\n");
});
