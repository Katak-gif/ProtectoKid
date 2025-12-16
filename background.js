// MV3 service worker — reply to content with structured UI copy.
chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
  if (message && message.type === "prediction") {
    const { prediction } = message; // -1 safe, 0 suspicious, 1 malicious
    let status = "safe";
    let title = "No Issues Detected";
    let sub = "This website is safe.";
    if (prediction === 0) {
      status = "suspicious";
      title = "Suspicious Activity";
      sub = "Proceed with caution.";
    } else if (prediction === 1) {
      status = "malicious";
      title = "Malicious Site Detected";
      sub = "This website may be unsafe.";
    }
    sendResponse({ status, title, sub });
    return true;
  }
});
