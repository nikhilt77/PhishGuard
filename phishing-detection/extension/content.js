let warnedUrls = new Set();
function checkCurrentURL(){
  const url = window.location.href;
  if(!url.startsWith('http')){
    return;
  }
  if(warnedUrls.has(url)){
    return;
  }
  chrome.runtime.sendMessage(
      {action: "checkURL", url: url},
      (response) => {
        if (response && response.prediction === "Phishing") {
          if (response.source === "blacklist" || response.probability > 75) {
            showPhishingWarning(response, url);
            warnedUrls.add(url);
          }
        }
      }
    );
  }

  // Show warning for high-confidence phishing sites with continue anyway option
  function showPhishingWarning(result, url) {
    // Create warning element
    const warningDiv = document.createElement('div');
    warningDiv.id = 'phishguard-warning';
    warningDiv.style.cssText = `
      position: fixed;
      top: 0;
      left: 0;
      width: 100%;
      background-color: #ff3b30;
      color: white;
      padding: 15px;
      text-align: center;
      font-size: 16px;
      z-index: 9999999;
      font-family: Arial, sans-serif;
      box-shadow: 0 2px 10px rgba(0, 0, 0, 0.2);
    `;

    // Content varies based on source (blacklist vs model prediction)
    const warningSource = result.source === "blacklist"
      ? "This site is in your blacklist."
      : `Our AI models indicate this site may be attempting to steal your information. Confidence: ${result.probability.toFixed(1)}%`;

    warningDiv.innerHTML = `
      <div style="max-width: 960px; margin: 0 auto; display: flex; align-items: center; justify-content: space-between;">
        <div style="display: flex; align-items: center;">
          <span style="font-size: 24px; margin-right: 10px;">⚠️</span>
          <div>
            <strong>Warning: Potential Phishing Site Detected!</strong>
            <p style="margin: 5px 0 0 0; font-size: 14px;">
              ${warningSource}
            </p>
          </div>
        </div>
        <div>
          <button id="phishguard-details" style="background: rgba(255,255,255,0.2); border: none; color: white; padding: 5px 10px; margin-right: 10px; cursor: pointer; border-radius: 4px;">Details</button>
          <button id="phishguard-continue" style="background: rgba(255,255,255,0.2); border: none; color: white; padding: 5px 10px; margin-right: 10px; cursor: pointer; border-radius: 4px;">Continue Anyway</button>
          <button id="phishguard-dismiss" style="background: rgba(255,255,255,0.2); border: none; color: white; padding: 5px 10px; cursor: pointer; border-radius: 4px;">Dismiss</button>
        </div>
      </div>
    `;

    // Add to page
    document.body.prepend(warningDiv);

    // Add event listeners
    document.getElementById('phishguard-dismiss').addEventListener('click', () => {
      warningDiv.remove();
    });

    document.getElementById('phishguard-details').addEventListener('click', () => {
      chrome.runtime.sendMessage({action: "openPopup"});
    });

    document.getElementById('phishguard-continue').addEventListener('click', () => {
      // Ask if user wants to add to whitelist
      if (confirm("Do you want to add this site to your whitelist? This will prevent future warnings for this site.")) {
        chrome.runtime.sendMessage({
          action: "addToWhitelist",
          url: url,
          notes: "User manually continued despite warning"
        });
      }
      warningDiv.remove();
    });
  }

  // Run when page loads
  window.addEventListener('load', checkCurrentURL);

  // Listen for messages from background script
  chrome.runtime.onMessage.addListener((request, sender, sendResponse) => {
    if (request.action === "pageLoaded") {
      checkCurrentURL();
    }
    return true;
  });
