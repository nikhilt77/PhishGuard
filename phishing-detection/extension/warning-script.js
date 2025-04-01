document.addEventListener("DOMContentLoaded", function () {
  let warnedUrl = "";

  // Show the navigation status element
  function showStatus(message) {
    const statusEl = document.getElementById("navigation-status");
    statusEl.textContent = message;
    statusEl.style.display = "block";
  }

  // Load the suspicious URL information
  chrome.storage.local.get(["warned_url", "phishing_data"], function (data) {
    warnedUrl = data.warned_url || "";

    if (warnedUrl) {
      document.getElementById("warned-url").textContent = warnedUrl;

      // Store the URL in sessionStorage as a fallback
      try {
        sessionStorage.setItem("phishguard_proceed_url", warnedUrl);
      } catch (e) {
        console.error("Could not store URL in sessionStorage:", e);
      }
    }

    if (data.phishing_data) {
      const result = data.phishing_data;
      document.getElementById("probability").textContent = result.probability
        ? result.probability.toFixed(1) + "%"
        : "Unknown";

      document.getElementById("detection-method").textContent =
        result.blend_method || "Machine learning analysis";

      // Set risk level text based on probability
      if (result.probability > 80 || result.source === "blacklist") {
        document.getElementById("risk-level").textContent = "Very High";
        document.getElementById("risk-level").style.color = "#FF0000";
      } else if (result.probability > 65) {
        document.getElementById("risk-level").textContent = "High";
        document.getElementById("risk-level").style.color = "#FF3B30";
      } else {
        document.getElementById("risk-level").textContent = "Medium";
        document.getElementById("risk-level").style.color = "#FF9500";
      }
    }
  });

  // Set up back button with multiple fallback methods
  document.getElementById("back-button").addEventListener("click", function () {
    // Try to go back in history first
    if (window.history.length > 1) {
      window.history.back();
    } else {
      // Fallback - create a new tab if history isn't available
      chrome.tabs.create({});
    }
  });

  // Set up Google homepage button
  document.getElementById("home-button").addEventListener("click", function () {
    chrome.tabs.update({ url: "https://www.google.com" });
  });

  // ULTRA DIRECT NAVIGATION APPROACH
  function ultraDirectNavigation(url) {
    // 0. Create a clickable link and click it (most reliable in some contexts)
    try {
      const a = document.createElement("a");
      a.href = url;
      a.target = "_self"; // Same tab
      a.style.display = "none";
      document.body.appendChild(a);
      a.click();
      document.body.removeChild(a);
      return true;
    } catch (e) {
      console.error("Link click navigation failed:", e);
    }

    // 1. Try window.location direct change
    try {
      window.location.href = url;
      return true;
    } catch (e) {
      console.error("window.location navigation failed:", e);
    }

    // 2. Try window.location.replace
    try {
      window.location.replace(url);
      return true;
    } catch (e) {
      console.error("window.location.replace failed:", e);
    }

    // 3. Try window.open
    try {
      window.open(url, "_self");
      return true;
    } catch (e) {
      console.error("window.open failed:", e);
    }

    // 4. Try document.location
    try {
      document.location.href = url;
      return true;
    } catch (e) {
      console.error("document.location failed:", e);
    }

    return false;
  }

  // Set up proceed anyway button - EXTREME MULTI-FALLBACK VERSION
  document
    .getElementById("proceed-button")
    .addEventListener("click", function () {
      const proceedButton = document.getElementById("proceed-button");
      proceedButton.textContent = "Proceeding...";
      proceedButton.disabled = true;

      // Get the URL from multiple sources
      let targetUrl = warnedUrl;

      // Fallback to sessionStorage if needed
      if (!targetUrl) {
        try {
          targetUrl = sessionStorage.getItem("phishguard_proceed_url");
        } catch (e) {
          console.error("Failed to get URL from sessionStorage:", e);
        }
      }

      if (!targetUrl) {
        console.error("No URL to proceed to!");
        proceedButton.textContent = "Error - Reload Page";
        proceedButton.disabled = false;
        return;
      }

      console.log("PROCEEDING TO:", targetUrl);
      showStatus("Attempting to navigate to site...");

      // APPROACH 1: Try messaging the background script
      let proceeded = false;
      try {
        chrome.runtime.sendMessage(
          {
            action: "proceedAnyway",
            url: targetUrl,
          },
          function (response) {
            if (chrome.runtime.lastError) {
              console.warn(
                "Background script messaging failed:",
                chrome.runtime.lastError,
              );
              showStatus("Trying alternate navigation method...");
            } else if (response && response.success) {
              proceeded = true;
              console.log("Successfully proceeded via background script");
              showStatus("Navigation successful!");
            }
          },
        );
      } catch (e) {
        console.error("Message sending failed:", e);
        showStatus("Communication error, trying direct navigation...");
      }

      // APPROACH 2: Try chrome.tabs direct API access
      setTimeout(function () {
        if (!proceeded) {
          try {
            chrome.tabs.getCurrent(function (tab) {
              if (tab && tab.id) {
                chrome.tabs.update(tab.id, { url: targetUrl });
                proceeded = true;
                showStatus("Navigation via tabs API successful!");
              } else {
                showStatus("Tab ID not found, trying next method...");
              }
            });
          } catch (e) {
            console.error("Chrome tabs update failed:", e);
            showStatus("Tabs API failed, trying direct methods...");
          }
        }
      }, 300);

      // APPROACH 3: Ultra direct navigation methods as final fallback
      setTimeout(function () {
        if (!proceeded) {
          console.log("Trying ultra direct navigation...");
          showStatus("Attempting direct browser navigation...");
          proceeded = ultraDirectNavigation(targetUrl);

          if (proceeded) {
            showStatus("Direct navigation initiated!");
          } else {
            showStatus(
              "All automatic methods failed. Please use the direct link below.",
            );
          }
        }
      }, 600);

      // Show the direct navigation link regardless, as a guaranteed fallback
      setTimeout(function () {
        const container = document.getElementById(
          "direct-navigation-container",
        );
        const link = document.getElementById("direct-proceed-link");

        link.href = targetUrl;
        container.style.display = "block";

        if (!proceeded) {
          showStatus("Please use the direct link below to proceed.");
          proceedButton.textContent = "Navigation Failed";
        }
      }, 800);
    });

  // Set up direct proceed link
  setTimeout(function () {
    const link = document.getElementById("direct-proceed-link");

    if (warnedUrl) {
      link.href = warnedUrl;
    }
  }, 200);
});
