let predictionCache = {};
let blacklist = [];
let whitelist = [];
let pendingRedirects = {};

// ===============================
//  1) LOAD LISTS WHEN SERVICE WORKER STARTS
// ===============================

loadListsFromStorage();

// Optionally also load on install or on startup
chrome.runtime.onInstalled.addListener(() => {
  loadListsFromStorage();
});

// If you want to load again each time Chrome restarts:
if (chrome.runtime.onStartup) {
  chrome.runtime.onStartup.addListener(() => {
    loadListsFromStorage();
  });
}

// ===============================
//  2) HELPER FUNCTIONS
// ===============================

// Load from chrome.storage.local
function loadListsFromStorage() {
  chrome.storage.local.get(["blacklist", "whitelist"], (result) => {
    blacklist = result.blacklist || [];
    whitelist = result.whitelist || [];
    console.log("Loaded lists from storage:", {
      blacklistCount: blacklist.length,
      whitelistCount: whitelist.length,
    });
  });
}

// Save to chrome.storage.local
function saveLists() {
  chrome.storage.local.set(
    {
      blacklist: blacklist,
      whitelist: whitelist,
    },
    () => {
      console.log("Lists saved to storage:", {
        blacklistCount: blacklist.length,
        whitelistCount: whitelist.length,
      });
    },
  );
}

// Check if a URL is in a given list
function isUrlInList(url, list) {
  // Normalize URL for comparison (remove protocol, www, trailing slash)
  const normalizedUrl = url
    .replace(/^https?:\/\//, "")
    .replace(/^www\./, "")
    .replace(/\/$/, "");

  return list.some((item) => {
    const normalizedItem = item.url
      .replace(/^https?:\/\//, "")
      .replace(/^www\./, "")
      .replace(/\/$/, "");

    return (
      normalizedUrl === normalizedItem ||
      normalizedUrl.startsWith(normalizedItem + "/") ||
      normalizedItem.startsWith(normalizedUrl + "/")
    );
  });
}

// Add a URL to either blacklist or whitelist
function addToList(url, isPhishing, timestamp = Date.now(), notes = "") {
  const entry = {
    url,
    timestamp,
    notes,
    addedBy: "user", // Or "system" if added automatically
  };

  if (isPhishing) {
    // Add to blacklist if not already present
    if (!isUrlInList(url, blacklist)) {
      blacklist.push(entry);
      // Remove from whitelist if present
      whitelist = whitelist.filter((item) => !isUrlInList(item.url, [entry]));
    }
  } else {
    // Add to whitelist if not already present
    if (!isUrlInList(url, whitelist)) {
      whitelist.push(entry);
      // Remove from blacklist if present
      blacklist = blacklist.filter((item) => !isUrlInList(item.url, [entry]));
    }
  }

  // IMPORTANT: Save after each update
  saveLists();
}

// ===============================
//  3) MAIN URL CHECK LOGIC
// ===============================

// The main function that checks a URL
async function checkUrl(url) {
  // 1. Check blacklist
  if (isUrlInList(url, blacklist)) {
    console.log("URL found in blacklist:", url);
    return {
      prediction: "Phishing",
      probability: 100,
      source: "blacklist",
      note: "This URL was manually added to your blacklist",
    };
  }

  // 2. Check whitelist
  if (isUrlInList(url, whitelist)) {
    console.log("URL found in whitelist:", url);
    return {
      prediction: "Legitimate",
      probability: 0,
      source: "whitelist",
      note: "This URL was manually added to your whitelist",
    };
  }

  // 3. Check in-memory cache
  if (predictionCache[url]) {
    console.log("Using cached prediction for:", url);
    return predictionCache[url];
  }

  // 4. If not in any list or cache, call the API
  try {
    const result = await fetchPrediction(url);
    predictionCache[url] = result;

    // Auto-add if high confidence
    if (result.probability > 90 && result.prediction === "Phishing") {
      addToList(
        url,
        true,
        Date.now(),
        "Automatically added - high confidence phishing",
      );
    } else if (result.probability < 10 && result.prediction === "Legitimate") {
      addToList(
        url,
        false,
        Date.now(),
        "Automatically added - high confidence legitimate",
      );
    }

    return result;
  } catch (error) {
    console.error("Error checking URL:", error);
    return {
      prediction: "Error",
      probability: 50,
      error: error.message,
    };
  }
}

// Call the backend ML API
async function fetchPrediction(url) {
  const response = await fetch("http://localhost:5000/predict", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({
      url: url,
      adaptive: true,
    }),
  });

  if (!response.ok) {
    throw new Error(`API error: ${response.status}`);
  }

  return await response.json();
}

// Update the extension badge
function updateBadge(tabId, result) {
  if (!tabId) return;

  let badgeText = "";
  let badgeColor = "#888888";

  if (result.prediction === "Phishing") {
    if (result.source === "blacklist") {
      badgeText = "B!";
      badgeColor = "#000000";
    } else if (result.probability > 80) {
      badgeText = "⚠️";
      badgeColor = "#FF0000";
    } else if (result.probability > 60) {
      badgeText = "!";
      badgeColor = "#FFA500";
    } else {
      badgeText = "?";
      badgeColor = "#FFCC00";
    }
  } else if (result.prediction === "Legitimate") {
    if (result.source === "whitelist") {
      badgeText = "W";
      badgeColor = "#4CAF50";
    } else if (result.probability < 20) {
      badgeText = "✓";
      badgeColor = "#00AA00";
    } else {
      badgeText = "✓";
      badgeColor = "#00CC00";
    }
  } else {
    badgeText = "?";
    badgeColor = "#888888";
  }

  chrome.action.setBadgeText({ text: badgeText, tabId });
  chrome.action.setBadgeBackgroundColor({ color: badgeColor, tabId });
}

// ===============================
//  4) LISTEN FOR MESSAGES & TAB UPDATES
// ===============================

chrome.runtime.onMessage.addListener((request, sender, sendResponse) => {
  if (request.action === "checkURL") {
    const url = request.url;
    const tabId = sender?.tab?.id;

    checkUrl(url).then((result) => {
      sendResponse(result);
      updateBadge(tabId, result);
    });
    return true; // Must return true for async response
  } else if (request.action === "getDetails") {
    const url = request.url;
    checkUrl(url).then((result) => {
      sendResponse(result);
    });
    return true;
  } else if (request.action === "addToBlacklist") {
    addToList(request.url, true, Date.now(), request.notes || "");
    sendResponse({ success: true });

    // Update badge for the current tab
    chrome.tabs.query({ active: true, currentWindow: true }, (tabs) => {
      const tabId = tabs[0]?.id;
      if (tabId) {
        updateBadge(tabId, {
          prediction: "Phishing",
          probability: 100,
          source: "blacklist",
        });
      }
    });

    return true;
  } else if (request.action === "addToWhitelist") {
    addToList(request.url, false, Date.now(), request.notes || "");
    sendResponse({ success: true });

    // Update badge for the current tab
    chrome.tabs.query({ active: true, currentWindow: true }, (tabs) => {
      const tabId = tabs[0]?.id;
      if (tabId) {
        updateBadge(tabId, {
          prediction: "Legitimate",
          probability: 0,
          source: "whitelist",
        });
      }
    });

    return true;
  } else if (request.action === "getLists") {
    sendResponse({
      blacklist: blacklist,
      whitelist: whitelist,
    });
    return true;
  } else if (request.action === "removeFromList") {
    const { url, listType } = request;
    if (listType === "blacklist") {
      blacklist = blacklist.filter((item) => !isUrlInList(url, [item]));
    } else if (listType === "whitelist") {
      whitelist = whitelist.filter((item) => !isUrlInList(url, [item]));
    }
    saveLists();
    sendResponse({ success: true });
    return true;
  } else if (request.action === "clearCache") {
    predictionCache = {};
    sendResponse({ success: true });
    return true;
  } else if (request.action === "proceedAnyway") {
    // Handle user choosing to proceed to a warned site
    const { url } = request;
    if (!url) {
      console.error("proceedAnyway called without a URL");
      sendResponse({ success: false, error: "No URL provided" });
      return true;
    }

    // Log the action
    console.log(`User chose to proceed to warned site: ${url}`);

    // Mark URL as whitelisted temporarily to avoid re-detection
    predictionCache[url] = {
      prediction: "Legitimate",
      probability: 30,
      source: "user_override",
      note: "User chose to proceed despite warning",
    };

    // Multiple approaches to navigate:
    try {
      // Approach 1: Use sender tab if available
      if (sender && sender.tab && sender.tab.id) {
        chrome.tabs.update(sender.tab.id, { url: url });
        sendResponse({ success: true });
        return true;
      }

      // Approach 2: Query for active tab and update it
      chrome.tabs.query({ active: true, currentWindow: true }, function (tabs) {
        if (tabs && tabs.length > 0) {
          chrome.tabs.update(tabs[0].id, { url: url });
          sendResponse({ success: true });
        } else {
          // Approach 3: Create new tab as last resort
          chrome.tabs.create({ url: url });
          sendResponse({ success: true });
        }
      });
    } catch (error) {
      console.error("All navigation methods failed in proceedAnyway:", error);
      sendResponse({ success: false, error: error.message });
    }

    return true;
  } else if (request.action === "openPopup") {
    // This action is sent from content.js when user clicks "Details" in the warning banner
    // No need to do anything here as the popup is controlled by the browser
    return false;
  }
});

// ===============================
//  5) PRE-NAVIGATION PROTECTION
// ===============================

// Check URLs at the beginning of navigation and potentially redirect
chrome.tabs.onUpdated.addListener(async (tabId, changeInfo, tab) => {
  // Pre-navigation check when loading starts
  if (
    changeInfo.status === "loading" &&
    tab.url &&
    tab.url.startsWith("http")
  ) {
    // Skip already pending redirects to avoid loops
    if (pendingRedirects[tabId] === tab.url) {
      return;
    }

    // Skip extension pages to avoid interfering with our own warning pages
    if (tab.url.startsWith(chrome.runtime.getURL(""))) {
      return;
    }

    console.log("Tab loading, checking URL:", tab.url);

    try {
      const result = await checkUrl(tab.url);
      updateBadge(tabId, result);

      // All phishing sites (including blacklisted and high-risk) show warning with proceed option
      if (result.prediction === "Phishing" && result.probability >= 50) {
        // Store URL details for warning page
        chrome.storage.local.set({
          warned_url: tab.url,
          phishing_data: result,
        });

        // Redirect to warning page
        const warningUrl = chrome.runtime.getURL("warning.html");
        pendingRedirects[tabId] = warningUrl;
        chrome.tabs.update(tabId, { url: warningUrl });

        // Clean up after redirect
        setTimeout(() => {
          if (pendingRedirects[tabId] === warningUrl) {
            delete pendingRedirects[tabId];
          }
        }, 2000);
      }
    } catch (error) {
      console.error("Error during pre-navigation check:", error);
    }
  }

  // Keep the existing post-load check for content scripts
  if (changeInfo.status === "complete" && tab.url) {
    if (tab.url.startsWith("http")) {
      chrome.tabs.sendMessage(tabId, { action: "pageLoaded" });
    }
  }
});
