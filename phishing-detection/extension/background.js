// background.js (Manifest V3 service worker)

let predictionCache = {};
let blacklist = [];
let whitelist = [];

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
  }
});

// Whenever a tab is updated, check the new URL
chrome.tabs.onUpdated.addListener((tabId, changeInfo, tab) => {
  if (changeInfo.status === "complete" && tab.url) {
    if (tab.url.startsWith("http")) {
      chrome.tabs.sendMessage(tabId, { action: "pageLoaded" });
    }
  }
});
