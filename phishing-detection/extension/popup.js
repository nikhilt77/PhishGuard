document.addEventListener('DOMContentLoaded', function() {
    // Get DOM elements
    const currentUrlEl = document.getElementById('current-url');
    const statusIndicatorEl = document.getElementById('status-indicator');
    const statusDotEl = statusIndicatorEl.querySelector('.status-dot');
    const statusTextEl = statusIndicatorEl.querySelector('.status-text');

    const resultIconEl = document.getElementById('result-icon');
    const resultTitleEl = document.getElementById('result-title');
    const probabilityBarEl = document.getElementById('probability-bar');
    const probabilityValueEl = document.getElementById('probability-value');
    const sourceLabel = document.getElementById('source-label');

    const rfVerdictEl = document.getElementById('rf-verdict');
    const rfProbabilityEl = document.getElementById('rf-probability');
    const svmVerdictEl = document.getElementById('svm-verdict');
    const svmProbabilityEl = document.getElementById('svm-probability');

    const rfWeightBarEl = document.getElementById('rf-weight-bar');
    const svmWeightBarEl = document.getElementById('svm-weight-bar');
    const rfWeightValueEl = document.getElementById('rf-weight-value');
    const svmWeightValueEl = document.getElementById('svm-weight-value');
    const blendMethodValueEl = document.getElementById('blend-method-value');
    const thresholdValueEl = document.getElementById('threshold-value');

    const featureListEl = document.getElementById('feature-list');
    const refreshButtonEl = document.getElementById('refresh-button');
    const listsButtonEl = document.getElementById('lists-button');
    const listActionsButtonEl = document.getElementById('list-actions-button');
    const listActionsDropdown = document.getElementById('list-actions-dropdown');
    const addToWhitelistEl = document.getElementById('add-to-whitelist');
    const addToBlacklistEl = document.getElementById('add-to-blacklist');
    const aboutLinkEl = document.getElementById('about-link');

    // Current URL and result
    let currentUrl = '';
    let currentResult = null;

    // Get the current tab's URL
    function getCurrentTab() {
        return new Promise((resolve) => {
            chrome.tabs.query({active: true, currentWindow: true}, (tabs) => {
                resolve(tabs[0]);
            });
        });
    }

    // Update UI elements based on prediction result
    function updateUI(tab, result) {
        currentUrl = tab.url;
        currentResult = result;

        // Update URL
        currentUrlEl.textContent = tab.url;

        // Update status
        statusDotEl.className = 'status-dot active';
        statusTextEl.textContent = 'Analysis complete';

        // Update result source if applicable
        if (result.source) {
            if (result.source === 'whitelist') {
                sourceLabel.textContent = 'Source: Trusted Sites List';
            } else if (result.source === 'blacklist') {
                sourceLabel.textContent = 'Source: Blocked Sites List';
            }
        } else {
            sourceLabel.textContent = '';
        }

        // Update result
        if (result.prediction === 'Phishing') {
            resultIconEl.textContent = '⚠️';
            resultTitleEl.textContent = 'Potential Phishing Site';
            resultTitleEl.style.color = 'var(--danger-color)';
        } else if (result.prediction === 'Legitimate') {
            resultIconEl.textContent = '✓';
            resultTitleEl.textContent = 'Legitimate Site';
            resultTitleEl.style.color = 'var(--success-color)';
        } else {
            resultIconEl.textContent = '❓';
            resultTitleEl.textContent = 'Analysis Inconclusive';
            resultTitleEl.style.color = 'var(--warning-color)';
        }

        // Update probability bar
        const probability = result.probability;
        probabilityBarEl.style.width = `${probability}%`;
        probabilityValueEl.textContent = `${probability.toFixed(1)}%`;

        if (probability < 30) {
            probabilityBarEl.className = 'probability-bar safe';
        } else if (probability < 70) {
            probabilityBarEl.className = 'probability-bar warning';
        } else {
            probabilityBarEl.className = 'probability-bar danger';
        }

        // If result came from whitelist/blacklist, don't show model details
        if (result.source === 'whitelist' || result.source === 'blacklist') {
            document.getElementById('details-container').style.display = 'none';
            return;
        } else {
            document.getElementById('details-container').style.display = 'block';
        }

        // Update model results
        rfVerdictEl.textContent = result.rf_prediction;
        rfVerdictEl.className = `model-verdict ${result.rf_prediction === 'Legitimate' ? 'safe' : 'danger'}`;
        rfProbabilityEl.textContent = `${result.rf_probability.toFixed(1)}%`;

        svmVerdictEl.textContent = result.svm_prediction;
        svmVerdictEl.className = `model-verdict ${result.svm_prediction === 'Legitimate' ? 'safe' : 'danger'}`;
        svmProbabilityEl.textContent = `${result.svm_probability.toFixed(1)}%`;

        // Update blending info
        rfWeightBarEl.style.width = `${result.rf_weight * 100}%`;
        svmWeightBarEl.style.width = `${result.svm_weight * 100}%`;
        rfWeightValueEl.textContent = `${(result.rf_weight * 100).toFixed(0)}%`;
        svmWeightValueEl.textContent = `${(result.svm_weight * 100).toFixed(0)}%`;
        blendMethodValueEl.textContent = result.blend_method || 'Standard';
        thresholdValueEl.textContent = result.threshold;

        // Update feature list
        if (result.url_features) {
            featureListEl.innerHTML = '';

            const features = [
                { name: 'GitHub URL', detected: result.url_features.is_github, type: 'neutral' },
                { name: 'Login/Sign-in page', detected: result.url_features.is_login_page, type: 'caution' },
                { name: 'Known trustworthy domain', detected: result.url_features.is_known_domain, type: 'good' },
                { name: 'Suspicious elements', detected: result.url_features.has_suspicious_elements, type: 'bad' }
            ];

            features.forEach(feature => {
                const li = document.createElement('li');
                li.className = `feature-item ${feature.detected ? (feature.type === 'bad' ? 'detected' : (feature.type === 'good' ? 'safe' : '')) : ''}`;

                let icon = '•';
                if (feature.detected) {
                    icon = feature.type === 'bad' ? '⚠️' : (feature.type === 'good' ? '✓' : 'ℹ️');
                }

                li.textContent = `${icon} ${feature.name}: ${feature.detected ? 'Yes' : 'No'}`;
                featureListEl.appendChild(li);
            });
        }
    }

    // Show loading state
    function showLoading() {
        statusDotEl.className = 'status-dot';
        statusTextEl.textContent = 'Analyzing...';
        resultIconEl.textContent = '⟳';
        resultTitleEl.textContent = 'Analyzing URL...';
        resultTitleEl.style.color = '';
        probabilityBarEl.style.width = '0%';
        probabilityValueEl.textContent = '0%';
        probabilityBarEl.className = 'probability-bar';
        sourceLabel.textContent = '';
    }

    // Show error state
    function showError(error) {
        statusDotEl.className = 'status-dot error';
        statusTextEl.textContent = 'Error';
        resultIconEl.textContent = '❌';
        resultTitleEl.textContent = 'Analysis Failed';
        resultTitleEl.style.color = 'var(--danger-color)';
        probabilityBarEl.style.width = '0%';
        probabilityValueEl.textContent = 'N/A';
        sourceLabel.textContent = error ? `Error: ${error}` : '';
        console.error('Error:', error);
    }

    // Load and display results
    async function loadResults() {
        showLoading();

        try {
            const tab = await getCurrentTab();
            currentUrlEl.textContent = tab.url;

            // Skip if not an HTTP URL
            if (!tab.url.startsWith('http')) {
                resultIconEl.textContent = 'ℹ️';
                resultTitleEl.textContent = 'Not a website';
                statusTextEl.textContent = 'Not applicable';
                return;
            }

            // Check URL using background script
            chrome.runtime.sendMessage(
                {action: 'getDetails', url: tab.url},
                (result) => {
                    if (chrome.runtime.lastError) {
                        showError(chrome.runtime.lastError);
                        return;
                    }

                    if (result.error) {
                        showError(result.error);
                        return;
                    }

                    updateUI(tab, result);
                }
            );
        } catch (error) {
            showError(error);
        }
    }

    // Toggle dropdown
    function toggleDropdown() {
        listActionsDropdown.classList.toggle('show');
    }

    // Close dropdown when clicking outside
    window.addEventListener('click', (event) => {
        if (!event.target.matches('#list-actions-button') && listActionsDropdown.classList.contains('show')) {
            listActionsDropdown.classList.remove('show');
        }
    });

    // Add to whitelist
    function addToWhitelist() {
        if (!currentUrl) return;

        chrome.runtime.sendMessage(
            {
                action: 'addToWhitelist',
                url: currentUrl,
                notes: 'Added manually from popup'
            },
            (response) => {
                if (response.success) {
                    alert('Added to Trusted Sites list!');
                    loadResults(); // Refresh
                } else {
                    alert('Failed to add to Trusted Sites list.');
                }
            }
        );

        listActionsDropdown.classList.remove('show');
    }

    // Add to blacklist
    function addToBlacklist() {
        if (!currentUrl) return;

        chrome.runtime.sendMessage(
            {
                action: 'addToBlacklist',
                url: currentUrl,
                notes: 'Added manually from popup'
            },
            (response) => {
                if (response.success) {
                    alert('Added to Blocked Sites list!');
                    loadResults(); // Refresh
                } else {
                    alert('Failed to add to Blocked Sites list.');
                }
            }
        );

        listActionsDropdown.classList.remove('show');
    }

    // Initial load
    loadResults();

    // Event listeners
    refreshButtonEl.addEventListener('click', loadResults);

    listsButtonEl.addEventListener('click', () => {
        window.location.href = 'lists.html';
    });

    listActionsButtonEl.addEventListener('click', toggleDropdown);

    addToWhitelistEl.addEventListener('click', addToWhitelist);

    addToBlacklistEl.addEventListener('click', addToBlacklist);

    aboutLinkEl.addEventListener('click', () => {
        chrome.tabs.create({
            url: 'https://yourwebsite.com/about-phishguard'
        });
    });
});
