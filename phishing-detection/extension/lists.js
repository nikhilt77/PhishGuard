document.addEventListener('DOMContentLoaded', function() {
    // Tab elements
    const whitelistTab = document.getElementById('whitelist-tab');
    const blacklistTab = document.getElementById('blacklist-tab');
    const whitelistContainer = document.getElementById('whitelist-container');
    const blacklistContainer = document.getElementById('blacklist-container');

    // List elements
    const whitelistItems = document.getElementById('whitelist-items');
    const blacklistItems = document.getElementById('blacklist-items');
    const whitelistCount = document.getElementById('whitelist-count');
    const blacklistCount = document.getElementById('blacklist-count');

    // Button elements
    const addToWhitelistBtn = document.getElementById('add-to-whitelist');
    const addToBlacklistBtn = document.getElementById('add-to-blacklist');
    const exportWhitelistBtn = document.getElementById('export-whitelist');
    const exportBlacklistBtn = document.getElementById('export-blacklist');
    const backButton = document.getElementById('back-button');

    // Modal elements
    const modal = document.getElementById('add-site-modal');
    const modalTitle = document.getElementById('modal-title');
    const closeModal = document.querySelector('.close');
    const closeButton = document.querySelector('.close-button');
    const addSiteForm = document.getElementById('add-site-form');
    const siteUrlInput = document.getElementById('site-url');
    const siteNotesInput = document.getElementById('site-notes');

    // Tab switching
    whitelistTab.addEventListener('click', () => {
        whitelistTab.classList.add('active');
        blacklistTab.classList.remove('active');
        whitelistContainer.classList.add('active');
        blacklistContainer.classList.remove('active');
    });

    blacklistTab.addEventListener('click', () => {
        blacklistTab.classList.add('active');
        whitelistTab.classList.remove('active');
        blacklistContainer.classList.add('active');
        whitelistContainer.classList.remove('active');
    });

    // Modal functions
    let currentListType = '';

    function openModal(listType) {
        currentListType = listType;
        modalTitle.textContent = `Add to ${listType === 'whitelist' ? 'Trusted Sites' : 'Blocked Sites'}`;
        siteUrlInput.value = '';
        siteNotesInput.value = '';
        modal.style.display = 'block';
    }

    function closeModalFunc() {
        modal.style.display = 'none';
    }

    addToWhitelistBtn.addEventListener('click', () => openModal('whitelist'));
    addToBlacklistBtn.addEventListener('click', () => openModal('blacklist'));
    closeModal.addEventListener('click', closeModalFunc);
    closeButton.addEventListener('click', closeModalFunc);

    // Close modal when clicking outside
    window.addEventListener('click', (event) => {
        if (event.target === modal) {
            closeModalFunc();
        }
    });

    // Form submission
    addSiteForm.addEventListener('submit', (e) => {
        e.preventDefault();

        const url = siteUrlInput.value.trim();
        const notes = siteNotesInput.value.trim();

        if (!url) {
            alert('Please enter a valid URL');
            return;
        }

        // Ensure URL has protocol
        let formattedUrl = url;
        if (!url.startsWith('http://') && !url.startsWith('https://')) {
            formattedUrl = 'https://' + url;
        }

        // Add to appropriate list
        const action = currentListType === 'whitelist' ? 'addToWhitelist' : 'addToBlacklist';

        chrome.runtime.sendMessage({
            action: action,
            url: formattedUrl,
            notes: notes
        }, (response) => {
            if (response.success) {
                closeModalFunc();
                loadLists();
            } else {
                alert('Failed to add URL to list');
            }
        });
    });

    // Export function
    function exportList(listType) {
        chrome.runtime.sendMessage({action: 'getLists'}, (response) => {
            const list = listType === 'whitelist' ? response.whitelist : response.blacklist;

            // Format data for export
            const exportData = list.map(item => ({
                           url: item.url,
                           added: new Date(item.timestamp).toLocaleString(),
                           notes: item.notes || '',
                           added_by: item.addedBy
                       }));

                       // Convert to CSV
                       const headers = ['URL', 'Date Added', 'Notes', 'Added By'];
                       const csvContent = [
                           headers.join(','),
                           ...exportData.map(row => [
                               `"${row.url}"`,
                               `"${row.added}"`,
                               `"${row.notes.replace(/"/g, '""')}"`,
                               `"${row.added_by}"`
                           ].join(','))
                       ].join('\n');

                       // Create download link
                       const blob = new Blob([csvContent], { type: 'text/csv' });
                       const url = URL.createObjectURL(blob);
                       const a = document.createElement('a');
                       a.setAttribute('hidden', '');
                       a.setAttribute('href', url);
                       a.setAttribute('download', `phishguard_${listType}_${new Date().toISOString().slice(0,10)}.csv`);
                       document.body.appendChild(a);
                       a.click();
                       document.body.removeChild(a);
                   });
               }

               exportWhitelistBtn.addEventListener('click', () => exportList('whitelist'));
               exportBlacklistBtn.addEventListener('click', () => exportList('blacklist'));

               // Remove item from list
               function removeFromList(url, listType) {
                   if (confirm(`Are you sure you want to remove this URL from your ${listType === 'whitelist' ? 'trusted' : 'blocked'} sites?`)) {
                       chrome.runtime.sendMessage({
                           action: 'removeFromList',
                           url: url,
                           listType: listType
                       }, (response) => {
                           if (response.success) {
                               loadLists();
                           } else {
                               alert('Failed to remove URL from list');
                           }
                       });
                   }
               }

               // Format date
               function formatDate(timestamp) {
                   const date = new Date(timestamp);
                   return date.toLocaleDateString() + ' ' + date.toLocaleTimeString();
               }

               // Render lists
               function renderList(list, container, listType) {
                   container.innerHTML = '';

                   if (list.length === 0) {
                       container.innerHTML = `
                           <div class="empty-list">
                               <p>No sites in this list yet.</p>
                           </div>
                       `;
                       return;
                   }

                   // Sort by newest first
                   const sortedList = [...list].sort((a, b) => b.timestamp - a.timestamp);

                   sortedList.forEach(item => {
                       const listItem = document.createElement('div');
                       listItem.className = `list-item ${listType}-item`;

                       // Format URL for display (truncate if too long)
                       let displayUrl = item.url;
                       if (displayUrl.length > 60) {
                           displayUrl = displayUrl.substring(0, 57) + '...';
                       }

                       listItem.innerHTML = `
                           <div class="item-header">
                               <div class="item-url" title="${item.url}">${displayUrl}</div>
                               <div class="item-actions">
                                   <button class="remove-btn" title="Remove from list">✕</button>
                               </div>
                           </div>
                           <div class="item-meta">
                               <span>Added: ${formatDate(item.timestamp)}</span>
                               <span>By: ${item.addedBy || 'User'}</span>
                           </div>
                           ${item.notes ? `<div class="item-notes">${item.notes}</div>` : ''}
                       `;

                       // Add event listener to remove button
                       const removeBtn = listItem.querySelector('.remove-btn');
                       removeBtn.addEventListener('click', () => {
                           removeFromList(item.url, listType);
                       });

                       container.appendChild(listItem);
                   });
               }

               // Load lists from background script
               function loadLists() {
                   chrome.runtime.sendMessage({action: 'getLists'}, (response) => {
                       const whitelist = response.whitelist || [];
                       const blacklist = response.blacklist || [];

                       // Update counts
                       whitelistCount.textContent = `${whitelist.length} site${whitelist.length !== 1 ? 's' : ''}`;
                       blacklistCount.textContent = `${blacklist.length} site${blacklist.length !== 1 ? 's' : ''}`;

                       // Render lists
                       renderList(whitelist, whitelistItems, 'whitelist');
                       renderList(blacklist, blacklistItems, 'blacklist');
                   });
               }

               // Back button to return to popup
               backButton.addEventListener('click', () => {
                   window.location.href = 'popup.html';
               });

               // Initial load
               loadLists();
           });
