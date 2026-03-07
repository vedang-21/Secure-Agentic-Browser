// Background Service Worker
console.log('🛡️ Secure Agent Firewall: Background worker started');

// Listen for extension installation
chrome.runtime.onInstalled.addListener((details) => {
  if (details.reason === 'install') {
    console.log('✅ Extension installed successfully!');
    
    // Initialize default settings
    chrome.storage.local.set({
      threatsBlocked: 0,
      pagesScanned: 0,
      extensionEnabled: true
    }, () => {
      console.log('💾 Default settings saved');
    });
  } else if (details.reason === 'update') {
    console.log('🔄 Extension updated');
  }
});

// Listen for messages from content scripts
chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
  console.log('📨 Message received from content script:', message);
  
  if (message.type === 'page_analyzed') {
    console.log('📊 Page analysis data:', message.data);
    
    // Increment pages scanned counter
    chrome.storage.local.get(['pagesScanned'], (result) => {
      const newCount = (result.pagesScanned || 0) + 1;
      chrome.storage.local.set({ pagesScanned: newCount });
      console.log('📈 Pages scanned:', newCount);
    });
    
    // Placeholder: Simulate risk analysis
    const riskScore = Math.floor(Math.random() * 30); // Random 0-30 (safe range)
    console.log('🎲 Simulated risk score:', riskScore);
    
    // Send response back to content script
    sendResponse({
      success: true,
      riskScore: riskScore,
      status: 'analyzed'
    });
  }
  
  // Return true to indicate we'll send a response asynchronously
  return true;
});

// Placeholder: Simulate backend API call
async function analyzePageContent(pageData) {
  console.log('🔍 Analyzing page content (placeholder)...');
  
  // Simulate API delay
  await new Promise(resolve => setTimeout(resolve, 500));
  
  // Placeholder response
  return {
    riskScore: 15,
    threats: [],
    recommendation: 'allow'
  };
}

// Placeholder: Validate agent action
async function validateAction(action) {
  console.log('🔒 Validating action (placeholder):', action);
  
  // Simulate validation
  await new Promise(resolve => setTimeout(resolve, 300));
  
  return {
    decision: 'allow',
    risk: 'low'
  };
}

// Listen for tab updates (when user navigates)
chrome.tabs.onUpdated.addListener((tabId, changeInfo, tab) => {
  if (changeInfo.status === 'complete' && tab.url) {
    console.log('🌐 Tab loaded:', tab.url);
    
    // Update badge to show extension is active
    chrome.action.setBadgeText({ 
      text: '✓',
      tabId: tabId 
    });
    
    chrome.action.setBadgeBackgroundColor({ 
      color: '#4ade80' // Green
    });
  }
});

// Placeholder: Set up alarm for periodic checks (optional)
chrome.alarms.create('healthCheck', {
  periodInMinutes: 60
});

chrome.alarms.onAlarm.addListener((alarm) => {
  if (alarm.name === 'healthCheck') {
    console.log('💓 Extension health check - All systems operational');
  }
});

// Log storage data periodically
setInterval(() => {
  chrome.storage.local.get(['threatsBlocked', 'pagesScanned'], (result) => {
    console.log('📊 Stats:', {
      threatsBlocked: result.threatsBlocked || 0,
      pagesScanned: result.pagesScanned || 0
    });
  });
}, 60000); // Every minute

console.log('🚀 Background worker ready and listening');
