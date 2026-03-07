// Content Script - Runs on every webpage
console.log('🛡️ Secure Agent Firewall: Content script loaded');
console.log('📍 Monitoring page:', window.location.href);

// Extract basic page information
const pageInfo = {
  url: window.location.href,
  title: document.title,
  textLength: document.body.innerText.length,
  formCount: document.forms.length,
  linkCount: document.links.length
};

console.log('📊 Page Info:', pageInfo);

// Simulate checking for threats (placeholder)
function checkForThreats() {
  const pageText = document.body.innerText.toLowerCase();
  
  // Simple placeholder threat detection
  const suspiciousKeywords = [
    'ignore previous instructions',
    'system prompt',
    'send credentials',
    'urgent account verification'
  ];
  
  let threatsFound = [];
  
  suspiciousKeywords.forEach(keyword => {
    if (pageText.includes(keyword)) {
      threatsFound.push(keyword);
    }
  });
  
  if (threatsFound.length > 0) {
    console.warn('⚠️ Potential threats detected:', threatsFound);
  } else {
    console.log('✅ No obvious threats detected');
  }
}

// Run threat check
checkForThreats();

// Log when forms are detected
if (document.forms.length > 0) {
  console.log('📝 Forms detected on page:', document.forms.length);
  
  // Log form details
  for (let i = 0; i < document.forms.length; i++) {
    const form = document.forms[i];
    const hasPasswordField = Array.from(form.elements).some(
      element => element.type === 'password'
    );
    
    if (hasPasswordField) {
      console.warn('🔐 Password field detected in form', i);
    }
  }
}

// Message to background script (placeholder)
if (typeof chrome !== 'undefined' && chrome.runtime) {
  chrome.runtime.sendMessage({
    type: 'page_analyzed',
    data: pageInfo
  }, response => {
    if (chrome.runtime.lastError) {
      // Ignore errors for now (background script might not be listening)
      return;
    }
    console.log('📤 Sent page info to background script');
  });
}

console.log('🛡️ Secure Agent Firewall: Monitoring active');

