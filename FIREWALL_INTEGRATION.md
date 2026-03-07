# External Firewall Integration Guide

This guide shows how to integrate your Secure Agentic Browser with an external firewall API running on localhost.

## 🏗️ Current vs Future Architecture

### **Current (Local Firewall)**
```
Agent → Local Firewall Rules → Browser Action
```

### **Future (External Firewall)**
```
Agent → Local Rules (Fast Check) → External API → Browser Action
```

## 🔧 Setup Instructions

### **Step 1: Configure Environment**

In your `.env` file:
```env
# Enable external firewall
USE_EXTERNAL_FIREWALL=true

# Point to your localhost firewall API
FIREWALL_API_URL=http://localhost:3001/api/validate

# Optional: API key for authentication
FIREWALL_API_KEY=your_firewall_api_key
```

### **Step 2: External Firewall API Requirements**

Your external firewall should:
- Run on `localhost:3001` (or update URL in .env)
- Accept `POST /api/validate` requests
- Return responses in the specified JSON format
- Handle the comprehensive page context data

### **Step 3: Test Integration**

```bash
# Test with mock firewall (included)
python tests/mock_external_firewall.py  # Terminal 1
python tests/test_external_firewall.py  # Terminal 2

# Run agent with external firewall
python main.py
```

## 📡 API Contract

### **Input Schema**
```json
{
  "action": {
    "action": "navigate|click|type|extract|finish",
    "selector": "CSS selector (for click/type)",
    "url": "URL (for navigate)",
    "text": "Text content (for type)"
  },
  "page_context": {
    "url": "Current page URL",
    "title": "Page title",
    "html_content": "Full HTML content",
    "visible_text": "Visible text content",
    "javascript_present": "Boolean - JS detected",
    "forms": "Array of form objects",
    "inputs": "Array of input field objects", 
    "links": "Array of link objects",
    "meta_data": "Page metadata",
    "security_headers": "Security headers",
    "cookies": "Cookie information",
    "page_size": "HTML content size"
  },
  "timestamp": "ISO timestamp",
  "agent_id": "secure-agentic-browser",
  "source": "agentic_browser"
}
```

### **Response Schema**
```json
{
  "allowed": "Boolean - allow/block action",
  "reason": "Human readable explanation",
  "source": "external",
  "confidence": "Float 0-1 - decision confidence",
  "risk_factors": "Array of detected risks",
  "risk_level": "low|medium|high|critical",
  "analysis": {
    "domain_reputation": "good|neutral|suspicious|malicious",
    "ssl_check": "valid|invalid|missing|n/a", 
    "content_safety": "clean|suspicious|malicious",
    "form_analysis": "secure|insecure|missing_csrf|etc"
  },
  "timestamp": "ISO timestamp",
  "processing_time_ms": "Integer - processing time"
}
```

## 🛡️ Security Features

### **Dual Layer Protection**
1. **Local Rules (Always On)** - Fast, basic security checks
2. **External API (When Available)** - Advanced analysis

### **Graceful Degradation**
- If external API is unavailable, uses local rules only
- No single point of failure
- Logs all firewall decisions for monitoring

### **Comprehensive Context**
- Full page HTML and structure
- Form and input field analysis
- JavaScript presence detection
- Security headers evaluation
- Cookie security assessment

## 📊 Example Scenarios

### **Scenario 1: Safe Navigation**
```json
// Input
{
  "action": {"action": "navigate", "url": "https://google.com"},
  "page_context": {"url": "https://google.com", "javascript_present": false}
}

// Expected Response
{
  "allowed": true,
  "reason": "Trusted domain with secure connection",
  "confidence": 0.95,
  "risk_level": "low"
}
```

### **Scenario 2: Password Field Over HTTP**
```json
// Input
{
  "action": {"action": "type", "selector": "input[type='password']", "text": "pass"},
  "page_context": {"url": "http://insecure-site.com", "forms": [...]}
}

// Expected Response
{
  "allowed": false,
  "reason": "Password field detected over insecure connection",
  "confidence": 0.98,
  "risk_level": "high"
}
```

### **Scenario 3: Suspicious JavaScript**
```json
// Input
{
  "action": {"action": "navigate", "url": "javascript:alert('xss')"},
  "page_context": {...}
}

// Expected Response  
{
  "allowed": false,
  "reason": "Dangerous URL scheme detected",
  "confidence": 0.99,
  "risk_level": "critical"
}
```

## 🧪 Testing Your Implementation

Use the included mock firewall to test your integration:

```bash
# Start mock firewall
python tests/mock_external_firewall.py

# Test various scenarios
python tests/test_external_firewall.py
```

The mock firewall demonstrates the expected behavior and can help you develop your actual firewall implementation.

## 🔄 Migration Path

1. **Phase 1**: Current system with local rules ✅
2. **Phase 2**: Add your external firewall, test in parallel
3. **Phase 3**: Enable external firewall with local fallback
4. **Phase 4**: Full external firewall with monitoring

## 💡 Implementation Tips

- Start with the mock firewall to understand the data flow
- Implement basic domain reputation checks first
- Add form and input analysis gradually
- Use confidence scores to indicate certainty
- Log all decisions for debugging and monitoring
- Handle timeouts and connection errors gracefully

Your external firewall will receive rich context about each action, enabling sophisticated security decisions!
