#!/usr/bin/env python3
"""
Mock External Firewall Server for Testing
This simulates your future localhost firewall API for development and testing.
"""

from fastapi import FastAPI, HTTPException
from pydantic import BaseModel
from typing import Dict, Any, List, Optional
import time
from datetime import datetime
import uvicorn
import logging

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

app = FastAPI(title="Mock External Firewall", version="1.0.0")

# Request/Response Models
class FirewallRequest(BaseModel):
    action: Dict[str, Any]
    page_context: Dict[str, Any]
    timestamp: Optional[str] = None
    agent_id: Optional[str] = None
    source: Optional[str] = None

class FirewallResponse(BaseModel):
    allowed: bool
    reason: str
    source: str = "external"
    confidence: float
    risk_factors: List[str]
    risk_level: str
    analysis: Dict[str, Any]
    timestamp: str
    processing_time_ms: int

@app.post("/api/validate", response_model=FirewallResponse)
async def validate_action(request: FirewallRequest):
    """
    Mock firewall validation endpoint that mimics your future external firewall.
    Returns responses in the exact format expected by your agent system.
    """
    start_time = time.time()
    
    logger.info(f"🛡️ Validating action: {request.action.get('action', 'unknown')}")
    logger.debug(f"📄 Page context: URL={request.page_context.get('url', 'unknown')}")
    
    # Simulate analysis based on action and page context
    action_type = request.action.get('action', '')
    url = request.page_context.get('url', '')
    
    # Default response values
    allowed = True
    reason = "Action passed all security checks"
    confidence = 0.95
    risk_factors = ["https_secure_connection", "trusted_domain"]
    risk_level = "low"
    analysis = {
        "domain_reputation": "good",
        "ssl_check": "valid",
        "content_safety": "clean",
        "form_analysis": "secure"
    }
    
    # Simulate security checks
    if "javascript:" in url or "data:" in url:
        allowed = False
        reason = "Dangerous URL scheme detected"
        confidence = 0.98
        risk_factors = ["dangerous_url_scheme", "potential_xss"]
        risk_level = "high"
        analysis = {
            "domain_reputation": "malicious",
            "ssl_check": "n/a",
            "content_safety": "dangerous_scheme",
            "form_analysis": "not_applicable"
        }
    
    elif "malware" in url or "phishing" in url:
        allowed = False
        reason = "Known malicious domain detected"
        confidence = 0.99
        risk_factors = ["malicious_domain", "known_threat"]
        risk_level = "critical"
        analysis = {
            "domain_reputation": "malicious",
            "ssl_check": "invalid",
            "content_safety": "malicious_content",
            "form_analysis": "unsafe"
        }
    
    elif action_type == "type" and "password" in request.action.get('selector', '').lower():
        if not url.startswith('https://'):
            allowed = False
            reason = "Password field detected over insecure connection"
            confidence = 0.95
            risk_factors = ["password_over_http", "credential_theft_risk"]
            risk_level = "high"
            analysis = {
                "domain_reputation": "neutral",
                "ssl_check": "missing",
                "content_safety": "credential_risk",
                "form_analysis": "insecure_credentials"
            }
        else:
            # Allow but warn about password fields
            reason = "Password field detected but connection is secure"
            confidence = 0.80
            risk_factors = ["password_field_detected", "credential_input"]
            risk_level = "medium"
            analysis = {
                "domain_reputation": "good",
                "ssl_check": "valid",
                "content_safety": "password_detected",
                "form_analysis": "secure_credentials"
            }
    
    elif "bit.ly" in url or "tinyurl.com" in url:
        allowed = True  # Allow but with caution
        reason = "URL shortener detected - allowing with increased monitoring"
        confidence = 0.65
        risk_factors = ["url_shortener", "hidden_destination"]
        risk_level = "medium"
        analysis = {
            "domain_reputation": "neutral",
            "ssl_check": "valid",
            "content_safety": "url_shortener",
            "form_analysis": "unknown_destination"
        }
    
    # Calculate processing time
    processing_time = int((time.time() - start_time) * 1000)
    
    response = FirewallResponse(
        allowed=allowed,
        reason=reason,
        confidence=confidence,
        risk_factors=risk_factors,
        risk_level=risk_level,
        analysis=analysis,
        timestamp=datetime.now().isoformat(),
        processing_time_ms=processing_time
    )
    
    logger.info(f"🎯 Decision: {'✅ ALLOWED' if allowed else '🚫 BLOCKED'} ({confidence:.2f} confidence)")
    
    return response

@app.get("/api/health")
async def health_check():
    """Health check endpoint"""
    return {
        "status": "healthy",
        "service": "Mock External Firewall",
        "version": "1.0.0",
        "timestamp": datetime.now().isoformat()
    }

@app.get("/")
async def root():
    """Root endpoint with API information"""
    return {
        "service": "Mock External Firewall API",
        "version": "1.0.0",
        "description": "Simulates your future localhost firewall for testing",
        "endpoints": {
            "POST /api/validate": "Validate agent actions",
            "GET /api/health": "Health check",
            "GET /": "API information"
        },
        "expected_input_format": {
            "action": {"action": "navigate", "selector": "", "text": ""},
            "page_context": {
                "url": "https://example.com",
                "title": "Page Title",
                "html_content": "<html>...</html>",
                "forms": [],
                "inputs": [],
                "links": []
            }
        }
    }

if __name__ == "__main__":
    print("🛡️ Starting Mock External Firewall Server...")
    print("📡 API will be available at: http://localhost:3001")
    print("📚 API docs at: http://localhost:3001/docs")
    print("🔍 Health check: http://localhost:3001/api/health")
    print("\n💡 To use with your agent:")
    print("   Set USE_EXTERNAL_FIREWALL=true in your .env file")
    print("   Set FIREWALL_API_URL=http://localhost:3001/api/validate")
    
    uvicorn.run(
        app,
        host="0.0.0.0",
        port=3001,
        log_level="info"
    )
