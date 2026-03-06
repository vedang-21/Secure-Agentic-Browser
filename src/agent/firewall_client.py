import logging
import httpx
import os
from typing import Dict, Any, List, Optional
import json
from datetime import datetime

logger = logging.getLogger(__name__)

class FirewallClient:
    def __init__(self, firewall_url: str = None):
        # Auto-detect firewall configuration
        self.firewall_url = firewall_url or os.getenv('FIREWALL_API_URL', 'http://localhost:3001/api/validate')
        self.use_external_api = os.getenv('USE_EXTERNAL_FIREWALL', 'false').lower() == 'true'
        self.client = httpx.AsyncClient(timeout=30.0)  # Increased timeout for page data
        
        # Enhanced security rules
        self.security_rules = {
            "blocked_domains": [
                "malware-site.com",
                "phishing-example.com",
                "dangerous-downloads.net",
                # Add common risky patterns
                "bit.ly",
                "tinyurl.com", 
                "t.co"
            ],
            "sensitive_selectors": [
                "input[type='password']",
                "input[name*='credit']",
                "input[name*='ssn']",
                "input[name*='social']",
                "input[name*='password']",
                "input[name*='pin']",
                "input[id*='password']"
            ],
            "dangerous_urls": [
                "javascript:",
                "data:",
                "file://",
                "ftp://",
                "chrome://",
                "chrome-extension://"
            ],
            "suspicious_html_patterns": [
                "onclick=\"window.open",
                "eval(",
                "document.write",
                "innerHTML =",
                "base64,",
                "data:text/html",
                "javascript:void"
            ],
            "allowed_domains": [
                "google.com",
                "youtube.com",
                "github.com", 
                "stackoverflow.com",
                "wikipedia.org"
            ]
        }
        
        logger.info(f"🛡️ Firewall initialized - External API: {self.use_external_api}")
    
    async def validate_action(self, action: Dict[str, Any], page_context: Dict[str, Any] = None) -> Dict[str, Any]:
        """
        Enhanced validation with comprehensive page context.
        
        Args:
            action: The action to validate (navigate, click, type, extract, finish)
            page_context: Complete page data including HTML, CSS, forms, inputs, etc.
            
        Returns:
            {
                'allowed': bool,
                'reason': str,
                'source': 'local' | 'external',
                'confidence': float,
                'risk_factors': List[str]
            }
        """
        try:
            # Create comprehensive validation payload
            validation_payload = self._create_validation_payload(action, page_context)
            
            # 1. Enhanced local security analysis (with page context)
            local_result = self._check_enhanced_local_rules(validation_payload)
            
            if not local_result['allowed']:
                logger.warning(f"🛡️ Local firewall BLOCKED: {local_result['reason']}")
                logger.warning(f"🚨 Risk factors: {local_result.get('risk_factors', [])}")
                return local_result
            
            # 2. External API validation (if enabled)
            if self.use_external_api:
                try:
                    external_result = await self._validate_with_external_api(validation_payload)
                    if external_result:
                        logger.info(f"🛡️ External firewall: {external_result['reason']}")
                        return external_result
                except Exception as e:
                    logger.warning(f"External firewall unavailable: {str(e)}")
            
            # 3. Enhanced local validation passed
            logger.info(f"🛡️ Firewall ALLOWED: {action.get('action', 'unknown')} with context analysis")
            return local_result
            
        except Exception as e:
            logger.error(f"Firewall validation error: {str(e)}")
            return {
                'allowed': False,
                'reason': f'Firewall error: {str(e)}',
                'source': 'error',
                'confidence': 0.0,
                'risk_factors': ['firewall_error']
            }
    
    def _create_validation_payload(self, action: Dict[str, Any], page_context: Dict[str, Any] = None) -> Dict[str, Any]:
        """Create comprehensive payload for validation including all page data."""
        payload = {
            'action': action,
            'timestamp': datetime.now().isoformat(),
            'agent_id': 'secure-agentic-browser',
            'source': 'agentic_browser'
        }
        
        # Add comprehensive page context if available
        if page_context:
            payload['page_context'] = {
                'url': page_context.get('url', ''),
                'title': page_context.get('title', ''),
                'html_content': page_context.get('html', ''),
                'visible_text': page_context.get('visible_text', ''),
                'css_styles': page_context.get('css', []),
                'javascript_present': page_context.get('has_javascript', False),
                'forms': page_context.get('forms', []),
                'links': page_context.get('links', []),
                'inputs': page_context.get('inputs', []),
                'meta_data': page_context.get('meta', {}),
                'security_headers': page_context.get('security_headers', {}),
                'cookies': page_context.get('cookies', []),
                'page_size': len(page_context.get('html', '')),
                'external_resources': page_context.get('external_resources', [])
            }
        
        return payload
    
    def _check_enhanced_local_rules(self, payload: Dict[str, Any]) -> Dict[str, Any]:
        """Enhanced local rule checking with comprehensive page context analysis."""
        action = payload.get('action', {})
        page_context = payload.get('page_context', {})
        action_type = action.get("action", "")
        risk_factors = []
        
        # 1. Basic action validation (existing logic)
        basic_result = self._check_basic_action_rules(action)
        if not basic_result['allowed']:
            return basic_result
        
        risk_factors.extend(basic_result.get('risk_factors', []))
        
        # 2. Enhanced page context security analysis
        if page_context:
            page_risks = self._analyze_page_security_context(page_context, action)
            risk_factors.extend(page_risks)
            
            # Block if multiple high-risk factors detected
            high_risk_factors = [risk for risk in page_risks if 'dangerous' in risk or 'malicious' in risk]
            if len(high_risk_factors) > 1:
                return {
                    'allowed': False,
                    'reason': f'Multiple high-risk security factors detected: {", ".join(high_risk_factors)}',
                    'source': 'local',
                    'confidence': 0.95,
                    'risk_factors': risk_factors
                }
            
            # Block if too many total risk factors
            if len(page_risks) > 3:
                return {
                    'allowed': False,
                    'reason': f'Multiple security risks detected on page: {", ".join(page_risks[:3])}...',
                    'source': 'local',
                    'confidence': 0.9,
                    'risk_factors': risk_factors
                }
        
        # Calculate confidence based on risk factors
        confidence = max(0.5, 1.0 - (len(risk_factors) * 0.1))
        
        return {
            'allowed': True,
            'reason': f'{action_type} action passed enhanced security analysis',
            'source': 'local',
            'confidence': confidence,
            'risk_factors': risk_factors
        }
    
    
    def _check_basic_action_rules(self, action: Dict[str, Any]) -> Dict[str, Any]:
        """Enhanced basic action validation with detailed responses."""
        action_type = action.get("action", "")
        
        # Navigate action validation
        if action_type == "navigate":
            url = action.get("url", "").lower()
            
            # Check dangerous schemes
            for scheme in self.security_rules["dangerous_urls"]:
                if url.startswith(scheme):
                    return {
                        'allowed': False,
                        'reason': f'Dangerous URL scheme detected: {scheme}',
                        'source': 'local',
                        'confidence': 1.0,
                        'risk_factors': ['dangerous_scheme']
                    }
            
            # Check blocked domains
            for domain in self.security_rules["blocked_domains"]:
                if domain in url:
                    return {
                        'allowed': False,
                        'reason': f'Blocked domain detected: {domain}',
                        'source': 'local',
                        'confidence': 1.0,
                        'risk_factors': ['blocked_domain']
                    }
        
        # Type action validation
        elif action_type == "type":
            selector = action.get("selector", "").lower()
            text = action.get("text", "")
            
            # Check sensitive fields
            for sensitive in self.security_rules["sensitive_selectors"]:
                if sensitive.replace('[', '').replace(']', '') in selector:
                    return {
                        'allowed': False,
                        'reason': f'Sensitive field detected: {selector}',
                        'source': 'local',
                        'confidence': 0.9,
                        'risk_factors': ['sensitive_field']
                    }
            
            # Check for suspicious text content
            suspicious_keywords = ['password', 'creditcard', 'ssn', 'admin', 'root']
            if any(keyword in text.lower() for keyword in suspicious_keywords):
                return {
                    'allowed': False,
                    'reason': 'Suspicious text content detected',
                    'source': 'local',
                    'confidence': 0.8,
                    'risk_factors': ['suspicious_text']
                }
        
        # Click action validation
        elif action_type == "click":
            selector = action.get("selector", "").lower()
            
            # Block suspicious download/file links
            dangerous_click_patterns = ['download', 'file-upload', 'delete', 'remove', 'logout']
            if any(pattern in selector for pattern in dangerous_click_patterns):
                return {
                    'allowed': False,
                    'reason': f'Potentially dangerous click target: {selector}',
                    'source': 'local',
                    'confidence': 0.7,
                    'risk_factors': ['suspicious_click_target']
                }
        
        # Allow by default with some risk factors for monitoring
        risk_factors = []
        if action_type not in ['navigate', 'click', 'type', 'extract', 'finish']:
            risk_factors.append('unknown_action_type')
        
        return {
            'allowed': True,
            'reason': f'{action_type} action passed basic security checks',
            'source': 'local',
            'confidence': 0.8,
            'risk_factors': risk_factors
        }
    
    def _analyze_page_security_context(self, page_context: Dict[str, Any], action: Dict[str, Any]) -> List[str]:
        """Analyze page context for security risks."""
        risk_factors = []
        
        # HTML content analysis
        html_content = page_context.get('html_content', '').lower()
        for pattern in self.security_rules["suspicious_html_patterns"]:
            if pattern in html_content:
                risk_factors.append(f'suspicious_html_{pattern.split("(")[0].replace("\"", "")}')
        
        # JavaScript analysis
        if page_context.get('javascript_present', False):
            dangerous_js_patterns = ['eval(', 'document.write', 'innerHTML =', 'outerhtml =']
            for pattern in dangerous_js_patterns:
                if pattern in html_content:
                    risk_factors.append(f'dangerous_javascript_{pattern.split("(")[0]}')
        
        # Form analysis
        forms = page_context.get('forms', [])
        url = page_context.get('url', '')
        for form in forms:
            # Check for insecure form submission
            if form.get('method', '').lower() == 'post' and not url.startswith('https://'):
                risk_factors.append('insecure_form_submission')
            
            # Check for suspicious form actions
            form_action = form.get('action', '').lower()
            if any(suspicious in form_action for suspicious in ['admin', 'login', 'password', 'credit']):
                risk_factors.append('sensitive_form_detected')
        
        # Input field analysis for the specific action
        if action.get('action') == 'type':
            inputs = page_context.get('inputs', [])
            target_selector = action.get('selector', '')
            for input_field in inputs:
                if target_selector in input_field.get('selector', ''):
                    # Password field over HTTP
                    if input_field.get('type') == 'password' and not url.startswith('https://'):
                        risk_factors.append('password_field_over_http')
                    
                    # Credit card field detection
                    input_name = input_field.get('name', '').lower()
                    if any(cc_pattern in input_name for cc_pattern in ['credit', 'card', 'cvv', 'expiry']):
                        risk_factors.append('credit_card_field_detected')
        
        # URL and protocol analysis
        if not url.startswith('https://'):
            # Check for sensitive content over HTTP
            sensitive_indicators = ['password', 'login', 'signin', 'credit', 'payment']
            if any(indicator in html_content for indicator in sensitive_indicators):
                risk_factors.append('sensitive_content_over_http')
        
        # Security headers analysis
        security_headers = page_context.get('security_headers', {})
        if not security_headers.get('content_security_policy'):
            risk_factors.append('missing_csp_header')
        
        # Cookie analysis
        cookies = page_context.get('cookies', [])
        for cookie in cookies:
            if not cookie.get('secure', False) and url.startswith('https://'):
                risk_factors.append('insecure_cookie_over_https')
        
        # Page size analysis (potential for large malicious content)
        page_size = page_context.get('page_size', 0)
        if page_size > 5000000:  # 5MB
            risk_factors.append('unusually_large_page')
        
        # External resources analysis
        external_resources = page_context.get('external_resources', [])
        for resource in external_resources:
            resource_url = resource.lower()
            # Check for suspicious external resources
            if any(suspicious_domain in resource_url for suspicious_domain in self.security_rules["blocked_domains"]):
                risk_factors.append('suspicious_external_resource')
        
        return risk_factors
        """Check action against local security rules."""
        action_type = action.get("action", "")
        target = action.get("target", "")
        value = action.get("value", "")
        
        # Block navigation to dangerous URLs
        if action_type == "navigate":
            url = target.lower()
            
            # Check for dangerous URL schemes
            for dangerous_scheme in self.security_rules["dangerous_urls"]:
                if url.startswith(dangerous_scheme):
                    logger.warning(f"Blocked dangerous URL scheme: {url}")
                    return False
            
            # Check for blocked domains
            for blocked_domain in self.security_rules["blocked_domains"]:
                if blocked_domain in url:
                    logger.warning(f"Blocked access to dangerous domain: {blocked_domain}")
                    return False
        
        # Block typing into sensitive fields
        if action_type == "type":
            for sensitive_selector in self.security_rules["sensitive_selectors"]:
                if self._selector_matches(target, sensitive_selector):
                    logger.warning(f"Blocked typing into sensitive field: {target}")
                    return False
        
        # Block suspicious file operations
        if "download" in value.lower() or "upload" in value.lower():
            if not self._is_safe_file_operation(action):
                logger.warning("Blocked suspicious file operation")
                return False
        
    
    async def _validate_with_external_api(self, payload: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """Send comprehensive payload to external firewall API."""
        try:
            # Add authentication headers
            headers = {
                "Content-Type": "application/json",
                "User-Agent": "SecureAgenticBrowser/1.0"
            }
            
            if os.getenv('FIREWALL_API_KEY'):
                headers["Authorization"] = f"Bearer {os.getenv('FIREWALL_API_KEY')}"
            
            response = await self.client.post(
                self.firewall_url,
                json=payload,
                headers=headers
            )
            
            if response.status_code == 200:
                result = response.json()
                return {
                    'allowed': result.get('allowed', False),
                    'reason': result.get('reason', 'External firewall decision'),
                    'source': 'external',
                    'confidence': result.get('confidence', 0.5),
                    'risk_factors': result.get('risk_factors', [])
                }
            else:
                logger.warning(f"External firewall API error: {response.status_code}")
                return None
                
        except Exception as e:
            logger.warning(f"External firewall API failed: {str(e)}")
            return None
    
    async def report_action_result(self, action: Dict[str, Any], result: Dict[str, Any], page_context: Dict[str, Any] = None) -> None:
        """Report action result with comprehensive page context."""
        try:
            payload = {
                "action": action,
                "result": result,
                "page_context": page_context,
                "timestamp": datetime.now().isoformat(),
                "source": "agentic_browser",
                "agent_id": "secure-agentic-browser"
            }
            
            headers = {
                "Content-Type": "application/json",
                "User-Agent": "SecureAgenticBrowser/1.0"
            }
            
            if os.getenv('FIREWALL_API_KEY'):
                headers["Authorization"] = f"Bearer {os.getenv('FIREWALL_API_KEY')}"
            
            response = await self.client.post(
                f"{self.firewall_url.replace('/validate', '/report')}",
                json=payload,
                headers=headers
            )
            
            if response.status_code == 200:
                logger.debug("Action result with context reported successfully")
            else:
                logger.debug(f"Failed to report to firewall: {response.status_code}")
                
        except Exception as e:
            logger.debug(f"Could not report to firewall: {str(e)}")
    
    # Legacy methods for backward compatibility
    def _selector_matches(self, actual_selector: str, pattern: str) -> bool:
        """Check if a selector matches a security pattern."""
        return pattern.lower() in actual_selector.lower()
    
    def _is_safe_file_operation(self, action: Dict[str, Any]) -> bool:
        """Validate file operations for safety."""
        return False  # Conservative approach
    
    def add_blocked_domain(self, domain: str) -> None:
        """Add a domain to the blocked list."""
        if domain not in self.security_rules["blocked_domains"]:
            self.security_rules["blocked_domains"].append(domain)
            logger.info(f"Added blocked domain: {domain}")
    
    def remove_blocked_domain(self, domain: str) -> None:
        """Remove a domain from the blocked list."""
        if domain in self.security_rules["blocked_domains"]:
            self.security_rules["blocked_domains"].remove(domain)
            logger.info(f"Removed blocked domain: {domain}")
    
    async def close(self) -> None:
        """Clean up HTTP client."""
        await self.client.aclose()