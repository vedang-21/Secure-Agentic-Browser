from bs4 import BeautifulSoup
import re
from typing import Dict, List
from urllib.parse import urlparse


class DOMAnalyzer:
    """Fast, rule-based DOM structure analysis"""

    SUSPICIOUS_PATTERNS = {
        'hidden_styles': ['display:none', 'visibility:hidden', 'opacity:0'],
        'offscreen': ['left:-9999px', 'top:-9999px', 'position:absolute'],
        'tiny_fonts': ['font-size:0', 'font-size:1px'],
        'color_hiding': ['color:white', 'color:#ffffff'],
    }

    def __init__(self):
        self.threat_indicators = []

    def analyze(self, page_content: str) -> Dict:
        """
        Fast DOM analysis - runs in <50ms for typical pages
        """
        soup = BeautifulSoup(page_content, 'html.parser')

        results = {
            'hidden_elements': self._find_hidden_elements(soup),
            'suspicious_forms': self._analyze_forms(soup),
            'external_resources': self._check_external_resources(soup),
            'iframe_analysis': self._analyze_iframes(soup),
            'script_analysis': self._analyze_scripts(soup),
            'link_analysis': self._analyze_links(soup),
            'redirect_analysis': self._analyze_redirects(soup),
            'dom_complexity': self._calculate_complexity(soup),
            'obfuscation_alerts': self._detect_obfuscation(soup),
            'dom_anomalies': self._detect_dom_anomalies(soup),
        }

        return results

    def _find_hidden_elements(self, soup) -> List[Dict]:
        """Detect hidden content using multiple techniques"""
        hidden_elements = []

        for element in soup.find_all(True):
            style = element.get('style', '').lower()

            is_hidden = any(p in style for p in self.SUSPICIOUS_PATTERNS['hidden_styles'])
            is_offscreen = any(p in style for p in self.SUSPICIOUS_PATTERNS['offscreen'])
            is_tiny = any(p in style for p in self.SUSPICIOUS_PATTERNS['tiny_fonts'])

            if is_hidden or is_offscreen or is_tiny:
                text_content = element.get_text(strip=True)
                if text_content:
                    hidden_elements.append({
                        'tag': element.name,
                        'text': text_content,
                        'method': self._categorize_hiding_method(style),
                        'severity': self._calculate_hiding_severity(style, text_content)
                    })

        return hidden_elements

    def _analyze_forms(self, soup) -> List[Dict]:
        """Analyze forms for phishing indicators"""
        suspicious_forms = []

        for form in soup.find_all('form'):
            action = form.get('action', '')
            method = form.get('method', 'get').lower()

            is_external = self._is_external_url(action)
            has_password = bool(form.find('input', {'type': 'password'}))
            has_email = bool(form.find('input', {'type': 'email'}))
            has_hidden_inputs = bool(form.find('input', {'type': 'hidden'}))
            sensitive_fields = self._detect_sensitive_fields(form)

            risk_score = 0.0
            indicators = []

            if is_external and has_password:
                risk_score += 0.6
                indicators.append('external_password_submission')
            if is_external and sensitive_fields:
                risk_score += 0.45
                indicators.append('external_sensitive_submission')

            if action.startswith('javascript:'):
                risk_score += 0.4
                indicators.append('javascript_action')

            if not action or action == '#':
                risk_score += 0.2
                indicators.append('no_action_url')

            if has_hidden_inputs and (has_password or sensitive_fields):
                risk_score += 0.15
                indicators.append('hidden_field_submission')

            if sensitive_fields:
                risk_score += min(len(sensitive_fields) * 0.1, 0.4)
                indicators.append('sensitive_data_collection')

            if has_password or has_email or sensitive_fields:
                suspicious_forms.append({
                    'action': action,
                    'method': method,
                    'has_password': has_password,
                    'has_email': has_email,
                    'has_hidden_inputs': has_hidden_inputs,
                    'sensitive_fields': sensitive_fields,
                    'is_external': is_external,
                    'risk_score': min(risk_score, 1.0),
                    'indicators': indicators
                })

        return suspicious_forms

    def _detect_sensitive_fields(self, form) -> List[str]:
        """Detect credential/PII/payment harvesting fields"""
        field_names = []
        sensitive_patterns = [
            (r'otp|2fa|one[\s_-]?time|verification[\s_-]?code', 'otp_code'),
            (r'cvv|cvc|card[\s_-]?number|credit[\s_-]?card|expiry', 'payment_data'),
            (r'ssn|social[\s_-]?security|tax[\s_-]?id', 'government_id'),
            (r'seed[\s_-]?phrase|recovery[\s_-]?phrase|private[\s_-]?key', 'wallet_secret'),
            (r'api[\s_-]?key|secret|token', 'api_secret'),
        ]

        for field in form.find_all(['input', 'textarea']):
            signal_text = " ".join([
                field.get('name', ''),
                field.get('id', ''),
                field.get('placeholder', ''),
                field.get('autocomplete', ''),
                field.get('aria-label', '')
            ]).lower()

            for pattern, label in sensitive_patterns:
                if re.search(pattern, signal_text):
                    field_names.append(label)
                    break

        return sorted(set(field_names))

    def _check_external_resources(self, soup) -> List[Dict]:
        """Detect external scripts, iframes, images, and links"""
        external = []

        for tag in soup.find_all(['script', 'iframe', 'img', 'link']):
            src = tag.get('src') or tag.get('href')
            if src and self._is_external_url(src):
                external.append({
                    'tag': tag.name,
                    'src': src
                })

        return external

    def _analyze_iframes(self, soup) -> List[Dict]:
        """Detect potentially malicious iframes"""
        iframes = []

        for iframe in soup.find_all('iframe'):
            src = iframe.get('src', '')
            sandbox = iframe.get('sandbox', '')

            iframes.append({
                'src': src,
                'is_external': self._is_external_url(src),
                'has_sandbox': bool(sandbox),
                'risk_level': 'high' if self._is_external_url(src) and not sandbox else 'medium'
            })

        return iframes

    def _analyze_scripts(self, soup) -> Dict:
        """Analyze JavaScript for dynamic injection and obfuscation risks"""
        scripts = soup.find_all('script')

        inline_scripts = [s for s in scripts if not s.get('src')]
        external_scripts = [s for s in scripts if s.get('src')]

        dangerous_patterns = [
            'eval(', 'innerHTML', 'document.write',
            'setTimeout', 'setInterval', 'Function(',
            'atob(', 'btoa(', 'fromCharCode', 'unescape',
            'window[', 'String.fromCharCode', 'setImmediate',
        ]

        obfuscation_patterns = [
            r"[A-Za-z0-9+/]{100,}",  # base64 blobs
            r"(\\x[0-9a-fA-F]{2}){5,}",  # hex encoding
            r"(\\u[0-9a-fA-F]{4}){3,}",  # unicode escapes
            r"function\\s*\\(.*?\\)\\s*\{.*?eval\\(",  # eval in function
            r"while\\s*\\(true\\)",  # infinite loop (anti-debug)
        ]

        risky_inline = []
        obfuscated_scripts = []
        for script in inline_scripts:
            content = script.string or ''
            if any(p in content for p in dangerous_patterns):
                risky_inline.append(content[:200])
            for pattern in obfuscation_patterns:
                try:
                    if re.search(pattern, content):
                        obfuscated_scripts.append(content[:200])
                        break
                except re.error:
                    # Never crash the agent due to a bad regex pattern.
                    continue

        return {
            'total_scripts': len(scripts),
            'inline_scripts': len(inline_scripts),
            'external_scripts': len(external_scripts),
            'risky_inline_count': len(risky_inline),
            'obfuscated_inline_count': len(obfuscated_scripts),
            'external_sources': [s.get('src') for s in external_scripts],
            'obfuscated_samples': obfuscated_scripts[:3],
        }

    def _analyze_links(self, soup) -> Dict:
        """Detect deceptive and high-risk URLs in anchors/forms"""
        suspicious_links = []
        tlds_of_interest = ('.zip', '.mov', '.top', '.xyz', '.click', '.work', '.gq')
        shortener_domains = (
            'bit.ly', 'tinyurl.com', 't.co', 'is.gd', 'cutt.ly', 'rebrand.ly'
        )

        for tag in soup.find_all(['a', 'form']):
            url = tag.get('href') or tag.get('action')
            if not url:
                continue

            indicators = []
            lowered = url.lower().strip()

            if lowered.startswith('javascript:'):
                indicators.append('javascript_url')
            if lowered.startswith('data:'):
                indicators.append('data_url')

            parsed = urlparse(url)
            hostname = (parsed.hostname or '').lower()

            if 'xn--' in hostname:
                indicators.append('punycode_domain')
            if parsed.username or parsed.password:
                indicators.append('credentialed_url')
            if any(hostname.endswith(tld) for tld in tlds_of_interest):
                indicators.append('suspicious_tld')
            if hostname in shortener_domains:
                indicators.append('url_shortener')
            if parsed.scheme == 'http':
                indicators.append('insecure_http')

            if indicators:
                suspicious_links.append({
                    'tag': tag.name,
                    'url': url,
                    'indicators': indicators,
                })

        return {
            'suspicious_count': len(suspicious_links),
            'suspicious_links': suspicious_links[:20],
        }

    def _analyze_redirects(self, soup) -> Dict:
        """Detect forced/hidden redirect behavior"""
        redirects = []

        for meta in soup.find_all('meta'):
            http_equiv = (meta.get('http-equiv') or '').lower()
            content = meta.get('content', '')
            if http_equiv == 'refresh':
                delay_match = re.search(r'^\s*(\d+)', content)
                delay = int(delay_match.group(1)) if delay_match else None
                redirects.append({
                    'type': 'meta_refresh',
                    'content': content[:200],
                    'delay_seconds': delay,
                    'is_immediate': delay == 0
                })

        redirect_js_patterns = [
            r'window\.location\s*=',
            r'location\.href\s*=',
            r'location\.replace\(',
            r'window\.open\(',
            r'history\.pushState\(',
        ]
        for script in soup.find_all('script'):
            content = script.string or ''
            if any(re.search(pattern, content) for pattern in redirect_js_patterns):
                redirects.append({
                    'type': 'javascript_redirect',
                    'sample': content[:200]
                })

        return {
            'redirect_count': len(redirects),
            'redirects': redirects[:10],
        }

    def _is_external_url(self, url: str) -> bool:
        """Check if URL is external"""
        if not url:
            return False
        if url.startswith('//'):
            return True
        return url.startswith('http://') or url.startswith('https://')

    def _calculate_complexity(self, soup) -> Dict:
        """Calculate DOM complexity metrics"""
        return {
            'total_elements': len(soup.find_all(True)),
            'max_depth': self._get_max_depth(soup),
            'form_count': len(soup.find_all('form')),
            'input_count': len(soup.find_all('input')),
            'button_count': len(soup.find_all('button')),
        }

    def _get_max_depth(self, element, depth=0) -> int:
        """Calculate maximum DOM tree depth"""
        if not hasattr(element, 'children'):
            return depth

        depths = [
            self._get_max_depth(child, depth + 1)
            for child in element.children
            if hasattr(child, 'children')
        ]

        return max(depths, default=depth)

    def _categorize_hiding_method(self, style: str) -> str:
        if 'display:none' in style:
            return 'display_none'
        if 'visibility:hidden' in style:
            return 'visibility_hidden'
        if 'opacity:0' in style:
            return 'opacity_zero'
        if 'left:-' in style or 'top:-' in style:
            return 'offscreen_positioning'
        if 'font-size:0' in style or 'font-size:1px' in style:
            return 'tiny_font'
        return 'unknown'

    def _calculate_hiding_severity(self, style: str, text: str) -> str:
        text_lower = text.lower()

        high_severity_keywords = [
            'ignore', 'instruction', 'system', 'override',
            'password', 'credential', 'admin', 'execute'
        ]

        if any(k in text_lower for k in high_severity_keywords):
            return 'critical'

        if len(text) > 50:
            return 'high'

        return 'medium'

    def _detect_obfuscation(self, soup) -> List[Dict]:
        """Detect obfuscated attributes, suspicious encoding, and hidden payloads"""
        alerts = []
        # Check for base64, hex, or unicode in attributes
        for tag in soup.find_all(True):
            for attr, value in tag.attrs.items():
                if isinstance(value, list):
                    value = ' '.join(value)
                if re.search(r'[A-Za-z0-9+/]{80,}', value):
                    alerts.append({'tag': tag.name, 'attr': attr, 'type': 'base64_suspected', 'sample': value[:60]})
                if re.search(r'(\\x[0-9a-fA-F]{2}){5,}', value):
                    alerts.append({'tag': tag.name, 'attr': attr, 'type': 'hex_encoding', 'sample': value[:60]})
                if re.search(r'(\\u[0-9a-fA-F]{4}){3,}', value):
                    alerts.append({'tag': tag.name, 'attr': attr, 'type': 'unicode_escape', 'sample': value[:60]})
        return alerts

    def _detect_dom_anomalies(self, soup) -> List[str]:
        """Detect DOM anomalies such as excessive nesting, suspicious tag ratios, or anti-analysis tricks"""
        anomalies = []
        total_elements = len(soup.find_all(True))
        script_count = len(soup.find_all('script'))
        iframe_count = len(soup.find_all('iframe'))
        if script_count > total_elements * 0.2:
            anomalies.append('High script-to-element ratio')
        if iframe_count > total_elements * 0.1:
            anomalies.append('High iframe-to-element ratio')
        if self._get_max_depth(soup) > 30:
            anomalies.append('Excessive DOM depth (possible anti-analysis)')
        return anomalies
