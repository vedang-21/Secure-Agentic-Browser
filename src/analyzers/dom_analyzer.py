from bs4 import BeautifulSoup
import re
from typing import Dict, List, Tuple


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
            'dom_complexity': self._calculate_complexity(soup),
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

            risk_score = 0.0
            indicators = []

            if is_external and has_password:
                risk_score += 0.6
                indicators.append('external_password_submission')

            if action.startswith('javascript:'):
                risk_score += 0.4
                indicators.append('javascript_action')

            if not action or action == '#':
                risk_score += 0.2
                indicators.append('no_action_url')

            if has_password or has_email:
                suspicious_forms.append({
                    'action': action,
                    'method': method,
                    'has_password': has_password,
                    'has_email': has_email,
                    'is_external': is_external,
                    'risk_score': min(risk_score, 1.0),
                    'indicators': indicators
                })

        return suspicious_forms

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
        """Analyze JavaScript for dynamic injection risks"""
        scripts = soup.find_all('script')

        inline_scripts = [s for s in scripts if not s.get('src')]
        external_scripts = [s for s in scripts if s.get('src')]

        dangerous_patterns = [
            'eval(', 'innerHTML', 'document.write',
            'setTimeout', 'setInterval', 'Function('
        ]

        risky_inline = []
        for script in inline_scripts:
            content = script.string or ''
            if any(p in content for p in dangerous_patterns):
                risky_inline.append(content[:200])

        return {
            'total_scripts': len(scripts),
            'inline_scripts': len(inline_scripts),
            'external_scripts': len(external_scripts),
            'risky_inline_count': len(risky_inline),
            'external_sources': [s.get('src') for s in external_scripts]
        }

    def _is_external_url(self, url: str) -> bool:
        """Check if URL is external"""
        if not url:
            return False
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