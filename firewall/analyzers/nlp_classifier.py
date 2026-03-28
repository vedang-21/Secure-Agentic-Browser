
import re
from typing import Dict, List, Tuple
from collections import Counter

class NLPThreatClassifier:
    """
    ML-free NLP threat detection using pattern matching and heuristics
    Can be upgraded to use ML models if time permits
    """
    
    # Prompt injection patterns (regex-based)
    INJECTION_PATTERNS = {
        'direct_override': [
            r'ignore\s+(previous|all|above|prior)\s+instructions?',
            r'disregard\s+(previous|all|above)\s+(instructions?|commands?)',
            r'forget\s+(previous|all|above)\s+instructions?',
        ],
        'system_impersonation': [
            r'system\s*:\s*',
            r'assistant\s*:\s*',
            r'<\|system\|>',
            r'\[SYSTEM\]',
            r'new\s+instructions?\s*:',
        ],
        'task_redirection': [
            r'your\s+(new|real|actual)\s+(task|goal|objective)\s+is',
            r'instead\s+of\s+.+?,\s+you\s+(should|must|will)',
            r'do\s+not\s+.+?,\s+instead',
        ],
        'role_manipulation': [
            r'you\s+are\s+(now|actually)\s+a',
            r'act\s+as\s+(a|an)\s+',
            r'pretend\s+(to\s+be|you\s+are)',
        ],
        'jailbreak_attempts': [
            r'developer\s+mode',
            r'god\s+mode',
            r'unrestricted',
            r'bypass\s+(restrictions?|limitations?|rules?)',
        ]
    }
    
    # Credential/sensitive data exfiltration patterns
    EXFILTRATION_PATTERNS = [
        r'send\s+(your|the)\s+(password|credentials?|api\s+key)',
        r'submit\s+to\s+https?://',
        r'transfer\s+(funds?|money|balance)',
        r'navigate\s+to\s+https?://[^\s]+',
    ]
    
    # Deceptive UI text patterns
    DECEPTIVE_UI_PATTERNS = [
        r'click\s+here\s+to\s+(claim|win|get)',
        r'you\s+(won|are\s+a\s+winner)',
        r'account\s+(suspended|locked|compromised)',
        r'verify\s+your\s+(account|identity|payment)',
        r'urgent\s+action\s+required',
    ]
    
    def __init__(self):
        self.compiled_patterns = self._compile_patterns()
    
    def _compile_patterns(self) -> Dict:
        """Pre-compile regex patterns for performance"""
        compiled = {}
        
        for category, patterns in self.INJECTION_PATTERNS.items():
            compiled[category] = [re.compile(p, re.IGNORECASE) for p in patterns]
        
        compiled['exfiltration'] = [re.compile(p, re.IGNORECASE) 
                                    for p in self.EXFILTRATION_PATTERNS]
        compiled['deceptive_ui'] = [re.compile(p, re.IGNORECASE) 
                                    for p in self.DECEPTIVE_UI_PATTERNS]
        
        return compiled
    
    def classify_text(self, text: str, context: str = 'visible') -> Dict:
        """
        Classify text content for threats
        
        Args:
            text: The text content to analyze
            context: 'visible' or 'hidden' - affects severity
        
        Returns:
            Classification results with threat categories and scores
        """
        results = {
            'is_malicious': False,
            'confidence': 0.0,
            'threats': [],
            'matched_patterns': [],
            'severity': 'none'
        }
        
        if not text or len(text.strip()) == 0:
            return results
        
        # Check each category
        for category, patterns in self.compiled_patterns.items():
            matches = []
            for pattern in patterns:
                found = pattern.findall(text)
                if found:
                    matches.extend(found)
            
            if matches:
                results['threats'].append(category)
                results['matched_patterns'].extend(matches)
        
        # Calculate confidence based on matches
        if results['threats']:
            results['is_malicious'] = True
            
            # More threats = higher confidence
            base_confidence = min(len(results['threats']) * 0.25, 0.8)
            
            # Hidden context increases confidence
            context_multiplier = 1.3 if context == 'hidden' else 1.0
            
            # Critical patterns boost confidence
            critical_categories = ['direct_override', 'system_impersonation', 'exfiltration']
            has_critical = any(cat in results['threats'] for cat in critical_categories)
            critical_boost = 0.2 if has_critical else 0.0
            
            results['confidence'] = min(base_confidence * context_multiplier + critical_boost, 1.0)
            
            # Determine severity
            if results['confidence'] > 0.8:
                results['severity'] = 'critical'
            elif results['confidence'] > 0.6:
                results['severity'] = 'high'
            elif results['confidence'] > 0.4:
                results['severity'] = 'medium'
            else:
                results['severity'] = 'low'
        
        return results
    
    def analyze_text_structure(self, text: str) -> Dict:
        """Analyze text structure for anomalies"""
        return {
            'character_count': len(text),
            'word_count': len(text.split()),
            'line_count': len(text.split('\n')),
            'has_special_chars': bool(re.search(r'[<>{}|\[\]]', text)),
            'has_urls': bool(re.search(r'https?://', text)),
            'capitalization_ratio': self._calc_caps_ratio(text),
            'punctuation_density': self._calc_punct_density(text),
        }
    
    def _calc_caps_ratio(self, text: str) -> float:
        """Calculate ratio of uppercase to total letters"""
        letters = [c for c in text if c.isalpha()]
        if not letters:
            return 0.0
        caps = [c for c in letters if c.isupper()]
        return len(caps) / len(letters)
    
    def _calc_punct_density(self, text: str) -> float:
        """Calculate punctuation density"""
        if not text:
            return 0.0
        punct = len([c for c in text if c in '!?.:;,'])
        return punct / len(text)
