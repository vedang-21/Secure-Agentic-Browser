from typing import Dict, List
import math

class MultiFactorRiskCalculator:
    """
    Calculates risk score from multiple analysis layers
    Optimized for high precision and low false positives
    """
    
    # Configurable weights for different factors
    WEIGHTS = {
        'dom_analysis': 0.20,
        'nlp_classification': 0.30,
        'llm_reasoning': 0.35,
        'behavioral_signals': 0.15,
    }
    
    # Risk thresholds
    THRESHOLDS = {
        'block': 0.80,      # Block immediately
        'confirm': 0.50,    # Require human confirmation
        'warn': 0.30,       # Log warning but allow
        'allow': 0.0,       # Safe to proceed
    }
    
    def calculate_risk(self, 
                      dom_results: Dict,
                      nlp_results: Dict,
                      llm_results: Dict = None,
                      behavioral_signals: Dict = None) -> Dict:
        """
        Multi-factor risk calculation with weighted scoring
        
        Returns comprehensive risk assessment
        """
        
        # Calculate individual component scores
        dom_score = self._score_dom_analysis(dom_results)
        nlp_score = self._score_nlp_results(nlp_results)
        llm_score = self._score_llm_results(llm_results) if llm_results else 0.0
        behavior_score = self._score_behavioral(behavioral_signals) if behavioral_signals else 0.0
        
        # Weighted combination
        weights = self.WEIGHTS
        total_risk = (
            dom_score * weights['dom_analysis'] +
            nlp_score * weights['nlp_classification'] +
            llm_score * weights['llm_reasoning'] +
            behavior_score * weights['behavioral_signals']
        )
        
        # Normalize to 0-1
        total_risk = max(0.0, min(1.0, total_risk))
        
        # Determine action
        action = self._determine_action(total_risk)
        
        # Build comprehensive report
        risk_report = {
            'total_risk_score': round(total_risk, 3),
            'action': action,
            'confidence': self._calculate_confidence(dom_results, nlp_results, llm_results),
            'component_scores': {
                'dom_analysis': round(dom_score, 3),
                'nlp_classification': round(nlp_score, 3),
                'llm_reasoning': round(llm_score, 3),
                'behavioral': round(behavior_score, 3),
            },
            'threat_indicators': self._collect_threat_indicators(
                dom_results, nlp_results, llm_results
            ),
            'mitigations': self._suggest_mitigations(total_risk, action),
        }
        
        return risk_report
    
    def _score_dom_analysis(self, dom_results: Dict) -> float:
        """Score DOM analysis results (0.0 - 1.0)"""
        score = 0.0
        
        # Hidden elements
        hidden = dom_results.get('hidden_elements', [])
        if hidden:
            # More hidden elements = higher score
            score += min(len(hidden) * 0.15, 0.4)
            
            # Critical hidden elements boost score
            critical_count = sum(1 for h in hidden if h.get('severity') == 'critical')
            score += critical_count * 0.2
        
        # Suspicious forms
        forms = dom_results.get('suspicious_forms', [])
        if forms:
            high_risk_forms = [f for f in forms if f.get('risk_score', 0) > 0.6]
            score += min(len(high_risk_forms) * 0.25, 0.5)
        
        # External iframes
        iframes = dom_results.get('iframe_analysis', [])
        external_iframes = [i for i in iframes if i.get('is_external')]
        score += min(len(external_iframes) * 0.1, 0.3)
        
        # Risky scripts
        scripts = dom_results.get('script_analysis', {})
        if scripts.get('risky_inline_count', 0) > 0:
            score += 0.2
        
        return min(score, 1.0)
    
    def _score_nlp_results(self, nlp_results: Dict) -> float:
        """Score NLP classification (0.0 - 1.0)"""
        if not nlp_results.get('is_malicious'):
            return 0.0
        
        # Use NLP's own confidence as base
        confidence = nlp_results.get('confidence', 0.0)
        
        # Boost based on threat types
        threats = nlp_results.get('threats', [])
        critical_threats = ['direct_override', 'system_impersonation', 'exfiltration']
        
        has_critical = any(t in threats for t in critical_threats)
        threat_count_factor = min(len(threats) * 0.1, 0.3)
        critical_boost = 0.2 if has_critical else 0.0
        
        score = confidence + threat_count_factor + critical_boost
        
        return min(score, 1.0)
    
    def _score_llm_results(self, llm_results: Dict) -> float:
        """Score LLM reasoning (0.0 - 1.0)"""
        if not llm_results:
            return 0.0
        
        if llm_results.get('is_malicious'):
            return llm_results.get('confidence', 0.7)
        
        return 0.0
    
    def _score_behavioral(self, behavioral: Dict) -> float:
        """Score behavioral signals"""
        # Placeholder for runtime behavioral monitoring
        # Could include: rapid page changes, multiple redirects, etc.
        return 0.0
    
    def _determine_action(self, risk_score: float) -> str:
        """Map risk score to action"""
        if risk_score >= self.THRESHOLDS['block']:
            return 'BLOCK'
        elif risk_score >= self.THRESHOLDS['confirm']:
            return 'CONFIRM'
        elif risk_score >= self.THRESHOLDS['warn']:
            return 'WARN'
        else:
            return 'ALLOW'
    
    def _calculate_confidence(self, dom, nlp, llm) -> float:
        """Calculate confidence in the risk assessment"""
        # More analysis layers = higher confidence
        layers_used = sum([
            bool(dom),
            bool(nlp),
            bool(llm)
        ])
        
        base_confidence = layers_used / 3.0
        
        # Agreement between layers increases confidence
        if nlp and llm:
            if nlp.get('is_malicious') == llm.get('is_malicious'):
                base_confidence += 0.2
        
        return min(base_confidence, 1.0)
    
    def _collect_threat_indicators(self, dom, nlp, llm) -> List[str]:
        """Collect all detected threat indicators"""
        indicators = []
        
        if dom:
            if dom.get('hidden_elements'):
                indicators.append(f"{len(dom['hidden_elements'])} hidden elements detected")
            if dom.get('suspicious_forms'):
                indicators.append(f"{len(dom['suspicious_forms'])} suspicious forms found")
        
        if nlp and nlp.get('threats'):
            for threat in nlp['threats']:
                indicators.append(f"NLP detected: {threat}")
        
        if llm and llm.get('is_malicious'):
            indicators.append(f"LLM assessment: {llm.get('threat_type')}")
        
        return indicators
    
    def _suggest_mitigations(self, risk_score: float, action: str) -> List[str]:
        """Suggest mitigation strategies"""
        mitigations = []
        
        if action == 'BLOCK':
            mitigations.append("Action blocked - manual review required")
            mitigations.append("Alert security team")
        elif action == 'CONFIRM':
            mitigations.append("Request human confirmation before proceeding")
            mitigations.append("Display detected threats to user")
        elif action == 'WARN':
            mitigations.append("Log suspicious activity")
            mitigations.append("Monitor subsequent actions closely")
        
        return mitigations
