from typing import Dict, List

class ExplanationGenerator:
    """
    Generates human-readable explanations for security decisions
    Critical for the Interpretability scoring criterion
    """
    
    def generate_explanation(self,
                           risk_report: Dict,
                           dom_results: Dict,
                           nlp_results: Dict,
                           llm_results: Dict = None) -> str:
        """
        Generate comprehensive, human-readable explanation
        """
        
        explanation_parts = []
        
        # Header with overall assessment
        action = risk_report['action']
        risk_score = risk_report['total_risk_score']
        
        action_emoji = {
            'BLOCK': '🛑',
            'CONFIRM': '⚠️',
            'WARN': '⚡',
            'ALLOW': '✅'
        }
        
        explanation_parts.append(f"{action_emoji.get(action, '❓')} SECURITY ASSESSMENT: {action}")
        explanation_parts.append(f"Risk Score: {risk_score:.2f}/1.00")
        explanation_parts.append(f"Confidence: {risk_report['confidence']:.2f}")
        explanation_parts.append("")
        
        # Detailed findings
        explanation_parts.append("=== THREAT ANALYSIS ===")
        
        # DOM findings
        if dom_results.get('hidden_elements'):
            hidden_count = len(dom_results['hidden_elements'])
            critical_count = sum(1 for h in dom_results['hidden_elements'] 
                               if h.get('severity') == 'critical')
            
            explanation_parts.append(f"• Hidden Content: {hidden_count} hidden elements detected")
            if critical_count > 0:
                explanation_parts.append(f"  └─ {critical_count} marked as CRITICAL")
            
            # Show sample hidden text
            for hidden in dom_results['hidden_elements'][:3]:
                method = hidden.get('method', 'unknown')
                text_preview = hidden.get('text', '')[:100]
                explanation_parts.append(f"  └─ Method: {method}")
                explanation_parts.append(f"     Text: \"{text_preview}...\"")
        
        # Form analysis
        if dom_results.get('suspicious_forms'):
            forms = dom_results['suspicious_forms']
            explanation_parts.append(f"• Suspicious Forms: {len(forms)} detected")
            for form in forms[:2]:
                if form.get('has_password'):
                    explanation_parts.append(f"  └─ Password field submitting to: {form.get('action', 'unknown')}")
                explanation_parts.append(f"     Risk: {form.get('risk_score', 0):.2f}")
        
        # NLP findings
        if nlp_results.get('is_malicious'):
            explanation_parts.append(f"• NLP Detection: {nlp_results['severity'].upper()} threat")
            explanation_parts.append(f"  └─ Confidence: {nlp_results['confidence']:.2f}")
            
            threats = nlp_results.get('threats', [])
            for threat in threats[:3]:
                threat_readable = threat.replace('_', ' ').title()
                explanation_parts.append(f"  └─ Type: {threat_readable}")
            
            # Show matched patterns
            patterns = nlp_results.get('matched_patterns', [])
            if patterns:
                explanation_parts.append(f"  └─ Matched patterns:")
                for pattern in patterns[:3]:
                    explanation_parts.append(f"     • \"{pattern}\"")
        
        # LLM reasoning
        if llm_results:
            explanation_parts.append(f"• AI Analysis: {llm_results.get('threat_type', 'unknown').upper()}")
            explanation_parts.append(f"  └─ Assessment: {llm_results.get('reasoning', 'N/A')}")
            explanation_parts.append(f"  └─ Recommendation: {llm_results.get('recommended_action', 'N/A').upper()}")
        
        explanation_parts.append("")
        
        # Component scores breakdown
        explanation_parts.append("=== RISK BREAKDOWN ===")
        scores = risk_report.get('component_scores', {})
        for component, score in scores.items():
            if score > 0:
                component_readable = component.replace('_', ' ').title()
                bar = self._generate_progress_bar(score)
                explanation_parts.append(f"• {component_readable}: {score:.3f} {bar}")
        
        explanation_parts.append("")
        
        # Threat indicators summary
        indicators = risk_report.get('threat_indicators', [])
        if indicators:
            explanation_parts.append("=== THREAT INDICATORS ===")
            for indicator in indicators:
                explanation_parts.append(f"• {indicator}")
            explanation_parts.append("")
        
        # Mitigation recommendations
        mitigations = risk_report.get('mitigations', [])
        if mitigations:
            explanation_parts.append("=== RECOMMENDED ACTIONS ===")
            for mitigation in mitigations:
                explanation_parts.append(f"• {mitigation}")
        
        return "\n".join(explanation_parts)
    
    def _generate_progress_bar(self, value: float, length: int = 20) -> str:
        """Generate ASCII progress bar"""
        filled = int(value * length)
        bar = '█' * filled + '░' * (length - filled)
        return f"[{bar}]"
    
    def generate_action_explanation(self, action: str, context: Dict) -> str:
        """
        Generate explanation for a specific action decision
        """
        if action == 'BLOCK':
            return f"Action BLOCKED: High risk detected ({context.get('risk_score', 0):.2f}). Manual review required."
        elif action == 'CONFIRM':
            return f"Action requires CONFIRMATION: Medium risk ({context.get('risk_score', 0):.2f}). Please verify before proceeding."
        elif action == 'WARN':
            return f"Action allowed with WARNING: Low-medium risk ({context.get('risk_score', 0):.2f}). Monitoring enabled."
        else:
            return f"Action ALLOWED: Low risk ({context.get('risk_score', 0):.2f}). Proceeding normally."
