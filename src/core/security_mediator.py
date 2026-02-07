import time
from typing import Dict, Optional
from analyzers.dom_analyzer import DOMAnalyzer
from analyzers.nlp_classifier import NLPThreatClassifier
from analyzers.llm_reasoner import LLMThreatReasoner
from policies.risk_calculator import MultiFactorRiskCalculator
from utils.performance_monitor import PerformanceMonitor
from utils.explanation_generator import ExplanationGenerator


class SecurityMediator:
    """
    Main orchestrator - routes through security layers efficiently
    Optimized for low latency while maintaining high accuracy
    """

    def __init__(self, config: Dict):
        # Initialize all analyzers
        self.dom_analyzer = DOMAnalyzer()
        self.nlp_classifier = NLPThreatClassifier()

        # 🔁 Anthropic → Gemini (NO logic change)
        self.llm_reasoner = LLMThreatReasoner(
            config.get('gemini_api_key')
        )

        self.risk_calculator = MultiFactorRiskCalculator()
        self.performance_monitor = PerformanceMonitor()
        self.explainer = ExplanationGenerator()

        # Configuration
        self.use_llm_for_borderline = config.get('use_llm_layer', True)
        self.llm_threshold = config.get('llm_threshold', 0.4)

        # Metrics tracking
        self.metrics = {
            'total_pages_analyzed': 0,
            'threats_detected': 0,
            'actions_blocked': 0,
            'false_positives': 0,
            'average_latency_ms': 0.0,
        }

    def analyze_page(self, page_content: str, agent_goal: str = "") -> Dict:
        """
        Main entry point - analyze a page through security layers
        """
        start_time = time.time()

        # Layer 1: Fast DOM analysis
        dom_results = self.dom_analyzer.analyze(page_content)

        visible_text = self._extract_visible_text(page_content)
        hidden_text = self._extract_hidden_text(dom_results)

        # Layer 2: NLP classification
        nlp_visible = self.nlp_classifier.classify_text(visible_text, context='visible')
        nlp_hidden = self.nlp_classifier.classify_text(hidden_text, context='hidden')

        nlp_results = self._combine_nlp_results(nlp_visible, nlp_hidden)

        initial_risk = self._quick_risk_check(dom_results, nlp_results)

        llm_results = None
        if initial_risk > self.llm_threshold and self.use_llm_for_borderline:
            # Layer 3: LLM reasoning (unchanged)
            llm_results = self.llm_reasoner.analyze_intent(
                visible_text=visible_text,
                hidden_text=hidden_text,
                agent_goal=agent_goal,
                dom_analysis=dom_results
            )

        # Layer 4: Risk calculation
        risk_report = self.risk_calculator.calculate_risk(
            dom_results=dom_results,
            nlp_results=nlp_results,
            llm_results=llm_results
        )

        explanation = self.explainer.generate_explanation(
            risk_report=risk_report,
            dom_results=dom_results,
            nlp_results=nlp_results,
            llm_results=llm_results
        )

        latency_ms = (time.time() - start_time) * 1000
        self.performance_monitor.record_analysis(latency_ms)

        self.metrics['total_pages_analyzed'] += 1
        if risk_report['action'] in ['BLOCK', 'CONFIRM']:
            self.metrics['threats_detected'] += 1
        if risk_report['action'] == 'BLOCK':
            self.metrics['actions_blocked'] += 1

        return {
            'risk_score': risk_report['total_risk_score'],
            'action': risk_report['action'],
            'confidence': risk_report['confidence'],
            'explanation': explanation,
            'detailed_analysis': {
                'dom': dom_results,
                'nlp': nlp_results,
                'llm': llm_results,
                'risk_breakdown': risk_report
            },
            'performance': {
                'latency_ms': round(latency_ms, 2),
                'layers_used': self._count_layers_used(llm_results)
            }
        }

    def validate_action(self, action: str, page_context: Dict) -> Dict:
        """
        Validate a specific agent action before execution
        """
        if page_context.get('risk_score', 0) > 0.3:
            validation = self.llm_reasoner.validate_agent_action(
                intended_action=action,
                page_context=str(page_context.get('visible_text', ''))
            )
            return validation

        return {
            'is_safe': True,
            'risk_level': 'low',
            'recommendation': 'proceed'
        }

    def _extract_visible_text(self, page_content: str) -> str:
        from bs4 import BeautifulSoup
        soup = BeautifulSoup(page_content, 'html.parser')

        for script in soup(['script', 'style']):
            script.decompose()

        return soup.get_text(separator=' ', strip=True)

    def _extract_hidden_text(self, dom_results: Dict) -> str:
        hidden_elements = dom_results.get('hidden_elements', [])
        hidden_texts = [elem['text'] for elem in hidden_elements]
        return ' '.join(hidden_texts)

    def _combine_nlp_results(self, visible: Dict, hidden: Dict) -> Dict:
        combined = {
            'is_malicious': visible['is_malicious'] or hidden['is_malicious'],
            'confidence': max(visible['confidence'], hidden['confidence']),
            'threats': list(set(visible['threats'] + hidden['threats'])),
            'matched_patterns': visible['matched_patterns'] + hidden['matched_patterns'],
            'severity': max(
                visible['severity'],
                hidden['severity'],
                key=lambda x: ['none', 'low', 'medium', 'high', 'critical'].index(x)
            )
        }
        return combined

    def _quick_risk_check(self, dom: Dict, nlp: Dict) -> float:
        score = 0.0

        if nlp.get('is_malicious'):
            score += nlp.get('confidence', 0.5)

        if dom.get('hidden_elements'):
            score += 0.2

        if dom.get('suspicious_forms'):
            score += 0.3

        return min(score, 1.0)

    def _count_layers_used(self, llm_results) -> int:
        return 3 if llm_results else 2

    def get_metrics(self) -> Dict:
        return self.metrics.copy()
