#!/usr/bin/env python3
"""
Benchmark script to evaluate security system against test dataset
Calculates Precision, Recall, F1, and other metrics
"""

import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent.parent / 'src'))

from src.core.security_mediator import SecurityMediator
from src.utils.metrics_collector import MetricsCollector
from src.utils.performance_monitor import PerformanceMonitor
import json
import yaml
from typing import Dict, List

class SecurityBenchmark:
    """Comprehensive benchmark suite"""
    
    def __init__(self, config: Dict):
        self.security_mediator = SecurityMediator(config)
        self.metrics = MetricsCollector()
        self.performance = PerformanceMonitor()
        
    def load_test_dataset(self, dataset_path: str) -> List[Dict]:
        """Load labeled test dataset"""
        with open(dataset_path, 'r') as f:
            return json.load(f)
    
    def run_benchmark(self, dataset_path: str) -> Dict:
        """
        Run full benchmark against labeled dataset
        
        Dataset format:
        [
            {
                "id": "test_001",
                "html_file": "tests/malicious_pages/prompt_injection.html",
                "label": "malicious",
                "attack_type": "prompt_injection",
                "description": "..."
            },
            ...
        ]
        """
        print("🔬 Starting Security Benchmark...")
        print("="*80)
        
        dataset = self.load_test_dataset(dataset_path)
        
        results = []
        
        for test_case in dataset:
            test_id = test_case['id']
            html_file = test_case['html_file']
            true_label = test_case['label']  # 'malicious' or 'benign'
            
            print(f"\nTesting: {test_id} ({true_label})")
            
            # Load HTML content
            html_path = Path(__file__).parent.parent / html_file
            if not html_path.exists():
                print(f"  ⚠️  File not found: {html_file}")
                continue
            
            page_content = html_path.read_text()
            
            # Analyze with security system
            analysis = self.security_mediator.analyze_page(
                page_content=page_content,
                agent_goal="Complete the task on this page"
            )
            
            # Determine prediction
            predicted_malicious = analysis['action'] in ['BLOCK', 'CONFIRM']
            actual_malicious = (true_label == 'malicious')
            
            # Record metrics
            self.metrics.record_prediction(
                predicted_malicious=predicted_malicious,
                actual_malicious=actual_malicious,
                confidence=analysis['confidence']
            )
            
            # Record performance
            self.performance.record_analysis(analysis['performance']['latency_ms'])
            
            # Store result
            result = {
                'test_id': test_id,
                'true_label': true_label,
                'predicted_action': analysis['action'],
                'risk_score': analysis['risk_score'],
                'confidence': analysis['confidence'],
                'latency_ms': analysis['performance']['latency_ms'],
                'correct': predicted_malicious == actual_malicious
            }
            results.append(result)
            
            # Print result
            status = "✅ CORRECT" if result['correct'] else "❌ INCORRECT"
            print(f"  {status} | Action: {analysis['action']} | Risk: {analysis['risk_score']:.3f}")
        
        # Calculate final metrics
        final_metrics = self.metrics.calculate_metrics()
        performance_stats = self.performance.get_statistics()
        
        # Generate report
        report = {
            'summary': {
                'total_tests': len(results),
                'correct_predictions': sum(1 for r in results if r['correct']),
                'accuracy': final_metrics['accuracy']
            },
            'attack_detection': {
                'precision': final_metrics['precision'],
                'recall': final_metrics['recall'],
                'f1_score': final_metrics['f1_score'],
                'detection_rate': final_metrics['detection_rate']
            },
            'error_rates': {
                'false_positive_rate': final_metrics['false_positive_rate'],
                'false_negative_rate': final_metrics['false_negative_rate'],
                'false_positives': final_metrics['false_positives'],
                'false_negatives': final_metrics['false_negatives']
            },
            'performance': performance_stats,
            'detailed_results': results
        }
        
        return report
    
    def print_report(self, report: Dict):
        """Print formatted benchmark report"""
        print("\n" + "="*80)
        print("BENCHMARK RESULTS")
        print("="*80)
        
        summary = report['summary']
        print(f"\n📊 SUMMARY:")
        print(f"  Total Tests: {summary['total_tests']}")
        print(f"  Correct: {summary['correct_predictions']}")
        print(f"  Accuracy: {summary['accuracy']:.4f}")
        
        attack = report['attack_detection']
        print(f"\n🎯 ATTACK DETECTION:")
        print(f"  Precision: {attack['precision']:.4f}")
        print(f"  Recall: {attack['recall']:.4f}")
        print(f"  F1 Score: {attack['f1_score']:.4f}")
        print(f"  Detection Rate: {attack['detection_rate']:.4f}")
        
        errors = report['error_rates']
        print(f"\n⚠️  ERROR RATES:")
        print(f"  False Positive Rate: {errors['false_positive_rate']:.4f}")
        print(f"  False Negatives: {errors['false_negatives']}")
        print(f"  False Positives: {errors['false_positives']}")
        
        perf = report['performance']
        print(f"\n⚡ PERFORMANCE:")
        print(f"  Average Latency: {perf['average_latency_ms']:.2f} ms")
        print(f"  Median Latency: {perf['median_latency_ms']:.2f} ms")
        print(f"  P95 Latency: {perf['p95_latency_ms']:.2f} ms")
        print(f"  P99 Latency: {perf['p99_latency_ms']:.2f} ms")
        
        # Check SLA (500ms target)
        sla_met = perf['p95_latency_ms'] < 500
        sla_status = "✅ PASS" if sla_met else "❌ FAIL"
        print(f"  SLA (P95 < 500ms): {sla_status}")
    
    def export_report(self, report: Dict, output_path: str):
        """Export report to JSON"""
        with open(output_path, 'w') as f:
            json.dump(report, f, indent=2)
        print(f"\n💾 Report exported to: {output_path}")

def main():
    # Load config
    config_path = Path(__file__).parent.parent / 'config.yaml'
    with open(config_path, 'r') as f:
        config = yaml.safe_load(f)
    
    # Create benchmark
    benchmark = SecurityBenchmark(config)
    
    # Run benchmark
    dataset_path = Path(__file__).parent.parent / 'tests/ground_truth/labeled_dataset.json'
    
    if not dataset_path.exists():
        print(f"❌ Dataset not found: {dataset_path}")
        print("Please create the labeled dataset first.")
        return
    
    report = benchmark.run_benchmark(str(dataset_path))
    
    # Print results
    benchmark.print_report(report)
    
    # Export
    output_path = Path(__file__).parent / 'benchmark_results.json'
    benchmark.export_report(report, str(output_path))

if __name__ == '__main__':
    main()
