import time
from typing import Dict, List
from collections import deque
import statistics

class PerformanceMonitor:
    """
    Track performance metrics for the security layer
    Critical for Performance and Latency scoring
    """
    
    def __init__(self, window_size: int = 100):
        self.window_size = window_size
        self.latencies = deque(maxlen=window_size)
        self.layer_timings = {
            'dom_analysis': deque(maxlen=window_size),
            'nlp_classification': deque(maxlen=window_size),
            'llm_reasoning': deque(maxlen=window_size),
            'total': deque(maxlen=window_size)
        }
        
    def record_analysis(self, latency_ms: float):
        """Record overall analysis latency"""
        self.latencies.append(latency_ms)
        self.layer_timings['total'].append(latency_ms)
    
    def record_layer_timing(self, layer: str, duration_ms: float):
        """Record timing for specific layer"""
        if layer in self.layer_timings:
            self.layer_timings[layer].append(duration_ms)
    
    def get_statistics(self) -> Dict:
        """Get performance statistics"""
        if not self.latencies:
            return {
                'average_latency_ms': 0.0,
                'median_latency_ms': 0.0,
                'p95_latency_ms': 0.0,
                'p99_latency_ms': 0.0,
                'min_latency_ms': 0.0,
                'max_latency_ms': 0.0
            }
        
        latencies_list = list(self.latencies)
        
        return {
            'average_latency_ms': round(statistics.mean(latencies_list), 2),
            'median_latency_ms': round(statistics.median(latencies_list), 2),
            'p95_latency_ms': round(self._percentile(latencies_list, 0.95), 2),
            'p99_latency_ms': round(self._percentile(latencies_list, 0.99), 2),
            'min_latency_ms': round(min(latencies_list), 2),
            'max_latency_ms': round(max(latencies_list), 2),
            'total_measurements': len(latencies_list)
        }
    
    def get_layer_breakdown(self) -> Dict:
        """Get timing breakdown by layer"""
        breakdown = {}
        
        for layer, timings in self.layer_timings.items():
            if timings:
                breakdown[layer] = {
                    'average_ms': round(statistics.mean(timings), 2),
                    'median_ms': round(statistics.median(timings), 2)
                }
        
        return breakdown
    
    def _percentile(self, data: List[float], percentile: float) -> float:
        """Calculate percentile value"""
        sorted_data = sorted(data)
        index = int(len(sorted_data) * percentile)
        return sorted_data[min(index, len(sorted_data) - 1)]
    
    def is_meeting_sla(self, sla_ms: float = 500) -> bool:
        """Check if performance meets SLA"""
        stats = self.get_statistics()
        return stats['p95_latency_ms'] < sla_ms
