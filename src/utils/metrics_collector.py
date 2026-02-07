from typing import Dict, List, Tuple
import json

class MetricsCollector:
    """
    Collect and calculate evaluation metrics
    Critical for Attack Detection Accuracy scoring
    """
    
    def __init__(self):
        self.predictions = []  # List of (predicted, actual, confidence)
        self.reset()
    
    def reset(self):
        """Reset all metrics"""
        self.predictions = []
        self.true_positives = 0
        self.true_negatives = 0
        self.false_positives = 0
        self.false_negatives = 0
    
    def record_prediction(self, 
                         predicted_malicious: bool,
                         actual_malicious: bool,
                         confidence: float = 1.0):
        """
        Record a single prediction
        
        Args:
            predicted_malicious: What the system predicted
            actual_malicious: Ground truth label
            confidence: Confidence score (0-1)
        """
        self.predictions.append({
            'predicted': predicted_malicious,
            'actual': actual_malicious,
            'confidence': confidence
        })
        
        # Update confusion matrix
        if predicted_malicious and actual_malicious:
            self.true_positives += 1
        elif not predicted_malicious and not actual_malicious:
            self.true_negatives += 1
        elif predicted_malicious and not actual_malicious:
            self.false_positives += 1
        elif not predicted_malicious and actual_malicious:
            self.false_negatives += 1
    
    def calculate_metrics(self) -> Dict:
        """
        Calculate precision, recall, F1, accuracy
        """
        # Avoid division by zero
        precision = 0.0
        if (self.true_positives + self.false_positives) > 0:
            precision = self.true_positives / (self.true_positives + self.false_positives)
        
        recall = 0.0
        if (self.true_positives + self.false_negatives) > 0:
            recall = self.true_positives / (self.true_positives + self.false_negatives)
        
        f1_score = 0.0
        if (precision + recall) > 0:
            f1_score = 2 * (precision * recall) / (precision + recall)
        
        total = self.true_positives + self.true_negatives + self.false_positives + self.false_negatives
        accuracy = 0.0
        if total > 0:
            accuracy = (self.true_positives + self.true_negatives) / total
        
        return {
            'precision': round(precision, 4),
            'recall': round(recall, 4),
            'f1_score': round(f1_score, 4),
            'accuracy': round(accuracy, 4),
            'true_positives': self.true_positives,
            'true_negatives': self.true_negatives,
            'false_positives': self.false_positives,
            'false_negatives': self.false_negatives,
            'total_samples': total,
            'detection_rate': round(recall, 4),  # Same as recall
            'false_positive_rate': round(self.false_positives / max(total, 1), 4),
            'false_negative_rate': round(self.false_negatives / max(total, 1), 4)
        }
    
    def export_results(self, filepath: str):
        """Export detailed results to JSON"""
        metrics = self.calculate_metrics()
        
        export_data = {
            'summary_metrics': metrics,
            'detailed_predictions': self.predictions,
            'confusion_matrix': {
                'TP': self.true_positives,
                'TN': self.true_negatives,
                'FP': self.false_positives,
                'FN': self.false_negatives
            }
        }
        
        with open(filepath, 'w') as f:
            json.dump(export_data, f, indent=2)
