
# Multi-Layer Security Mediator

This system protects AI agents by analyzing web pages across four specialized layers.

## 🛠 Core Implementation

### Layer 1: DOM Analyzer

This layer scans for hidden elements and suspicious HTML structures.

```python
from bs4 import BeautifulSoup

class DOMAnalyzer:
    def analyze(self, page_content: str):
        soup = BeautifulSoup(page_content, 'html.parser')
        # Logic to find hidden text or malicious iframes
        return {"status": "scanned", "hidden_elements": []}

```

### Layer 2: NLP Classifier

Uses pattern matching to detect prompt injection attempts like "Ignore previous instructions."

```python
import re

class NLPThreatClassifier:
    patterns = [r"ignore previous instructions", r"system override"]
    
    def classify(self, text):
        for p in self.patterns:
            if re.search(p, text, re.I):
                return "Threat Detected"
        return "Clean"

```

### Layer 3: LLM Reasoner

Deep analysis using Claude for complex or "gray area" threats.

```python
from anthropic import Anthropic

class LLMThreatReasoner:
    def analyze_intent(self, text, goal):
        # Sends content to Claude to check if page intent aligns with agent goal
        pass

```

---


