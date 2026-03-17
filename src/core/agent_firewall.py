import os
import time
from datetime import datetime
from typing import Dict, List
from collections import defaultdict
from urllib.parse import urlparse


class AgentFirewall:
    BLOCKED_DOMAINS = [
        "evil.com",
        "malicious-site.com",
        "phishing-example.com",
        "malicious.com",
        "steal-credentials.com",
    ]

    MAX_REQUESTS_PER_MINUTE = 30
    MAX_BLOCKS_BEFORE_SESSION_BAN = 3

    def __init__(self):
        self.request_log = []
        self.session_tracker = defaultdict(list)
        self.blocked_sessions = set()
        self.action_sequences = defaultdict(list)

    def verify_api_key(self, api_key: str) -> bool:
        expected_key = os.getenv("FIREWALL_API_KEY", "")
        if expected_key == "":
            return True
        return api_key == expected_key

    def check_rate_limit(self, session_id: str) -> bool:
        now = time.time()
        minute_ago = now - 60
        self.session_tracker[session_id] = [
            timestamp
            for timestamp in self.session_tracker[session_id]
            if timestamp > minute_ago
        ]

        if len(self.session_tracker[session_id]) >= self.MAX_REQUESTS_PER_MINUTE:
            return False

        self.session_tracker[session_id].append(now)
        return True

    def check_url(self, url: str) -> Dict:
        domain = self._extract_domain(url)
        if domain in self.BLOCKED_DOMAINS:
            return {
                "allowed": False,
                "reason": f"Domain {domain} is blocklisted",
                "confidence": 1.0,
                "risk_level": "critical",
                "risk_factors": ["blocklisted_domain"],
            }

        return {
            "allowed": True,
            "reason": "URL passed pre-check",
            "confidence": 1.0,
            "risk_level": "low",
            "risk_factors": [],
        }

    def pre_flight(self, url: str, api_key: str, session_id: str) -> Dict:
        if not self.verify_api_key(api_key):
            return {
                "allowed": False,
                "reason": "Invalid API key — unauthorized request",
                "confidence": 1.0,
                "risk_level": "critical",
                "risk_factors": ["auth_failed"],
            }

        if session_id in self.blocked_sessions:
            return {
                "allowed": False,
                "reason": "Session blocked due to repeated suspicious activity",
                "confidence": 1.0,
                "risk_level": "critical",
                "risk_factors": ["session_blocked"],
            }

        if not self.check_rate_limit(session_id):
            return {
                "allowed": False,
                "reason": "Rate limit exceeded — too many requests",
                "confidence": 1.0,
                "risk_level": "high",
                "risk_factors": ["rate_limited"],
            }

        url_check = self.check_url(url)
        if not url_check["allowed"]:
            return {
                "allowed": False,
                "reason": url_check["reason"],
                "confidence": 1.0,
                "risk_level": "critical",
                "risk_factors": url_check["risk_factors"],
            }

        return {
            "allowed": True,
            "reason": "All pre-flight checks passed",
            "confidence": 1.0,
            "risk_level": "low",
            "risk_factors": [],
        }

    def log_request(
        self,
        session_id: str,
        url: str,
        decision: str,
        risk_score: float,
    ):
        entry = {
            "timestamp": datetime.utcnow().isoformat() + "Z",
            "session_id": session_id,
            "url": url,
            "decision": decision,
            "risk_score": risk_score,
        }
        self.request_log.append(entry)

        recent_blocks = [
            e
            for e in self.request_log
            if e["session_id"] == session_id and e["decision"] == "BLOCK"
        ]
        if len(recent_blocks) >= self.MAX_BLOCKS_BEFORE_SESSION_BAN:
            self.blocked_sessions.add(session_id)

    def get_audit_log(self, session_id: str = None) -> List[Dict]:
        if session_id is not None:
            return [
                entry
                for entry in self.request_log
                if entry["session_id"] == session_id
            ]
        return self.request_log

    def get_stats(self) -> Dict:
        total_blocked = sum(
            1 for entry in self.request_log if entry["decision"] == "BLOCK"
        )
        total_allowed = sum(
            1 for entry in self.request_log if entry["decision"] == "ALLOW"
        )
        active_sessions = len(
            {entry["session_id"] for entry in self.request_log}
        )

        return {
            "total_requests": len(self.request_log),
            "total_blocked": total_blocked,
            "total_allowed": total_allowed,
            "blocked_sessions": list(self.blocked_sessions),
            "active_sessions": active_sessions,
        }

    def _extract_domain(self, url: str) -> str:
        try:
            return urlparse(url).netloc.lower()
        except Exception:
            return ""
    
    def log_action(self, session_id: str, action_type: str, url: str) -> Dict:
        action_entry = {
            "action": action_type,
            "url": url,
            "timestamp": time.time(),
        }
        self.action_sequences[session_id].append(action_entry)
        return self._check_sequence_anomaly(session_id)
    
    def _check_sequence_anomaly(self, session_id: str) -> Dict:
        actions = self.action_sequences[session_id][-10:]
        click_count = sum(1 for a in actions if a["action"] == "click")
        submit_count = sum(1 for a in actions if a["action"] == "submit")
        domains = set(self._extract_domain(a["url"]) for a in actions)
    
        if click_count >= 5:
            return {
                "is_anomalous": True,
                "reason": "Abnormal action chain detected — rapid repeated clicks",
                "confidence": 0.85,
            }
        if submit_count > 2:
            return {
                "is_anomalous": True,
                "reason": "Abnormal action chain detected — multiple form submissions",
                "confidence": 0.90,
            }
        if len(domains) > 4:
            return {
                "is_anomalous": True,
                "reason": "Abnormal action chain detected — rapid domain switching",
                "confidence": 0.80,
            }
        return {
            "is_anomalous": False,
            "reason": "Normal behaviour pattern",
            "confidence": 1.0,
        }
    
    def get_behaviour_profile(self, session_id: str) -> Dict:
        sequence = self.action_sequences[session_id]
        action_counts = defaultdict(int)
        for a in sequence:
            action_counts[a["action"]] += 1
        return {
            "session_id": session_id,
            "total_actions": len(sequence),
            "recent_actions": sequence[-10:],
            "is_flagged": session_id in self.blocked_sessions,
            "action_counts": dict(action_counts),
        }
