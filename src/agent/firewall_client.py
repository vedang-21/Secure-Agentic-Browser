import logging
import os
from typing import Any, Dict, Optional

import httpx

try:
    from dotenv import load_dotenv

    load_dotenv()
except Exception:
    pass

from firewall.core.security_mediator import SecurityMediator

logger = logging.getLogger(__name__)


class FirewallClient:
    """Adapter used by `src/agent/agent_controller.py`.

    Uses the root-level `firewall/` + `analysers/` implementation for local decisions,
    and optionally calls an external firewall API when enabled.
    """

    def __init__(self, firewall_url: str | None = None):
        self.firewall_url = firewall_url or os.getenv(
            "FIREWALL_API_URL", "http://localhost:3001/api/validate"
        )
        self.use_external_api = os.getenv("USE_EXTERNAL_FIREWALL", "false").lower() == "true"
        self.client = httpx.AsyncClient(timeout=30.0)

        self._mediator = SecurityMediator(
            {
                "gemini_api_key": os.getenv("GOOGLE_API_KEY", "")
                or os.getenv("GEMINI_API_KEY", ""),
                "use_llm_layer": os.getenv("FIREWALL_USE_LLM", "true").lower() == "true",
                "llm_threshold": float(os.getenv("FIREWALL_LLM_THRESHOLD", "0.4")),
            }
        )

        logger.info(f"🛡️ Firewall initialized - External API: {self.use_external_api}")

    async def close(self):
        await self.client.aclose()

    async def validate_action(
        self, action: Dict[str, Any], page_context: Optional[Dict[str, Any]] = None
    ) -> Dict[str, Any]:
        """Validate an intended agent action.

        Returns the existing response format used elsewhere in the codebase:
        `{allowed, reason, source, confidence, risk_factors, risk_level, analysis}`.
        """
        payload = {"action": action, "page_context": page_context or {}}

        local = self._validate_locally(payload)
        if not local["allowed"]:
            return local

        if self.use_external_api:
            external = await self._validate_with_external_api(payload)
            if external is not None:
                return external

        return local

    def _validate_locally(self, payload: Dict[str, Any]) -> Dict[str, Any]:
        action = payload.get("action") or {}
        page_context = payload.get("page_context") or {}

        action_type = action.get("action", "unknown")

        # Page assessment (html is optional; SecurityMediator expects HTML string)
        html = page_context.get("html") or page_context.get("html_content") or ""
        goal = page_context.get("agent_goal") or page_context.get("goal") or ""

        risk_summary = {"risk_score": 0.0, "action": "ALLOW", "confidence": 0.0}
        if html.strip():
            risk_summary = self._mediator.analyze_page(page_content=html, agent_goal=goal)

        # Action validation (borderline page risk)
        action_validation = self._mediator.validate_action(
            action=str(action),
            page_context={
                "visible_text": page_context.get("visible_text", ""),
                "risk_score": float(risk_summary.get("risk_score", 0.0) or 0.0),
            },
        )

        # Map mediator result to expected contract
        recommendation = (action_validation.get("recommendation") or "proceed").lower()
        is_safe = bool(action_validation.get("is_safe", True))

        blocked = (not is_safe) or recommendation == "block"
        risk_level = (action_validation.get("risk_level") or "low").lower()

        reason = "Local firewall allowed"
        confidence = float(risk_summary.get("confidence", 0.8) or 0.8)
        if blocked:
            concerns = action_validation.get("concerns") or []
            reason = "Action blocked by local firewall"
            if concerns:
                reason += f": {', '.join(concerns[:3])}"
            confidence = max(confidence, 0.9)

        risk_factors = []
        if risk_summary.get("action") in {"BLOCK", "CONFIRM", "WARN"}:
            risk_factors.append(f"page_risk_{risk_summary.get('action', 'unknown').lower()}")
        if action_validation.get("concerns"):
            risk_factors.append("action_concerns")

        return {
            "allowed": not blocked,
            "reason": reason,
            "source": "local",
            "confidence": min(max(confidence, 0.0), 1.0),
            "risk_factors": risk_factors,
            "risk_level": risk_level,
            "analysis": {
                "page_risk": risk_summary,
                "action_validation": action_validation,
            },
        }

    async def report_action_result(
        self,
        action: Dict[str, Any],
        result: Dict[str, Any],
        page_context: Optional[Dict[str, Any]] = None,
    ) -> None:
        """Compatibility hook.

        The current runner logs action outcomes and calls this method.
        For now we keep it as a lightweight no-op (or optional external report)
        so the agent loop doesn't crash.
        """

        # If you later add an external firewall that wants post-action telemetry,
        # this is the place to forward it.
        if not self.use_external_api:
            return

        report_url = os.getenv("FIREWALL_REPORT_URL")
        if not report_url:
            return

        try:
            headers: Dict[str, str] = {}
            api_key = os.getenv("FIREWALL_API_KEY")
            if api_key:
                headers["X-API-Key"] = api_key

            await self.client.post(
                report_url,
                json={
                    "action": action,
                    "result": result,
                    "page_context": page_context or {},
                },
                headers=headers,
            )
        except Exception as e:
            logger.warning(f"External firewall report unavailable: {e}")

    async def _validate_with_external_api(self, payload: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        try:
            headers = {}
            api_key = os.getenv("FIREWALL_API_KEY")
            if api_key:
                headers["X-API-Key"] = api_key

            resp = await self.client.post(self.firewall_url, json=payload, headers=headers)
            resp.raise_for_status()
            data = resp.json()

            # Normalize a minimal subset if the external API doesn't provide everything.
            return {
                "allowed": bool(data.get("allowed", False)),
                "reason": data.get("reason", "External firewall result"),
                "source": data.get("source", "external"),
                "confidence": float(data.get("confidence", 0.5) or 0.5),
                "risk_factors": data.get("risk_factors", []) or [],
                "risk_level": data.get("risk_level", "unknown"),
                "analysis": data.get("analysis", {}) or {},
                "timestamp": data.get("timestamp"),
                "processing_time_ms": data.get("processing_time_ms"),
            }
        except Exception as e:
            logger.warning(
                f"External firewall unavailable ({self.firewall_url}). "
                f"Set USE_EXTERNAL_FIREWALL=false to silence this. Error: {e}"
            )
            return None