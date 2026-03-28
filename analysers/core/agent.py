from playwright.sync_api import sync_playwright, Page
from typing import Dict, List, Optional
import json
import os

import google.generativeai as genai
from dotenv import load_dotenv


class AgenticBrowser:
    """
    AI-powered browser agent that can navigate and interact with web pages
    Protected by the security layer
    """

    def __init__(self, security_mediator, config: Dict):
        self.security_mediator = security_mediator

        # 🔁 Anthropic → Gemini (NO logic change)
        load_dotenv()
        genai.configure(
            api_key=os.getenv("GEMINI_API_KEY") or config.get("gemini_api_key")
        )
        self.anthropic = genai.GenerativeModel("gemini-2.5-flash-lite")

        # Keep same variable name + intent
        self.model = "gemini-2.5-flash-lite"

        self.browser = None
        self.page = None
        self.current_goal = ""

    def launch(self, headless: bool = True):
        """Launch the browser (safe for repeated calls)"""
        if getattr(self, "_playwright", None) is None:
            self._playwright = sync_playwright().start()
            self.browser = self._playwright.chromium.launch(headless=headless)
            self.page = self.browser.new_page()


    def close(self):
        """Close the browser"""
        if self.browser:
            self.browser.close()
            self.browser = None

        if getattr(self, "_playwright", None):
            self._playwright.stop()
            self._playwright = None


    def navigate_and_execute(self, url: str, goal: str) -> Dict:
        """
        Navigate to a URL and execute a task with security protection
        """
        self.current_goal = goal

        print(f"🌐 Navigating to: {url}")
        # Only navigate if we're not already on an injected page
        if url != "about:blank":
            self.page.goto(url, wait_until='networkidle')


        page_content = self.page.content()

        print("🔒 Running security analysis...")
        security_assessment = self.security_mediator.analyze_page(
            page_content=page_content,
            agent_goal=goal
        )

        print(f"\n{security_assessment['explanation']}\n")

        action = security_assessment["action"]

        if action == "BLOCK":
            return {
                "status": "BLOCKED",
                "reason": "Page deemed malicious by security layer",
                "security_assessment": security_assessment,
                "task_completed": False
            }

        if action == "CONFIRM":
            print("⚠️  SECURITY WARNING: This page requires manual confirmation")
            user_approval = input("Proceed anyway? (yes/no): ")
            if user_approval.lower() != "yes":
                return {
                    "status": "BLOCKED_BY_USER",
                    "security_assessment": security_assessment,
                    "task_completed": False
                }

        print(f"🛡️ Security check passed. Evaluating task intent under security constraints:")
        print(f"   ▶ Requested goal: {goal}")

        try:
            result = self._execute_task(goal, page_content, security_assessment)
            return {
                "status": "SUCCESS",
                "result": result,
                "security_assessment": security_assessment,
                "task_completed": True
            }
        except Exception as e:
            print("❌ EXECUTION ERROR:", e)
            return {
                'status': 'ERROR',
                'error': str(e),
                'security_assessment': security_assessment,
                'task_completed': False
            }


    def _execute_task(self, goal: str, page_content: str, security_context: Dict) -> Dict:
        """
        Use LLM to decide what actions to take, with security validation
        """
        page_text = self.page.evaluate("() => document.body.innerText")

        prompt = f"""You are controlling a web browser. 

        Current page text (truncated):
        {page_text[:2000]}

        Your goal: {goal}

        What action should you take? Respond in JSON:
        {{
            "action_type": "click" | "fill" | "navigate" | "submit" | "none",
        "selector": "CSS selector of element (if applicable)",
            "value": "text to enter (if filling form)",
            "reasoning": "why you chose this action"
        }}

        If the goal is already complete or cannot be completed, use "none".
        """

        response = self.anthropic.generate_content(prompt)

        # ✅ SAFE text extraction for Gemini
        response_text = ""
        if hasattr(response, "text") and response.text:
            response_text = response.text
        elif hasattr(response, "candidates") and response.candidates:
            response_text = response.candidates[0].content.parts[0].text
        else:
            raise ValueError("Gemini returned empty response")


        # Parse JSON response (UNCHANGED)
        if "```json" in response_text:
            json_str = response_text.split("```json")[1].split("```")[0].strip()
        else:
            json_str = response_text.strip()

        action_plan = json.loads(json_str)

        action_validation = self.security_mediator.validate_action(
            action=str(action_plan),
            page_context={
                "visible_text": page_text,
                "risk_score": security_context["risk_score"]
            }
        )

        if action_validation.get("recommendation") == "block":
            return {
                "action": "BLOCKED",
                "reason": f"Action validation failed: {action_validation.get('concerns')}"
            }

        return self._perform_action(action_plan)

    def _perform_action(self, action_plan: Dict) -> Dict:
        """Actually perform the browser action"""
        action_type = action_plan.get("action_type")

        try:
            if action_type == "none":
                return {"action": "none", "status": "complete"}

            elif action_type == "fill":
                selector = action_plan.get("selector")
                value = action_plan.get("value")

                if not selector:
                    return {
                        "action": "fill",
                        "status": "skipped",
                        "reason": "missing selector"
                    }

                # ✅ CRITICAL FIX
                if not self.page.query_selector(selector):
                    return {
                        "action": "fill",
                        "status": "skipped",
                        "reason": f"selector not found: {selector}"
                    }

                self.page.fill(selector, value)
                return {
                    "action": "fill",
                    "selector": selector,
                    "status": "success"
                }

            elif action_type == "click":
                selector = action_plan.get("selector")

                if not selector:
                    return {
                        "action": "click",
                        "status": "skipped",
                        "reason": "missing selector"
                    }

                if not self.page.query_selector(selector):
                    return {
                        "action": "click",
                        "status": "skipped",
                        "reason": f"selector not found: {selector}"
                    }

                self.page.click(selector)
                return {
                    "action": "click",
                    "selector": selector,
                    "status": "success"
                }

            elif action_type == "submit":
                selector = action_plan.get("selector", "form")

                if not self.page.query_selector(selector):
                    return {
                        "action": "submit",
                        "status": "skipped",
                        "reason": f"form not found: {selector}"
                    }

                self.page.click(f"{selector} button[type='submit']")
                return {
                    "action": "submit",
                    "status": "success"
                }

            elif action_type == "navigate":
                url = action_plan.get("value")
                self.page.goto(url)
                return {
                    "action": "navigate",
                    "url": url,
                    "status": "success"
                }

            return {"action": "unknown", "status": "error"}

        except Exception as e:
            return {
                "action": action_type,
                "status": "error",
                "error": str(e)
            }