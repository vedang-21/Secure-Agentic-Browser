import os
import json
import logging
from typing import Dict, Any, List
import google.generativeai as genai

# Load environment variables from .env file
try:
    from dotenv import load_dotenv
    load_dotenv()
except ImportError:
    # dotenv not installed, use system environment variables
    pass

logger = logging.getLogger(__name__)

class LLMPlanner:
    def __init__(self):
        # Configure Gemini API
        api_key = os.getenv("GOOGLE_API_KEY")
        if not api_key:
            raise ValueError("GOOGLE_API_KEY environment variable is required")
        
        genai.configure(api_key=api_key)
        self.model = genai.GenerativeModel('gemini-2.5-flash')
        
        # System prompt for web browsing agent
        self.system_prompt = """
You are an intelligent web browsing agent that helps users complete tasks by controlling a browser.

Your job is to analyze the current page and decide the next action to take to complete the user's task.

Available actions:
- navigate: Go to a URL
- click: Click on an element 
- type: Type text into an input field
- type_and_submit: Type text and immediately submit (perfect for search boxes)
- submit: Submit a form or press Enter
- extract: Extract information from the page
- finish: Complete the task

Return your response as JSON in one of these formats:

{"action": "navigate", "url": "https://example.com"}

{"action": "click", "selector": "#submit-btn"}

{"action": "type", "selector": "input[name='search']", "text": "search query"}

{"action": "type_and_submit", "selector": "input[name='q']", "text": "search query"}

{"action": "submit", "selector": "input[name='q']"}

{"action": "extract", "selector": ".results"}

{"action": "finish", "summary": "Task completed successfully"}

Rules:
- Always return valid JSON
- Be precise with selectors
- Only use "finish" when the task is truly complete

Selector Rules (IMPORTANT):
- Use ONLY Playwright-compatible selectors: CSS, `text=...`, and `:has-text("...")`
- NEVER use jQuery-only selectors like `:contains()` (invalid in Playwright)
- If you need to click a visible label/value, prefer `text=Some Text`

Google Search Flow:
- For Google search, use "type_and_submit" with selector "input[name='q']" 
- Common Google selectors: input[name="q"], textarea[name="q"], input[title="Search"]

Flight Search Policy (IMPORTANT):
- If the user request is about checking flights (city A to city B, dates, fare search), DO NOT open airline booking sites.
- Prefer Google Flights first:
  1) Navigate to https://www.google.com/travel/flights
  2) Fill origin, destination, and date
  3) Extract top results (airline + depart time + duration + price)
- Only visit an airline website if the user explicitly asks to book on that airline.
- If the site is blocked/needs OTP/login/bot checks, finish with a summary and ask for manual intervention.

Analyze the page content and user task, then decide the next logical action.
"""
    
    async def decide_next_action(self, task: str, page_text: str) -> Dict[str, Any]:
        """
        Decide the next browser action based on user task and current page content.
        
        Args:
            task: The user's task description
            page_text: Visible text content from the current page
            
        Returns:
            Dict containing action details in JSON format
        """
        try:
            # Build the prompt
            prompt = f"""
{self.system_prompt}

USER TASK: {task}

CURRENT PAGE CONTENT:
{page_text[:2000]}

Based on the user task and current page content, what should be the next action?
Return ONLY valid JSON with no additional text.
"""
            
            # Call Gemini API
            response = self.model.generate_content(prompt)
            
            # Parse and validate the JSON response
            return self._parse_json_response(response.text)
            
        except Exception as e:
            logger.error(f"Failed to decide next action: {str(e)}")
            return {
                "action": "finish",
                "summary": f"Error occurred: {str(e)}"
            }
    
    def _parse_json_response(self, response_text: str) -> Dict[str, Any]:
        """Safely parse JSON response from LLM.

        Gemini sometimes returns extra prose around the JSON (even when instructed not to).
        This method attempts to recover by extracting the first top-level JSON object.
        Returns a finish action only if recovery fails.
        """
        try:
            raw = (response_text or "").strip()

            # Remove markdown code blocks if present
            if raw.startswith("```json"):
                raw = raw[7:]
                if raw.endswith("```"):
                    raw = raw[:-3]
                raw = raw.strip()
            elif raw.startswith("```"):
                raw = raw[3:]
                if raw.endswith("```"):
                    raw = raw[:-3]
                raw = raw.strip()

            # Fast path: direct JSON
            try:
                action_data = json.loads(raw)
            except json.JSONDecodeError:
                # Recovery: extract first JSON object by brace matching
                start = raw.find("{")
                if start == -1:
                    raise

                depth = 0
                end = None
                for i in range(start, len(raw)):
                    ch = raw[i]
                    if ch == "{":
                        depth += 1
                    elif ch == "}":
                        depth -= 1
                        if depth == 0:
                            end = i + 1
                            break

                if end is None:
                    raise

                candidate = raw[start:end]
                action_data = json.loads(candidate)

            # Validate action type
            valid_actions = ["navigate", "click", "type", "type_and_submit", "submit", "extract", "finish"]
            if action_data.get("action") not in valid_actions:
                logger.warning(f"Invalid action type: {action_data.get('action')}")
                return {"action": "finish", "summary": "Invalid action type returned"}

            if "action" not in action_data:
                return {"action": "finish", "summary": "Missing action field"}

            logger.info(f"LLM decided action: {action_data['action']}")
            return action_data

        except json.JSONDecodeError as e:
            logger.error(f"JSON parsing failed: {str(e)}")
            logger.error(f"Raw response: {response_text}")
            return {
                "action": "finish",
                "summary": "Failed to parse LLM response",
                "error": str(e),
            }
        except Exception as e:
            logger.error(f"Unexpected error parsing response: {str(e)}")
            return {
                "action": "finish",
                "summary": f"Parsing error: {str(e)}",
            }