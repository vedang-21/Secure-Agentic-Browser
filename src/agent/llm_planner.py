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
- Be precise with CSS selectors
- Only use "finish" when the task is truly complete
- For Google search, use "type_and_submit" with selector "input[name='q']" 
- For other search boxes, try "type_and_submit" first, then "type" + "submit" if needed
- Common Google selectors: input[name="q"], input[title="Search"]
- Think step by step about what needs to be done
- After typing in a search box, you must submit it to get results

Special Google Search Flow:
1. Navigate to https://google.com
2. Use type_and_submit with selector "input[name='q']" and your search text
3. Wait for results to load, then extract with selectors like "h3", ".g h3", or "[data-header-feature] h3"

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
        """
        Safely parse JSON response from LLM.
        Returns finish action if parsing fails.
        """
        try:
            # Clean the response text
            response_text = response_text.strip()
            
            # Remove markdown code blocks if present
            if response_text.startswith("```json"):
                response_text = response_text[7:-3].strip()
            elif response_text.startswith("```"):
                response_text = response_text[3:-3].strip()
            
            # Parse JSON
            action_data = json.loads(response_text)
            
            # Validate action type
            valid_actions = ["navigate", "click", "type", "type_and_submit", "submit", "extract", "finish"]
            if action_data.get("action") not in valid_actions:
                logger.warning(f"Invalid action type: {action_data.get('action')}")
                return {"action": "finish", "summary": "Invalid action type returned"}
            
            # Ensure required fields exist
            if "action" not in action_data:
                return {"action": "finish", "summary": "Missing action field"}
            
            logger.info(f"LLM decided action: {action_data['action']}")
            return action_data
            
        except json.JSONDecodeError as e:
            logger.error(f"JSON parsing failed: {str(e)}")
            logger.error(f"Raw response: {response_text}")
            return {
                "action": "finish", 
                "summary": "Failed to parse LLM response"
            }
        except Exception as e:
            logger.error(f"Unexpected error parsing response: {str(e)}")
            return {
                "action": "finish",
                "summary": f"Parsing error: {str(e)}"
            }