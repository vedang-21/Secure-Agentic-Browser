#!/usr/bin/env python3
"""
macOS-Optimized Browser Executor
This version removes Linux/Docker-specific flags that can break on macOS
"""

import asyncio
import logging
from playwright.async_api import async_playwright
from typing import Dict, Any

logger = logging.getLogger(__name__)

class MacOSBrowserExecutor:
    """Browser executor optimized for macOS without problematic Linux flags."""
    
    def __init__(self):
        self.playwright = None
        self.browser = None
        self.context = None
        self.page = None
        self._initialized = False
    
    async def initialize_browser(self):
        """Initialize browser with macOS-optimized settings."""
        if self._initialized:
            return
        
        try:
            logger.info("🍎 Initializing browser for macOS...")
            
           
            
            self.playwright = await async_playwright().start()
            self.browser = await self.playwright.chromium.launch(
                headless=False,  # Visible browser for debugging
                
                slow_mo=100  # Small delay between actions for stability
            )
            
            # Create context with realistic settings
            self.context = await self.browser.new_context(
                viewport={'width': 1280, 'height': 720},
                user_agent='Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
                locale='en-US',
                timezone_id='America/New_York'
            )
            
            # Create the main page
            self.page = await self.context.new_page()
            
            self._initialized = True
            logger.info("✅ macOS Browser initialized successfully!")
            
        except Exception as e:
            logger.error(f"❌ macOS Browser initialization failed: {str(e)}")
            raise RuntimeError(f"Browser setup failed: {str(e)}")
    
    async def navigate(self, url: str) -> None:
        """Navigate to a URL with better error handling."""
        if not self._initialized:
            await self.initialize_browser()
        
        try:
            logger.info(f"🌐 Navigating to: {url}")
            await self.page.goto(url, wait_until="domcontentloaded", timeout=30000)
            await asyncio.sleep(2)  # Allow page to fully load
            logger.info(f"✅ Successfully navigated to: {url}")
            
        except Exception as e:
            error_msg = f"Navigation failed: {str(e)}"
            logger.error(f"❌ {error_msg}")
            raise RuntimeError(error_msg)
    
    async def click(self, selector: str) -> None:
        """Click on an element with better error handling."""
        if not self._initialized:
            await self.initialize_browser()
        
        try:
            logger.info(f"👆 Clicking: {selector}")
            await self.page.wait_for_selector(selector, timeout=10000)
            await self.page.click(selector)
            await asyncio.sleep(1)
            logger.info(f"✅ Successfully clicked: {selector}")
            
        except Exception as e:
            error_msg = f"Click failed: {str(e)}"
            logger.error(f"❌ {error_msg}")
            raise RuntimeError(error_msg)
    
    async def type(self, selector: str, text: str) -> None:
        """Type text with better error handling."""
        if not self._initialized:
            await self.initialize_browser()
        
        try:
            logger.info(f"⌨️  Typing '{text}' into: {selector}")
            await self.page.wait_for_selector(selector, timeout=10000)
            await self.page.fill(selector, text)
            await asyncio.sleep(0.5)
            logger.info(f"✅ Successfully typed into: {selector}")
            
        except Exception as e:
            error_msg = f"Type failed: {str(e)}"
            logger.error(f"❌ {error_msg}")
            raise RuntimeError(error_msg)
    
    async def extract(self, selector: str) -> str:
        """Extract text from elements."""
        if not self._initialized:
            await self.initialize_browser()
        
        try:
            logger.info(f"📤 Extracting text from: {selector}")
            elements = await self.page.query_selector_all(selector)
            
            if not elements:
                return "No elements found with the given selector"
            
            texts = []
            for element in elements[:10]:  # Limit to 10 elements
                text = await element.inner_text()
                if text.strip():
                    texts.append(text.strip())
            
            result = "\n".join(texts) if texts else "No text content found"
            logger.info(f"✅ Extracted {len(texts)} text elements")
            return result
            
        except Exception as e:
            error_msg = f"Extract failed: {str(e)}"
            logger.error(f"❌ {error_msg}")
            return error_msg
    
    async def get_page_content(self) -> str:
        """Get current page content optimized for macOS."""
        if not self._initialized:
            await self.initialize_browser()
        
        try:
            title = await self.page.title()
            url = self.page.url
            visible_text = await self.page.inner_text('body')
            
            content = f"Title: {title}\nURL: {url}\n\nContent:\n{visible_text}"
            
            # Limit content for better performance
            if len(content) > 4000:
                content = content[:4000] + "... [content truncated]"
            
            return content
            
        except Exception as e:
            logger.error(f"❌ Failed to get page content: {str(e)}")
            return f"Error getting page content: {str(e)}"
    
    async def get_comprehensive_page_context(self) -> Dict[str, Any]:
        """Get comprehensive page context optimized for macOS."""
        if not self._initialized:
            await self.initialize_browser()
        
        try:
            context = {
                'url': self.page.url,
                'title': await self.page.title(),
                'visible_text': await self.page.inner_text('body'),
                'html': await self.page.content(),
                'has_javascript': True,  # Assume JS is present
                'forms': [],
                'inputs': [],
                'links': [],
                'meta': {},
                'cookies': [],
                'security_headers': {}
            }
            
            # Get forms (with error handling)
            try:
                forms = await self.page.query_selector_all('form')
                for form in forms[:5]:  # Limit to 5 forms
                    form_data = {
                        'action': await form.get_attribute('action') or '',
                        'method': await form.get_attribute('method') or 'get',
                        'https': context['url'].startswith('https://')
                    }
                    context['forms'].append(form_data)
            except:
                pass
            
            # Get inputs (with error handling)
            try:
                inputs = await self.page.query_selector_all('input')
                for input_elem in inputs[:10]:  # Limit to 10 inputs
                    input_data = {
                        'type': await input_elem.get_attribute('type') or 'text',
                        'name': await input_elem.get_attribute('name') or '',
                        'selector': f'input[type="{await input_elem.get_attribute("type") or "text"}"]'
                    }
                    context['inputs'].append(input_data)
            except:
                pass
            
            # Get links (with error handling)
            try:
                links = await self.page.query_selector_all('a[href]')
                for link in links[:5]:  # Limit to 5 links
                    href = await link.get_attribute('href')
                    if href:
                        context['links'].append({
                            'href': href,
                            'text': (await link.inner_text())[:50]
                        })
            except:
                pass
            
            logger.info(f"📊 macOS Page context: {len(context['forms'])} forms, {len(context['inputs'])} inputs")
            return context
            
        except Exception as e:
            logger.error(f"❌ Failed to get page context: {str(e)}")
            return {
                'url': getattr(self.page, 'url', ''),
                'title': 'Error getting page context',
                'error': str(e)
            }
    
    async def execute(self, action: Dict[str, Any]) -> str:
        """Execute browser action with macOS optimizations."""
        try:
            action_type = action.get("action", "")
            
            if action_type == "navigate":
                await self.navigate(action["url"])
                return f"Successfully navigated to: {action['url']}"
                
            elif action_type == "click":
                await self.click(action["selector"])
                return f"Successfully clicked: {action['selector']}"
                
            elif action_type == "type":
                await self.type(action["selector"], action["text"])
                return f"Successfully typed '{action['text']}' into: {action['selector']}"
                
            elif action_type == "extract":
                result = await self.extract(action["selector"])
                return f"Extracted content: {result}"
                
            elif action_type == "finish":
                return f"Task finished: {action.get('summary', 'Task completed')}"
                
            else:
                return f"Error: Unknown action type: {action_type}"
                
        except Exception as e:
            error_msg = f"Action execution failed: {str(e)}"
            logger.error(f"❌ {error_msg}")
            return f"Error: {error_msg}"
    
    async def cleanup(self):
        """Clean up browser resources."""
        try:
            if self.page:
                await self.page.close()
            if self.context:
                await self.context.close()
            if self.browser:
                await self.browser.close()
            if self.playwright:
                await self.playwright.stop()
                
            self._initialized = False
            logger.info("🧹 macOS Browser cleanup completed")
            
        except Exception as e:
            logger.error(f"❌ Cleanup error: {str(e)}")

# For backward compatibility, create an alias
BrowserExecutor = MacOSBrowserExecutor