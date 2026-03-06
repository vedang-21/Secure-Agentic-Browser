import asyncio
import logging
from typing import Dict, Any, List, Optional
from playwright.async_api import async_playwright, Browser, BrowserContext, Page

logger = logging.getLogger(__name__)

class BrowserExecutor:
    def __init__(self):
        self.playwright = None
        self.browser: Optional[Browser] = None
        self.context: Optional[BrowserContext] = None
        self.page: Optional[Page] = None
        self._initialized = False
        
    async def initialize_browser(self) -> None:
        """Initialize Playwright browser instance."""
        if self._initialized:
            return
            
        try:
            self.playwright = await async_playwright().start()
            self.browser = await self.playwright.chromium.launch(
                headless=False,  # Set to True for production
                args=['--no-sandbox', '--disable-dev-shm-usage']
            )
            self.context = await self.browser.new_context(
                viewport={'width': 1280, 'height': 720},
                user_agent='Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
            )
            self.page = await self.context.new_page()
            self._initialized = True
            logger.info("Browser initialized successfully")
        except Exception as e:
            logger.error(f"Failed to initialize browser: {str(e)}")
            raise
    
    async def execute(self, action: Dict[str, Any]) -> str:
        """
        Execute a browser action and return page content.
        
        Args:
            action: Dictionary containing action details
            
        Returns:
            String containing page content after execution
        """
        # Ensure browser is initialized
        await self.initialize_browser()
        
        action_type = action.get("action")
        
        try:
            if action_type == "navigate":
                await self.navigate(action.get("url", ""))
            elif action_type == "click":
                await self.click(action.get("selector", ""))
            elif action_type == "type":
                await self.type(action.get("selector", ""), action.get("text", ""))
            elif action_type == "extract":
                return await self.extract(action.get("selector", ""))
            else:
                logger.warning(f"Unknown action type: {action_type}")
            
            # Return current page content
            return await self.get_page_content()
            
        except Exception as e:
            logger.error(f"Action execution failed: {str(e)}")
            return f"Error: {str(e)}"
    
    async def navigate(self, url: str) -> None:
        """Navigate to a URL."""
        if not self.page:
            raise RuntimeError("Browser not initialized")
            
        logger.info(f"🌐 Navigating to: {url}")
        await self.page.goto(url, wait_until="networkidle")
        await asyncio.sleep(2)  # Wait for page to settle
        logger.info(f"✅ Navigation completed successfully")
    
    async def click(self, selector: str) -> None:
        """Click on an element."""
        if not self.page:
            raise RuntimeError("Browser not initialized")
            
        logger.info(f"👆 Clicking element: {selector}")
        await self.page.wait_for_selector(selector, timeout=10000)
        await self.page.click(selector)
        await asyncio.sleep(1)  # Wait for click effects
        logger.info(f"✅ Click completed successfully")
    
    async def type(self, selector: str, text: str) -> None:
        """Type text into an input field."""
        if not self.page:
            raise RuntimeError("Browser not initialized")
            
        logger.info(f"⌨️  Typing '{text}' into: {selector}")
        await self.page.wait_for_selector(selector, timeout=10000)
        await self.page.fill(selector, text)
        await asyncio.sleep(0.5)
        logger.info(f"✅ Text input completed successfully")
    
    async def extract(self, selector: str) -> str:
        """Extract text from elements matching selector."""
        if not self.page:
            raise RuntimeError("Browser not initialized")
            
        logger.info(f"Extracting from: {selector}")
        
        try:
            if selector == "page" or selector == "":
                # Extract all page text
                return await self.page.evaluate("() => document.body.innerText")
            else:
                # Extract from specific selector
                elements = await self.page.query_selector_all(selector)
                if not elements:
                    return f"No elements found for selector: {selector}"
                
                extracted_texts = []
                for element in elements:
                    text = await element.inner_text()
                    if text.strip():
                        extracted_texts.append(text.strip())
                
                return "\n".join(extracted_texts)
                
        except Exception as e:
            return f"Extraction error: {str(e)}"
    
    async def get_page_content(self) -> str:
        """Get current page text content using inner_text for better performance."""
        if not self.page:
            return "Browser not initialized"
            
        try:
            # Get page title and URL
            title = await self.page.title()
            url = self.page.url
            
            # Use inner_text('body') for faster, more accurate text extraction
            visible_text = await self.page.inner_text('body')
            
            # Format the content
            content = f"Page: {title}\nURL: {url}\n\nContent:\n{visible_text}"
            
            # Limit content length to avoid overwhelming the LLM
            if len(content) > 3000:
                content = content[:3000] + "... [content truncated]"
            
            return content
            
        except Exception as e:
            logger.error(f"Failed to get page content: {str(e)}")
            return f"Error getting page content: {str(e)}"
    
    async def get_comprehensive_page_context(self) -> Dict[str, Any]:
        """Get comprehensive page context for security analysis."""
        if not self._initialized:
            await self.initialize_browser()
            return {"error": "Browser was not initialized"}
        
        try:
            # Basic page info
            context = {
                'url': self.page.url,
                'title': await self.page.title(),
                'visible_text': await self.page.inner_text('body'),
            }
            
            # HTML content
            context['html'] = await self.page.content()
            
            # Check for JavaScript
            context['has_javascript'] = 'script' in context['html'].lower()
            
            # Get all forms
            forms = await self.page.query_selector_all('form')
            context['forms'] = []
            for form in forms:
                form_data = {
                    'action': await form.get_attribute('action') or '',
                    'method': await form.get_attribute('method') or 'get',
                    'https': context['url'].startswith('https://')
                }
                context['forms'].append(form_data)
            
            # Get all input fields
            inputs = await self.page.query_selector_all('input')
            context['inputs'] = []
            for input_elem in inputs:
                input_data = {
                    'type': await input_elem.get_attribute('type') or 'text',
                    'name': await input_elem.get_attribute('name') or '',
                    'selector': await self._get_element_selector(input_elem)
                }
                context['inputs'].append(input_data)
            
            # Get all links
            links = await self.page.query_selector_all('a[href]')
            context['links'] = []
            for link in links[:10]:  # Limit to first 10 links
                href = await link.get_attribute('href')
                if href:
                    context['links'].append({
                        'href': href,
                        'text': (await link.inner_text())[:50]  # First 50 chars
                    })
            
            # Get meta information
            meta_elements = await self.page.query_selector_all('meta')
            context['meta'] = {}
            for meta in meta_elements:
                name = await meta.get_attribute('name') or await meta.get_attribute('property')
                content_attr = await meta.get_attribute('content')
                if name and content_attr:
                    context['meta'][name] = content_attr
            
            # Get security headers (simplified version)
            context['security_headers'] = {
                'content_security_policy': False,  # Would need to check actual headers
                'x_frame_options': False,
                'strict_transport_security': context['url'].startswith('https://')
            }
            
            # Get cookies
            cookies = await self.page.context.cookies()
            context['cookies'] = [{'name': c['name'], 'secure': c.get('secure', False)} for c in cookies]
            
            logger.info(f"📄 Collected comprehensive page context: {len(context['html'])} chars HTML, "
                       f"{len(context['forms'])} forms, {len(context['inputs'])} inputs, "
                       f"{len(context['links'])} links")
            
            return context
            
        except Exception as e:
            logger.error(f"Failed to get comprehensive page context: {str(e)}")
            return {
                'url': getattr(self.page, 'url', ''),
                'title': 'Error getting page context',
                'error': str(e)
            }

    async def _get_element_selector(self, element) -> str:
        """Generate a selector for an element."""
        try:
            # Try to get a unique selector
            tag_name = await element.evaluate('el => el.tagName.toLowerCase()')
            element_id = await element.get_attribute('id')
            element_name = await element.get_attribute('name')
            element_class = await element.get_attribute('class')
            
            if element_id:
                return f"{tag_name}#{element_id}"
            elif element_name:
                return f"{tag_name}[name='{element_name}']"
            elif element_class:
                return f"{tag_name}.{element_class.split()[0]}"
            else:
                return tag_name
        except:
            return 'unknown'
    
    async def get_detailed_page_content(self) -> str:
        """Get detailed page content with interactive elements (legacy method)."""
        if not self.page:
            return "Browser not initialized"
            
        try:
            # Get page title and URL
            title = await self.page.title()
            url = self.page.url
            
            # Get visible interactive elements
            elements = await self.page.evaluate("""
                () => {
                    const elements = [];
                    const selectors = [
                        'button', 'input', 'select', 'textarea', 'a[href]',
                        '[onclick]', '[role="button"]', '[type="submit"]'
                    ];
                    
                    selectors.forEach(selector => {
                        document.querySelectorAll(selector).forEach((el, index) => {
                            if (el.offsetWidth > 0 && el.offsetHeight > 0) {
                                const rect = el.getBoundingClientRect();
                                if (rect.top >= 0 && rect.top <= window.innerHeight) {
                                    elements.push({
                                        tag: el.tagName.toLowerCase(),
                                        type: el.type || '',
                                        text: (el.innerText || el.value || el.placeholder || '').slice(0, 100),
                                        id: el.id || '',
                                        className: el.className || '',
                                        selector: el.id ? `#${el.id}` : 
                                                 el.className ? `.${el.className.split(' ')[0]}` :
                                                 `${el.tagName.toLowerCase()}:nth-of-type(${index + 1})`
                                    });
                                }
                            }
                        });
                    });
                    return elements.slice(0, 20); // Limit to 20 elements
                }
            """)
            
            # Get page text content (limited)
            text_content = await self.page.evaluate(
                "() => document.body.innerText.slice(0, 1000)"
            )
            
            return {
                "url": url,
                "title": title,
                "elements": elements,
                "text": text_content
            }
            
        except Exception as e:
            logger.error(f"Failed to get detailed page content: {str(e)}")
            return {"error": str(e)}
    
    async def cleanup(self) -> None:
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
            logger.info("Browser cleanup completed")
        except Exception as e:
            logger.error(f"Cleanup failed: {str(e)}")

# Maintain backward compatibility with existing code
class ActionExecutor(BrowserExecutor):
    """Alias for backward compatibility."""
    pass