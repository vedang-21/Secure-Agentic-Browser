#!/usr/bin/env python3
"""
System Chrome Browser Executor for macOS
Uses system-installed Google Chrome instead of bundled Chromium to avoid crashes
"""

import asyncio
import logging
from playwright.async_api import async_playwright
from typing import Dict, Any

logger = logging.getLogger(__name__)

class SystemChromeBrowserExecutor:
    """Browser executor that uses system Google Chrome."""

    def __init__(self):
        self.playwright = None
        self.browser = None
        self.context = None
        self.page = None
        self._initialized = False
        # If True, when a CAPTCHA is detected we will pause and wait for the user
        # to solve it in the interactive (headed) Chrome window.
        self.allow_manual_captcha_solve: bool = True
        # Maximum time to wait for manual CAPTCHA solve.
        self.manual_captcha_timeout_s: int = 180
    
    async def initialize_browser(self):
        """Initialize browser using system Google Chrome."""
        if self._initialized:
            return
        
        try:
            logger.info("🍎 Initializing browser with system Google Chrome...")
            
            self.playwright = await async_playwright().start()
            self.browser = await self.playwright.chromium.launch(
                executable_path="/Applications/Google Chrome.app/Contents/MacOS/Google Chrome",
                headless=False  # Set to True for headless mode
                # No custom args - let Chrome handle everything
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
            logger.info("✅ System Chrome initialized successfully!")
            
        except Exception as e:
            logger.error(f"❌ System Chrome initialization failed: {str(e)}")
            # Fallback to bundled Chromium if system Chrome fails
            try:
                logger.info("🔄 Falling back to bundled Chromium...")
                self.browser = await self.playwright.chromium.launch(headless=True)
                self.context = await self.browser.new_context()
                self.page = await self.context.new_page()
                self._initialized = True
                logger.info("✅ Fallback to bundled Chromium successful")
            except Exception as fallback_error:
                logger.error(f"❌ Fallback also failed: {str(fallback_error)}")
                raise RuntimeError(f"Browser setup failed: {str(e)}")
    
    async def navigate(self, url: str) -> None:
        """Navigate to a URL with better error handling."""
        if not self._initialized:
            await self.initialize_browser()

        try:
            logger.info(f"🌐 Navigating to: {url}")
            await self.page.goto(url, wait_until="domcontentloaded", timeout=30000)
            await asyncio.sleep(2)  # Allow page to fully load
            await self._best_effort_dismiss_overlays()
            await self._maybe_use_google_ncr()
            await self._handle_captcha_if_present("after navigation")
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
    
    async def submit_form(self, selector: str) -> None:
        """Submit a form or press Enter in an input field."""
        if not self._initialized:
            await self.initialize_browser()
        
        try:
            logger.info(f"📨 Submitting form/pressing Enter: {selector}")
            await self.page.wait_for_selector(selector, timeout=10000)
            # Try pressing Enter first (common for search boxes)
            await self.page.press(selector, 'Enter')
            await asyncio.sleep(2)  # Wait for page to load
            logger.info(f"✅ Successfully submitted: {selector}")
            
        except Exception as e:
            error_msg = f"Submit failed: {str(e)}"
            logger.error(f"❌ {error_msg}")
            raise RuntimeError(error_msg)
    
    async def _best_effort_dismiss_overlays(self) -> None:
        """Best-effort click-away for common consent/overlay dialogs (Google, etc.)."""
        if not self._initialized:
            return

        candidates = [
            "button:has-text('I agree')",
            "button:has-text('Accept all')",
            "button:has-text('Accept All')",
            "button:has-text('Accept')",
            "button:has-text('Agree')",
            "text=I agree",
            "text=Accept all",
            "text=Accept",
        ]

        for sel in candidates:
            try:
                el = await self.page.query_selector(sel)
                if el:
                    await el.click(timeout=1500)
                    await asyncio.sleep(0.5)
            except Exception:
                pass

    async def _set_input_value_js(self, selector: str, value: str) -> bool:
        """Fallback: set value via JS and dispatch events."""
        if not self.page:
            return False
        try:
            ok = await self.page.evaluate(
                """
                ({ selector, value }) => {
                  const el = document.querySelector(selector);
                  if (!el) return false;
                  el.focus();
                  // Works for <input> and <textarea>
                  el.value = value;
                  el.dispatchEvent(new Event('input', { bubbles: true }));
                  el.dispatchEvent(new Event('change', { bubbles: true }));
                  // Enter key
                  el.dispatchEvent(new KeyboardEvent('keydown', { key: 'Enter', code: 'Enter', which: 13, keyCode: 13, bubbles: true }));
                  el.dispatchEvent(new KeyboardEvent('keyup', { key: 'Enter', code: 'Enter', which: 13, keyCode: 13, bubbles: true }));
                  return true;
                }
                """,
                {"selector": selector, "value": value},
            )
            return bool(ok)
        except Exception:
            return False

    async def type_and_submit(self, selector: str, text: str) -> None:
        """Type text and immediately submit (useful for search boxes)."""
        if not self._initialized:
            await self.initialize_browser()

        # If we're on Google and already blocked, don't keep retrying selectors.
        await self._handle_captcha_if_present("before typing")

        selector_candidates = []
        if selector:
            selector_candidates.append(selector)
        selector_candidates.extend(
            [
                "input[name='q']",
                "textarea[name='q']",
                "input[name='search']",
                "input[type='search']",
                "textarea[type='search']",
                "input[role='combobox']",
                "textarea[role='combobox']",
            ]
        )

        last_error: Exception | None = None
        for sel in selector_candidates:
            try:
                logger.info(f"⌨️🔍 Typing and submitting '{text}' in: {sel}")

                await self.page.bring_to_front()

                # Only wait for load state / selector if not immediately present.
                el = await self.page.query_selector(sel)
                if el is None:
                    await self.page.wait_for_load_state("domcontentloaded", timeout=15000)
                    await self._best_effort_dismiss_overlays()
                    await self._maybe_use_google_ncr()
                    await self._handle_captcha_if_present("before selector wait")
                    el = await self.page.wait_for_selector(sel, timeout=15000, state="visible")
                else:
                    try:
                        await self._best_effort_dismiss_overlays()
                        await self._maybe_use_google_ncr()
                    except Exception:
                        pass

                await el.scroll_into_view_if_needed(timeout=3000)

                if not await el.is_editable():
                    raise RuntimeError("element not editable")

                await el.click(timeout=5000, force=True)

                # Clear existing content
                try:
                    await el.fill("")
                except Exception:
                    await el.press("Meta+A")
                    await el.press("Backspace")

                # Prefer fill (instant) then Enter; fall back to slow typing; then JS.
                try:
                    await el.fill(text)
                    await el.press("Enter")
                except Exception:
                    try:
                        await el.type(text, delay=5)
                        await el.press("Enter")
                    except Exception:
                        # Last resort: JS set + dispatch
                        if not await self._set_input_value_js(sel, text):
                            raise

                # If Google blocks with CAPTCHA after submit, wait/raise accordingly.
                try:
                    await self.page.wait_for_load_state("domcontentloaded", timeout=15000)
                except Exception:
                    pass

                await self._handle_captcha_if_present("after submit")

                logger.info(f"✅ Successfully typed and submitted: {sel}")
                return

            except Exception as e:
                last_error = e
                # If a CAPTCHA is present, don't waste time trying other selectors.
                try:
                    await self._handle_captcha_if_present("during typing")
                except Exception as captcha_err:
                    last_error = captcha_err
                    break
                continue

        try:
            await self.page.screenshot(path="typing_failed.png", full_page=True)
            logger.error("Saved debug screenshot: typing_failed.png")
        except Exception:
            pass

        error_msg = f"Type and submit failed: {last_error}"
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
        """Get current page content."""
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
        """Get comprehensive page context."""
        if not self._initialized:
            await self.initialize_browser()
        
        try:
            context = {
                'url': self.page.url,
                'title': await self.page.title(),
                'visible_text': await self.page.inner_text('body'),
                'html': await self.page.content(),
                'has_javascript': True,
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
            
            logger.info(f"📊 Page context: {len(context['forms'])} forms, {len(context['inputs'])} inputs")
            return context
            
        except Exception as e:
            logger.error(f"❌ Failed to get page context: {str(e)}")
            return {
                'url': getattr(self.page, 'url', ''),
                'title': 'Error getting page context',
                'error': str(e)
            }
    
    async def execute(self, action: Dict[str, Any]) -> str:
        """Execute browser action."""
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
            
            elif action_type == "type_and_submit":
                await self.type_and_submit(action["selector"], action["text"])
                return f"Successfully typed and submitted '{action['text']}' in: {action['selector']}"
            
            elif action_type == "submit":
                await self.submit_form(action["selector"])
                return f"Successfully submitted form: {action['selector']}"
                
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
            logger.info("🧹 System Chrome cleanup completed")
            
        except Exception as e:
            logger.error(f"❌ Cleanup error: {str(e)}")

    async def _is_captcha_page(self) -> bool:
        """Heuristically detect common CAPTCHA / bot-detection interstitials."""
        if not self.page:
            return False

        try:
            url = (self.page.url or "").lower()
            if any(s in url for s in ["/sorry/", "recaptcha", "captcha", "challenge", "/validate/"]):
                return True

            # Look for common DOM markers.
            markers = [
                "iframe[src*='recaptcha']",
                "#recaptcha",
                ".g-recaptcha",
                "div[aria-label*='captcha' i]",
                "input[name='captcha']",
                "text=/i\s*am\s*not\s*a\s*robot/i",
                "text=/unusual\s*traffic/i",
                "text=/verify\s*you\s*are\s*human/i",
            ]
            for m in markers:
                try:
                    if await self.page.query_selector(m):
                        return True
                except Exception:
                    continue

            # Content fallback (cheap, robust).
            try:
                body_text = (await self.page.inner_text("body"))[:5000].lower()
                if any(k in body_text for k in [
                    "unusual traffic",
                    "verify you are human",
                    "captcha",
                    "i am not a robot",
                    "our systems have detected",
                ]):
                    return True
            except Exception:
                pass

            return False
        except Exception:
            return False

    async def _handle_captcha_if_present(self, context: str = "") -> None:
        """If a CAPTCHA is detected, pause for manual solve (headed mode) or fail fast."""
        if not await self._is_captcha_page():
            return

        try:
            await self.page.screenshot(path="captcha_detected.png", full_page=True)
            logger.error("Saved debug screenshot: captcha_detected.png")
        except Exception:
            pass

        msg = f"CAPTCHA detected{': ' + context if context else ''} at {getattr(self.page, 'url', '')}"
        logger.error(msg)

        if not self.allow_manual_captcha_solve:
            raise RuntimeError(msg)

        # Manual intervention: keep the browser open and poll until CAPTCHA disappears.
        deadline = asyncio.get_event_loop().time() + float(self.manual_captcha_timeout_s)
        logger.error(
            "Waiting for manual CAPTCHA solve in the Chrome window (timeout: %ss)...",
            self.manual_captcha_timeout_s,
        )
        while asyncio.get_event_loop().time() < deadline:
            await asyncio.sleep(2)
            if not await self._is_captcha_page():
                logger.info("CAPTCHA appears resolved; resuming automation.")
                return

        raise RuntimeError(f"Timed out waiting for manual CAPTCHA solve after {self.manual_captcha_timeout_s}s")

    async def _maybe_use_google_ncr(self) -> None:
        """Reduce consent interstitials by using Google's 'no country redirect' endpoint."""
        if not self.page:
            return
        try:
            url = self.page.url or ""
            if "google." in url and "consent" in url.lower():
                # If we landed on a consent page, try to go to NCR homepage.
                await self.page.goto("https://www.google.com/ncr", wait_until="domcontentloaded", timeout=20000)
                await asyncio.sleep(1)
        except Exception:
            pass

# For backward compatibility, create an alias
BrowserExecutor = SystemChromeBrowserExecutor