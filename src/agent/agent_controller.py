import asyncio
import logging
from typing import Dict, Any, Optional, List
from dataclasses import dataclass
from enum import Enum
from .llm_planner import LLMPlanner
from .system_chrome_executor import SystemChromeBrowserExecutor as BrowserExecutor
from .firewall_client import FirewallClient

# Configure agent-specific logger
logger = logging.getLogger(__name__)

# Create a custom formatter for agent logs
class AgentLogFormatter(logging.Formatter):
    def format(self, record):
        # Add color coding for different log levels
        colors = {
            'DEBUG': '\033[36m',    # Cyan
            'INFO': '\033[32m',     # Green
            'WARNING': '\033[33m',  # Yellow
            'ERROR': '\033[31m',    # Red
            'CRITICAL': '\033[35m'  # Magenta
        }
        reset = '\033[0m'
        
        if record.levelname in colors:
            record.levelname = f"{colors[record.levelname]}{record.levelname}{reset}"
        
        return super().format(record)

# Setup agent logger
def setup_agent_logging():
    """Setup specialized logging for the agent system."""
    agent_logger = logging.getLogger('agent')
    agent_logger.setLevel(logging.INFO)
    
    # Console handler with custom formatting
    console_handler = logging.StreamHandler()
    formatter = AgentLogFormatter(
        '%(asctime)s - 🤖 AGENT - %(levelname)s - %(message)s',
        datefmt='%H:%M:%S'
    )
    console_handler.setFormatter(formatter)
    agent_logger.addHandler(console_handler)
    
    # File handler for persistent logs
    file_handler = logging.FileHandler('agent_execution.log')
    file_formatter = logging.Formatter(
        '%(asctime)s - AGENT - %(levelname)s - %(message)s',
        datefmt='%Y-%m-%d %H:%M:%S'
    )
    file_handler.setFormatter(file_formatter)
    agent_logger.addHandler(file_handler)
    
    return agent_logger

# Initialize agent logger
agent_log = setup_agent_logging()

class AgentStatus(Enum):
    IDLE = "idle"
    RUNNING = "running"
    FINISHED = "finished"
    ERROR = "error"

@dataclass
class AgentTask:
    task_id: str
    user_request: str
    max_steps: int = 20
    current_step: int = 0
    status: AgentStatus = AgentStatus.IDLE
    result: Optional[Dict[str, Any]] = None
    error: Optional[str] = None
    steps_log: List[Dict[str, Any]] = None

    def __post_init__(self):
        if self.steps_log is None:
            self.steps_log = []

class AgentController:
    def __init__(self):
        self.llm_planner = LLMPlanner()
        self.browser_executor = BrowserExecutor()
        self.firewall_client = FirewallClient()
        self.current_task: Optional[AgentTask] = None
        
    async def execute_task(self, task: AgentTask) -> Dict[str, Any]:
        """
        Execute the secure agent loop with comprehensive logging:
        User Task → AI Decision → Firewall Validation → Execute Action → Observe Page → Repeat
        """
        self.current_task = task
        task.status = AgentStatus.RUNNING
        
        try:
            # === TASK START LOGGING ===
            agent_log.info("=" * 80)
            agent_log.info("🚀 STARTING SECURE AGENT EXECUTION")
            agent_log.info("=" * 80)
            agent_log.info(f"📋 Task: {task.user_request}")
            agent_log.info(f"🆔 Task ID: {task.task_id}")
            agent_log.info(f"⚙️  Max Steps: {task.max_steps}")
            agent_log.info("=" * 80)
            
            # Main secure agent loop
            while task.current_step < task.max_steps and task.status == AgentStatus.RUNNING:
                task.current_step += 1
                step_start_time = asyncio.get_event_loop().time()
                
                # === STEP START LOGGING ===
                agent_log.info(f"\n🔄 AGENT STEP {task.current_step}")
                agent_log.info("-" * 50)
                
                # 1. OBSERVE: Get current page state
                agent_log.info("👀 Observing current page state...")
                page_content = await self._observe_page_content()
                page_preview = page_content[:100] + "..." if len(page_content) > 100 else page_content
                agent_log.info(f"📄 Page content preview: {page_preview}")
                
                # 2. AI DECISION: Use LLM to decide next action
                agent_log.info("🧠 AI analyzing page and deciding next action...")
                planned_action = await self.llm_planner.decide_next_action(
                    task.user_request, 
                    page_content
                )
                
                # === PROPOSED ACTION LOGGING ===
                action_type = planned_action.get('action', 'unknown')
                action_details = self._format_action_details(planned_action)
                agent_log.info(f"💭 Proposed action: {action_type} - {action_details}")
                
                # 3. FIREWALL VALIDATION: Security check with page context
                agent_log.info("🛡️  Checking firewall with page context...")
                page_context = await self.browser_executor.get_comprehensive_page_context()
                validation_result = await self.firewall_client.validate_action(planned_action, page_context)
                
                # === FIREWALL DECISION LOGGING ===
                if validation_result.get('allowed', False):
                    agent_log.info("✅ Firewall: ALLOWED")
                    confidence = validation_result.get('confidence', 0.0)
                    risk_factors = validation_result.get('risk_factors', [])
                    agent_log.info(f"🎯 Confidence: {confidence:.2f}, Risk factors: {len(risk_factors)}")
                    if risk_factors:
                        agent_log.info(f"⚠️  Risk factors: {risk_factors[:3]}")  # Show first 3
                else:
                    agent_log.warning("🚫 Firewall: BLOCKED")
                    agent_log.warning(f"🔒 Reason: {validation_result.get('reason', 'Unknown')}")
                    risk_factors = validation_result.get('risk_factors', [])
                    if risk_factors:
                        agent_log.warning(f"🚨 Risk factors: {risk_factors}")
                    
                    step_result = {
                        "step": task.current_step,
                        "action": planned_action,
                        "status": "blocked_by_firewall",
                        "result": f"Security firewall blocked {action_type} action: {validation_result.get('reason', 'Unknown')}",
                        "page_context_preview": page_content[:200] + "..." if len(page_content) > 200 else page_content,
                        "duration": asyncio.get_event_loop().time() - step_start_time,
                        "firewall_result": validation_result
                    }
                    task.steps_log.append(step_result)
                    
                    agent_log.info(f"⏭️  Continuing to next step...")
                    continue
                
                # 4. EXECUTE: Perform the validated action
                agent_log.info(f"⚡ Executing {action_type}...")
                execution_result = await self._execute_action(planned_action)
                
                # === EXECUTION RESULT LOGGING ===
                if "Error:" in execution_result:
                    agent_log.error(f"❌ Execution failed: {execution_result}")
                else:
                    result_preview = execution_result[:150] + "..." if len(execution_result) > 150 else execution_result
                    agent_log.info(f"✅ Execution successful")
                    agent_log.info(f"📊 Result preview: {result_preview}")
                
                # 5. POST-ACTION OBSERVATION: Read the updated page
                agent_log.info("📖 Reading updated page after action...")
                updated_page_content = await self._observe_page_content()
                
                # Show what changed on the page
                if updated_page_content != page_content:
                    agent_log.info("🔄 Page content has changed after action")
                    new_content_preview = updated_page_content[:150] + "..." if len(updated_page_content) > 150 else updated_page_content
                    agent_log.info(f"📝 Updated page preview: {new_content_preview}")
                else:
                    agent_log.info("📋 Page content unchanged after action")
                
                # 6. REPORT: Tell firewall about the result with page context
                await self.firewall_client.report_action_result(planned_action, {
                    "status": "success" if "Error:" not in execution_result else "error",
                    "result_preview": execution_result[:500],
                    "page_content_after": updated_page_content[:500]  # Include updated page content
                }, page_context)
                
                # Calculate step duration
                step_duration = asyncio.get_event_loop().time() - step_start_time
                
                # Log this step with updated page content
                step_result = {
                    "step": task.current_step,
                    "action": planned_action,
                    "status": "executed",
                    "result": execution_result[:1000] + "..." if len(execution_result) > 1000 else execution_result,
                    "duration": step_duration,
                    "page_before": page_content[:500] + "..." if len(page_content) > 500 else page_content,
                    "page_after": updated_page_content[:500] + "..." if len(updated_page_content) > 500 else updated_page_content
                }
                task.steps_log.append(step_result)
                
                # === STEP COMPLETION LOGGING ===
                agent_log.info(f"⏱️  Step {task.current_step} completed in {step_duration:.2f}s")
                
                # 7. CHECK COMPLETION: Stop if task is finished
                if planned_action.get("action") == "finish":
                    agent_log.info("🏁 AI marked task as FINISHED")
                    task.status = AgentStatus.FINISHED
                    task.result = {
                        "summary": planned_action.get("summary", "Task completed by AI"),
                        "final_result": execution_result,
                        "final_page_content": updated_page_content,
                        "total_steps": task.current_step
                    }
                    break
                
                # Brief pause between actions for stability
                agent_log.info("⏸️  Pausing 1 second before next step...")
                await asyncio.sleep(1)
            
            # === TASK COMPLETION LOGGING ===
            if task.status == AgentStatus.RUNNING:
                agent_log.warning(f"⏱️  Task reached maximum steps ({task.max_steps})")
                task.status = AgentStatus.FINISHED
                task.result = {
                    "summary": f"Task reached maximum steps limit ({task.max_steps})",
                    "total_steps": task.current_step,
                    "status": "partial_completion"
                }
            
            # === FINAL SUMMARY LOGGING ===
            agent_log.info("\n" + "=" * 80)
            agent_log.info("� TASK EXECUTION COMPLETED")
            agent_log.info("=" * 80)
            agent_log.info(f"📊 Final Status: {task.status.value.upper()}")
            agent_log.info(f"📈 Steps Completed: {task.current_step}/{task.max_steps}")
            if task.result:
                agent_log.info(f"📝 Summary: {task.result.get('summary', 'No summary available')}")
            agent_log.info("=" * 80)
            
            return {
                "task_id": task.task_id,
                "status": task.status.value,
                "steps_completed": task.current_step,
                "result": task.result,
                "steps_log": task.steps_log
            }
            
        except Exception as e:
            agent_log.error(f"💥 CRITICAL ERROR: Task execution failed")
            agent_log.error(f"❌ Error details: {str(e)}")
            logger.exception("Full error traceback:")
            
            task.status = AgentStatus.ERROR
            task.error = str(e)
            return {
                "task_id": task.task_id,
                "status": task.status.value,
                "error": task.error,
                "steps_completed": task.current_step,
                "steps_log": task.steps_log
            }
        finally:
            # Clean up browser resources
            try:
                await self.browser_executor.cleanup()
                agent_log.info("🧹 Browser cleanup completed")
            except Exception as e:
                agent_log.error(f"🚨 Cleanup error: {str(e)}")
    
    def _format_action_details(self, action: Dict[str, Any]) -> str:
        """Format action details for logging."""
        action_type = action.get('action', 'unknown')
        
        if action_type == 'navigate':
            return action.get('url', 'unknown URL')
        elif action_type == 'click':
            return f"selector: {action.get('selector', 'unknown selector')}"
        elif action_type == 'type':
            selector = action.get('selector', 'unknown selector')
            text = action.get('text', 'unknown text')
            return f"'{text}' into {selector}"
        elif action_type == 'extract':
            return f"from {action.get('selector', 'page')}"
        elif action_type == 'finish':
            return action.get('summary', 'task completion')
        else:
            return str(action)
    
    async def _observe_page_content(self) -> str:
        """
        ENHANCED: Observe current page content using page.inner_text('body')
        This provides the actual visible text content that users see.
        """
        try:
            if not self.browser_executor.page:
                # If no page is available, initialize browser first
                await self.browser_executor.initialize_browser()
                return "Browser initialized - no page content yet"
            
            # Use page.inner_text('body') to get the visible text content
            page_text = await self.browser_executor.page.inner_text('body')
            
            # Get additional context
            page_title = await self.browser_executor.page.title()
            page_url = self.browser_executor.page.url
            
            # Format the comprehensive page content
            formatted_content = f"Title: {page_title}\nURL: {page_url}\n\nVisible Text:\n{page_text}"
            
            # Limit content length for LLM processing
            if len(formatted_content) > 4000:
                formatted_content = formatted_content[:4000] + "\n... [content truncated for LLM processing]"
            
            agent_log.debug(f"📄 Page content length: {len(page_text)} characters")
            return formatted_content
            
        except Exception as e:
            error_msg = f"Failed to observe page content: {str(e)}"
            agent_log.error(error_msg)
            return error_msg
    
    async def _observe_page(self) -> str:
        """
        DEPRECATED: Use _observe_page_content() instead
        Kept for backward compatibility
        """
        return await self._observe_page_content()
    
    async def _execute_action(self, action: Dict[str, Any]) -> str:
        """
        STEP 4: Execute a validated action using the browser executor
        """
        try:
            result = await self.browser_executor.execute(action)
            logger.debug(f"Action execution result length: {len(result)} characters")
            return result
        except Exception as e:
            error_msg = f"Action execution failed: {str(e)}"
            logger.error(error_msg)
            return error_msg
    
    
    async def get_task_status(self) -> Dict[str, Any]:
        """Get current task status and progress."""
        if not self.current_task:
            return {"status": "no_active_task"}
        
        return {
            "task_id": self.current_task.task_id,
            "status": self.current_task.status.value,
            "current_step": self.current_task.current_step,
            "max_steps": self.current_task.max_steps,
            "user_request": self.current_task.user_request,
            "steps_log": self.current_task.steps_log[-5:] if self.current_task.steps_log else [],  # Last 5 steps
            "result": self.current_task.result,
            "error": self.current_task.error
        }
    
    async def stop_current_task(self) -> Dict[str, Any]:
        """Stop the currently running task."""
        if self.current_task and self.current_task.status == AgentStatus.RUNNING:
            logger.info("🛑 Stopping current task...")
            self.current_task.status = AgentStatus.FINISHED
            self.current_task.result = {
                "summary": "Task stopped by user request",
                "total_steps": self.current_task.current_step
            }
            
            try:
                await self.browser_executor.cleanup()
            except Exception as e:
                logger.error(f"Cleanup error during stop: {str(e)}")
            
            return {"message": "Task stopped successfully"}
        return {"message": "No active task to stop"}

    async def cleanup(self) -> None:
        """Clean up all agent resources."""
        try:
            await self.browser_executor.cleanup()
            await self.firewall_client.close()
            logger.info("Agent controller cleanup completed")
        except Exception as e:
            logger.error(f"Agent cleanup failed: {str(e)}")

    def get_security_status(self) -> Dict[str, Any]:
        """Get current security configuration status."""
        return {
            "firewall_enabled": True,
            "blocked_domains": len(self.firewall_client.security_rules.get("blocked_domains", [])),
            "sensitive_selectors": len(self.firewall_client.security_rules.get("sensitive_selectors", [])),
            "browser_initialized": self.browser_executor._initialized if hasattr(self.browser_executor, '_initialized') else False
        }