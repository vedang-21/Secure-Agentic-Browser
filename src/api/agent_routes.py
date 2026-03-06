from fastapi import APIRouter, HTTPException, BackgroundTasks
from pydantic import BaseModel
from typing import Dict, Any, Optional
import uuid
import logging
import asyncio
from ..agent.agent_controller import AgentController, AgentTask

logger = logging.getLogger(__name__)
router = APIRouter()

# Initialize the agent controller
agent_controller = AgentController()

class TaskRequest(BaseModel):
    user_request: str
    max_steps: Optional[int] = 20

class AgentExecuteRequest(BaseModel):
    task: str

class TaskResponse(BaseModel):
    task_id: str
    status: str
    message: str

class AgentExecuteResponse(BaseModel):
    status: str

class TaskStatusResponse(BaseModel):
    task_id: str
    status: str
    current_step: Optional[int] = None
    max_steps: Optional[int] = None
    user_request: Optional[str] = None
    result: Optional[Dict[str, Any]] = None
    error: Optional[str] = None

async def run_agent(task: str) -> Dict[str, Any]:
    """
    Run the agent with the given task.
    This is the core function that executes the secure agent loop.
    """
    try:
        # Create a new agent task
        agent_task = AgentTask(
            task_id=str(uuid.uuid4()),
            user_request=task,
            max_steps=15  # Reasonable default for API usage
        )
        
        logger.info(f"Starting agent execution for task: {task}")
        
        # Execute the secure agent loop
        result = await agent_controller.execute_task(agent_task)
        
        return result
        
    except Exception as e:
        logger.error(f"Agent execution failed: {str(e)}")
        return {
            "status": "error",
            "error": str(e)
        }

@router.post("/agent_execute", response_model=AgentExecuteResponse)
async def agent_execute(request: AgentExecuteRequest, background_tasks: BackgroundTasks):
    """
    Execute agent task endpoint.
    
    POST /agent_execute
    {
        "task": "Find best laptop under 60000"
    }
    
    Returns:
    {
        "status": "started"
    }
    """
    try:
        logger.info(f"Received agent execute request: {request.task}")
        
        # Start the agent task in background
        background_tasks.add_task(run_agent, request.task)
        
        return AgentExecuteResponse(status="started")
        
    except Exception as e:
        logger.error(f"Failed to start agent task: {str(e)}")
        raise HTTPException(status_code=500, detail=f"Failed to start agent task: {str(e)}")

# ...existing code...
    task_id: str
    status: str
    current_step: Optional[int] = None
    max_steps: Optional[int] = None
    user_request: Optional[str] = None
    result: Optional[Dict[str, Any]] = None
    error: Optional[str] = None

@router.post("/execute-task", response_model=TaskResponse)
async def execute_task(request: TaskRequest, background_tasks: BackgroundTasks):
    """
    Execute an agent task.
    The task will run in the background and can be monitored via the status endpoint.
    """
    try:
        # Generate unique task ID
        task_id = str(uuid.uuid4())
        
        # Create task object
        task = AgentTask(
            task_id=task_id,
            user_request=request.user_request,
            max_steps=request.max_steps
        )
        
        # Start task in background
        background_tasks.add_task(agent_controller.execute_task, task)
        
        logger.info(f"Started task {task_id}: {request.user_request}")
        
        return TaskResponse(
            task_id=task_id,
            status="running",
            message="Task started successfully"
        )
        
    except Exception as e:
        logger.error(f"Failed to start task: {str(e)}")
        raise HTTPException(status_code=500, detail=f"Failed to start task: {str(e)}")

@router.get("/task-status", response_model=TaskStatusResponse)
async def get_task_status():
    """Get the status of the current task."""
    try:
        status = await agent_controller.get_task_status()
        
        if status.get("status") == "no_active_task":
            return TaskStatusResponse(
                task_id="",
                status="no_active_task"
            )
        
        return TaskStatusResponse(
            task_id=status.get("task_id", ""),
            status=status.get("status", "unknown"),
            current_step=status.get("current_step"),
            max_steps=status.get("max_steps"),
            user_request=status.get("user_request")
        )
        
    except Exception as e:
        logger.error(f"Failed to get task status: {str(e)}")
        raise HTTPException(status_code=500, detail=f"Failed to get task status: {str(e)}")

@router.post("/stop-task")
async def stop_task():
    """Stop the currently running task."""
    try:
        result = await agent_controller.stop_current_task()
        return {"message": result["message"]}
        
    except Exception as e:
        logger.error(f"Failed to stop task: {str(e)}")
        raise HTTPException(status_code=500, detail=f"Failed to stop task: {str(e)}")

@router.get("/health")
async def health_check():
    """Health check endpoint."""
    return {
        "status": "healthy",
        "service": "Secure Agentic Browser API",
        "version": "1.0.0"
    }

# Extension-specific endpoints for browser integration
@router.post("/browser/execute-action")
async def execute_browser_action(action: Dict[str, Any]):
    """
    Execute a single browser action (for browser extension integration).
    This endpoint allows the browser extension to send individual actions.
    """
    try:
        # Validate the action has required fields
        if "action" not in action:
            raise HTTPException(status_code=400, detail="Action field is required")
        
        # Initialize browser if needed
        if not hasattr(agent_controller.action_executor, 'page') or not agent_controller.action_executor.page:
            await agent_controller.action_executor.initialize_browser()
        
        # Validate action with firewall
        is_safe = await agent_controller.firewall_client.validate_action(action)
        if not is_safe:
            raise HTTPException(status_code=403, detail="Action blocked by security firewall")
        
        # Execute the action
        result = await agent_controller.action_executor.execute_action(action)
        
        # Report result to firewall
        await agent_controller.firewall_client.report_action_result(action, result)
        
        return {
            "success": True,
            "result": result
        }
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Failed to execute browser action: {str(e)}")
        raise HTTPException(status_code=500, detail=f"Failed to execute action: {str(e)}")

@router.get("/browser/page-state")
async def get_page_state():
    """Get current page state for extension or external tools."""
    try:
        if not hasattr(agent_controller.action_executor, 'page') or not agent_controller.action_executor.page:
            raise HTTPException(status_code=400, detail="No active browser session")
        
        state = await agent_controller.action_executor.get_page_state()
        return state
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Failed to get page state: {str(e)}")
        raise HTTPException(status_code=500, detail=f"Failed to get page state: {str(e)}")

@router.post("/browser/initialize")
async def initialize_browser():
    """Initialize browser session."""
    try:
        await agent_controller.action_executor.initialize_browser()
        return {"message": "Browser initialized successfully"}
        
    except Exception as e:
        logger.error(f"Failed to initialize browser: {str(e)}")
        raise HTTPException(status_code=500, detail=f"Failed to initialize browser: {str(e)}")

@router.post("/browser/cleanup")
async def cleanup_browser():
    """Clean up browser session."""
    try:
        await agent_controller.action_executor.cleanup()
        return {"message": "Browser cleaned up successfully"}
        
    except Exception as e:
        logger.error(f"Failed to cleanup browser: {str(e)}")
        raise HTTPException(status_code=500, detail=f"Failed to cleanup browser: {str(e)}")