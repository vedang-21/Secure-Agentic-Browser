from fastapi import APIRouter, HTTPException, BackgroundTasks
from pydantic import BaseModel
from typing import Dict, Any, Optional, List
import uuid
import logging
import asyncio
import os
import json
import time
from pathlib import Path
import sqlite3

from ..agent.agent_controller import AgentController, AgentTask
from firewall.core.security_mediator import SecurityMediator

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
    steps_log: Optional[list] = None

class RunOnActiveTabRequest(BaseModel):
    task: str
    tabId: Optional[int] = None
    tabUrl: Optional[str] = None
    # Extension-generated per-run marker used to map to the exact tab via CDP.
    marker: Optional[str] = None
    # Optional override; defaults to CDP_ENDPOINT env or http://127.0.0.1:9222
    cdpEndpoint: Optional[str] = None
    max_steps: Optional[int] = 15

class AnalyzePageRequest(BaseModel):
    page_content: str
    goal: Optional[str] = ""
    tabUrl: Optional[str] = None
    title: Optional[str] = None

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
            user_request=status.get("user_request"),
            result=status.get("result"),
            error=status.get("error"),
            steps_log=status.get("steps_log"),
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

@router.post("/agent/run_on_active_tab")
async def run_on_active_tab(request: RunOnActiveTabRequest):
    """Run the secure agent loop attached to an existing Chrome tab via CDP.

    The extension supplies the active tab info; the server attaches to Chrome that was
    started with remote debugging (e.g. --remote-debugging-port=9222).

    All actions still flow through FirewallClient -> root firewall/analysers.
    """
    try:
        if not request.task:
            raise HTTPException(status_code=400, detail="task is required")

        cdp_endpoint = request.cdpEndpoint or os.getenv("CDP_ENDPOINT") or "http://127.0.0.1:9222"

        # Attach first (prefer exact marker match when available; fallback to URL substring)
        await agent_controller.attach_to_existing_tab(
            cdp_endpoint=cdp_endpoint,
            tab_url=request.tabUrl,
            marker=request.marker,
        )

        agent_task = AgentTask(
            task_id=str(uuid.uuid4()),
            user_request=request.task,
            max_steps=int(request.max_steps or 15),
        )

        result = await agent_controller.execute_task(agent_task)
        return {"status": "ok", "task_id": agent_task.task_id, "result": result}

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"run_on_active_tab failed: {str(e)}")
        raise HTTPException(status_code=500, detail=str(e))

@router.post("/firewall/analyze_page")
async def analyze_page(request: AnalyzePageRequest):
    """Analyze current page HTML for threats (DOM/NLP + optional LLM layer)."""
    try:
        mediator = SecurityMediator(
            {
                "use_llm_layer": True,
                "llm_threshold": float(os.getenv("FIREWALL_LLM_THRESHOLD", "0.4")),
                "gemini_api_key": os.getenv("GOOGLE_API_KEY") or os.getenv("GEMINI_API_KEY"),
            }
        )
        report = mediator.analyze_page(page_content=request.page_content or "", agent_goal=request.goal or "")

        # Persist analyze events so they show up in lifetime metrics/logs.
        # We treat each analyze call as a scan with its own task_id.
        try:
            from ..memory.sqlite_memory import SQLiteMemoryStore

            mem = SQLiteMemoryStore()
            risk_score = 0.0
            verdict = "ALLOW"
            try:
                risk_score = float((report or {}).get("risk_score") or (report or {}).get("risk") or 0.0)
            except Exception:
                risk_score = 0.0

            # Best-effort verdict derivation (use report verdict if provided)
            verdict = str((report or {}).get("verdict") or "").upper().strip() or (
                "BLOCK" if risk_score >= 0.65 else "WARN" if risk_score >= 0.35 else "ALLOW"
            )

            url = str(request.tabUrl or "")
            title = str(request.title or "")
            goal = str(request.goal or "")
            summary = f"analyze_page verdict={verdict} risk={risk_score:.3f} goal={goal[:80]}".strip()

            mem.add(
                kind="analyze",
                task_id=f"analyze:{uuid.uuid4()}",
                url=url,
                title=title,
                summary=summary,
                content=request.page_content or "",
                metadata={
                    "source": "firewall.analyze_page",
                    "risk_score": risk_score,
                    "verdict": verdict,
                    "tabUrl": request.tabUrl,
                    "title": request.title,
                    "goal": request.goal,
                    "report": report,
                },
            )
        except Exception as e:
            logger.warning(f"Failed to persist analyze_page event to memory: {e}")

        return {
            "status": "ok",
            "tabUrl": request.tabUrl,
            "title": request.title,
            "report": report,
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@router.get("/metrics")
async def metrics() -> Dict[str, Any]:
    """Dashboard-friendly metrics snapshot (JSON).

    Includes:
    - current task status + last N timeline steps
    - step execution stats (blocked/executed/errors) + duration aggregates
    - memory DB stats (row counts, by kind, db size)
    - tail of agent_execution.log

    Safe for localhost use. If hosting, add auth/rate limiting.
    """

    status = await agent_controller.get_task_status()

    steps = status.get("steps_log", []) or []
    blocked = 0
    executed = 0
    errors = 0
    durations = []

    # Dashboard rollups
    verdict_split: Dict[str, int] = {"ALLOW": 0, "BLOCK": 0, "WARN": 0, "CONFIRM": 0}
    attack_types: Dict[str, int] = {}
    risk_over_time = []
    timestamps = []
    dashboard_logs = []

    for s in steps:
        if not isinstance(s, dict):
            continue

        fw = s.get("firewall") if isinstance(s.get("firewall"), dict) else {}
        verdict = str(fw.get("verdict") or ("ALLOW" if fw.get("allowed", True) else "BLOCK")).upper()
        if verdict not in verdict_split:
            verdict_split[verdict] = 0
        verdict_split[verdict] += 1

        if fw.get("allowed") is False:
            blocked += 1
        if s.get("status") == "executed":
            executed += 1

        ex = s.get("execution") if isinstance(s.get("execution"), dict) else {}
        if ex.get("status") == "error":
            errors += 1

        d = s.get("duration")
        if isinstance(d, (int, float)):
            durations.append(float(d))

        # Risk and timeline series
        risk = fw.get("risk")
        if isinstance(risk, (int, float)):
            r = float(risk)
            risk_over_time.append(r)
            timestamps.append(str(s.get("ts") or s.get("timestamp") or ""))

        # Attack type rollup (best-effort)
        for t in (fw.get("reasons") or fw.get("signals") or []):
            if isinstance(t, str) and t.strip():
                key = t.strip()[:42]
                attack_types[key] = attack_types.get(key, 0) + 1

        # Recent logs table
        url = s.get("url") or (s.get("page") or {}).get("url")
        title = (s.get("page") or {}).get("title") if isinstance(s.get("page"), dict) else None
        explain = fw.get("explanation") or fw.get("summary") or ""
        if not explain and fw.get("reasons"):
            explain = ", ".join([str(x) for x in (fw.get("reasons") or [])[:3]])

        dashboard_logs.append(
            {
                "ts": str(s.get("ts") or s.get("timestamp") or ""),
                "url": str(url or ""),
                "risk": float(risk) if isinstance(risk, (int, float)) else 0.0,
                "verdict": verdict,
                "explain": str(explain or title or ""),
            }
        )

    # Keep only the most recent items
    dashboard_logs = [l for l in dashboard_logs if (l.get("url") or l.get("explain"))]
    dashboard_logs = dashboard_logs[-30:][::-1]

    durations_sorted = sorted(durations)
    avg_step_s = (sum(durations) / len(durations)) if durations else 0.0
    p95_step_s = 0.0
    if durations_sorted:
        idx = int(0.95 * (len(durations_sorted) - 1))
        p95_step_s = durations_sorted[max(0, min(idx, len(durations_sorted) - 1))]

    avg_risk = (sum(risk_over_time) / len(risk_over_time)) if risk_over_time else 0.0

    # Memory DB stats
    mem_db_path = Path(os.getenv("AGENT_MEMORY_DB", "agent_memory.db"))
    mem_stats: Dict[str, Any] = {
        "path": str(mem_db_path),
        "exists": mem_db_path.exists(),
        "size_bytes": mem_db_path.stat().st_size if mem_db_path.exists() else 0,
        "total_items": 0,
        "by_kind": {},
        "total_tasks": 0,
    }

    # Lifetime aggregates (computed from memory when possible)
    lifetime_verdict_split: Dict[str, int] = {"ALLOW": 0, "BLOCK": 0, "WARN": 0, "CONFIRM": 0}
    lifetime_blocked = 0
    lifetime_avg_risk = 0.0
    lifetime_risk_series: List[float] = []
    lifetime_ts_series: List[str] = []
    lifetime_logs = []

    if mem_db_path.exists():
        try:
            con = sqlite3.connect(str(mem_db_path))
            con.row_factory = sqlite3.Row
            cur = con.cursor()

            cur.execute("SELECT COUNT(*) AS c FROM memory_items")
            row = cur.fetchone()
            mem_stats["total_items"] = int((dict(row).get("c") if row else 0) or 0)

            cur.execute("SELECT kind, COUNT(*) AS c FROM memory_items GROUP BY kind")
            mem_stats["by_kind"] = {str(r["kind"]): int(r["c"]) for r in cur.fetchall()}

            # Total scans: count distinct task_id for agent tasks + analyze events only.
            # This avoids counting unrelated rows that may have empty task_id.
            cur.execute(
                "SELECT COUNT(DISTINCT task_id) AS c "
                "FROM memory_items "
                "WHERE task_id IS NOT NULL AND task_id != '' "
                "  AND (kind IN ('step','final') OR kind = 'analyze')"
            )
            row = cur.fetchone()
            mem_stats["total_tasks"] = int((dict(row).get("c") if row else 0) or 0)

            # Risk & trust aggregates from metadata_json
            try:
                cur.execute(
                    "SELECT "
                    "  COUNT(*) AS n, "
                    "  SUM(CASE WHEN json_extract(metadata_json, '$.risk_score') >= 0.65 THEN 1 ELSE 0 END) AS threats, "
                    "  AVG(COALESCE(json_extract(metadata_json, '$.risk_score'), 0.0)) AS avg_risk "
                    "FROM memory_items "
                    "WHERE kind IN ('step','final','analyze')"
                )
                rrow = cur.fetchone()
                rdict = dict(rrow) if rrow else {}
                lifetime_blocked = int(rdict.get("threats") or 0)
                lifetime_avg_risk = float(rdict.get("avg_risk") or 0.0)
            except Exception:
                lifetime_blocked = 0
                lifetime_avg_risk = 0.0

            # Risk series (last 20)
            try:
                cur.execute(
                    "SELECT ts, COALESCE(json_extract(metadata_json, '$.risk_score'), 0.0) AS risk "
                    "FROM memory_items "
                    "WHERE kind IN ('step','final','analyze') "
                    "ORDER BY ts DESC "
                    "LIMIT 20"
                )
                rows = cur.fetchall()
                # reverse to chronological
                rows = list(reversed(rows))
                lifetime_risk_series = [float(r["risk"] or 0.0) for r in rows]
                lifetime_ts_series = [time.strftime('%H:%M:%S', time.localtime(float(r["ts"] or 0.0))) for r in rows]
            except Exception:
                lifetime_risk_series = []
                lifetime_ts_series = []

            # Verdict split (prefer stored verdict when present; fallback to risk thresholds)
            try:
                cur.execute(
                    "SELECT "
                    "  SUM(CASE WHEN upper(COALESCE(json_extract(metadata_json, '$.verdict'),'')) = 'BLOCK' THEN 1 ELSE 0 END) AS block_n, "
                    "  SUM(CASE WHEN upper(COALESCE(json_extract(metadata_json, '$.verdict'),'')) = 'WARN' THEN 1 ELSE 0 END) AS warn_n, "
                    "  SUM(CASE WHEN upper(COALESCE(json_extract(metadata_json, '$.verdict'),'')) = 'CONFIRM' THEN 1 ELSE 0 END) AS confirm_n, "
                    "  SUM(CASE WHEN upper(COALESCE(json_extract(metadata_json, '$.verdict'),'')) = 'ALLOW' THEN 1 ELSE 0 END) AS allow_n, "
                    "  SUM(CASE WHEN COALESCE(json_extract(metadata_json, '$.verdict'), NULL) IS NULL OR json_extract(metadata_json, '$.verdict') = '' THEN 1 ELSE 0 END) AS no_verdict_n "
                    "FROM memory_items WHERE kind IN ('step','final','analyze')"
                )
                vrow = cur.fetchone()
                vdict = dict(vrow) if vrow else {}

                block_n = int(vdict.get("block_n") or 0)
                warn_n = int(vdict.get("warn_n") or 0)
                confirm_n = int(vdict.get("confirm_n") or 0)
                allow_n = int(vdict.get("allow_n") or 0)
                no_verdict_n = int(vdict.get("no_verdict_n") or 0)

                lifetime_verdict_split["BLOCK"] = block_n
                lifetime_verdict_split["WARN"] = warn_n
                lifetime_verdict_split["CONFIRM"] = confirm_n
                lifetime_verdict_split["ALLOW"] = allow_n

                if no_verdict_n:
                    cur.execute(
                        "SELECT "
                        "  SUM(CASE WHEN COALESCE(json_extract(metadata_json, '$.risk_score'),0.0) >= 0.65 THEN 1 ELSE 0 END) AS block_n, "
                        "  SUM(CASE WHEN COALESCE(json_extract(metadata_json, '$.risk_score'),0.0) >= 0.35 AND COALESCE(json_extract(metadata_json, '$.risk_score'),0.0) < 0.65 THEN 1 ELSE 0 END) AS warn_n, "
                        "  SUM(CASE WHEN COALESCE(json_extract(metadata_json, '$.risk_score'),0.0) < 0.35 THEN 1 ELSE 0 END) AS allow_n "
                        "FROM memory_items "
                        "WHERE kind IN ('step','final','analyze') AND (json_extract(metadata_json,'$.verdict') IS NULL OR json_extract(metadata_json,'$.verdict') = '')"
                    )
                    rr0 = cur.fetchone()
                    rr = dict(rr0) if rr0 else {}
                    lifetime_verdict_split["BLOCK"] += int(rr.get("block_n") or 0)
                    lifetime_verdict_split["WARN"] += int(rr.get("warn_n") or 0)
                    lifetime_verdict_split["ALLOW"] += int(rr.get("allow_n") or 0)
            except Exception:
                pass

            # Treat threats/blocked as BLOCK + CONFIRM (tune if needed)
            lifetime_blocked = int(lifetime_verdict_split.get("BLOCK", 0) + lifetime_verdict_split.get("CONFIRM", 0))

            # Recent logs (last 30)
            try:
                cur.execute(
                    "SELECT ts, url, title, summary, metadata_json "
                    "FROM memory_items "
                    "WHERE kind IN ('step','final','analyze') "
                    "ORDER BY ts DESC "
                    "LIMIT 30"
                )
                for r in cur.fetchall():
                    meta = {}
                    try:
                        meta = json.loads(r["metadata_json"] or "{}")
                    except Exception:
                        meta = {}
                    risk = 0.0
                    try:
                        risk = float(meta.get("risk_score", 0.0) or 0.0)
                    except Exception:
                        risk = 0.0

                    verdict = str(meta.get("verdict") or "").upper().strip()
                    if not verdict:
                        verdict = "BLOCK" if risk >= 0.65 else "WARN" if risk >= 0.35 else "ALLOW"

                    lifetime_logs.append(
                        {
                            "ts": time.strftime('%H:%M:%S', time.localtime(float(r["ts"] or 0.0))),
                            "url": str(r["url"] or ""),
                            "risk": risk,
                            "verdict": verdict,
                            "explain": str(r["summary"] or r["title"] or ""),
                        }
                    )
            except Exception:
                lifetime_logs = []

            con.close()
        except Exception as e:
            mem_stats["error"] = str(e)

    # Tail logs
    log_path = Path("agent_execution.log")
    log_tail = []
    if log_path.exists():
        try:
            text = log_path.read_text(errors="ignore")
            log_tail = text.splitlines()[-80:]
        except Exception:
            log_tail = []

    # Ensure attack_types has something friendly even when empty
    if not attack_types:
        # Derive from verdict counts as a fallback
        attack_types = {
            "Prompt Injection": 0,
            "Phishing": 0,
            "Obfuscation": 0,
            "Credential Harvest": 0,
            "DOM Manipulation": 0,
            "Redirect Chain": 0,
        }

    # Prefer lifetime aggregates from memory when available
    threats_total = int(lifetime_blocked or blocked)
    blocked_total = int(lifetime_blocked or blocked)
    avg_risk_total = float(lifetime_avg_risk if mem_stats.get("total_items") else avg_risk)
    verdict_total = lifetime_verdict_split if mem_stats.get("total_items") else verdict_split
    risk_series = lifetime_risk_series[-20:] if lifetime_risk_series else risk_over_time[-20:]
    ts_series = lifetime_ts_series[-20:] if lifetime_ts_series else timestamps[-20:]
    logs_series = lifetime_logs if lifetime_logs else dashboard_logs

    return {
        # ORIX dashboard expects these top-level keys
        "total_scans": int(mem_stats.get("total_tasks") or 0),
        "threats": threats_total,
        "blocked": blocked_total,
        "avg_risk": round(float(avg_risk_total), 3),
        "risk_over_time": risk_series,
        "timestamps": ts_series,
        "attack_types": attack_types,
        "verdict_split": verdict_total,
        "logs": logs_series,

        # Keep existing detailed fields for debugging/other UIs
        "service": "secure-agentic-browser",
        "task": {
            "task_id": status.get("task_id"),
            "status": status.get("status"),
            "current_step": status.get("current_step"),
            "max_steps": status.get("max_steps"),
            "user_request": status.get("user_request"),
        },
        "timeline_window": {
            "window_size": len(steps),
            "executed": executed,
            "blocked": blocked,
            "errors": errors,
            "avg_step_s": round(avg_step_s, 3),
            "p95_step_s": round(p95_step_s, 3),
        },
        "memory": mem_stats,
        "logs_debug": {
            "agent_execution_log_path": str(log_path),
            "tail_lines": log_tail,
        },
    }