import uvicorn
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

# Load environment variables from .env file
try:
    from dotenv import load_dotenv
    load_dotenv()
except ImportError:
    # dotenv not installed, use system environment variables
    pass

from src.api.agent_routes import router as agent_router

app = FastAPI(
    title="Secure Agentic Browser",
    description="AI-powered browser automation with security firewall",
    version="1.0.0"
)

# Configure CORS for browser extension compatibility
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # Allow all origins for browser extensions
    allow_credentials=True,
    allow_methods=["*"],  # Allow all HTTP methods
    allow_headers=["*"],  # Allow all headers
    expose_headers=["*"]  # Expose all headers to the client
)

# Register API routes
app.include_router(agent_router, prefix="/api/v1")

@app.get("/")
async def health_check():
    return {
        "status": "healthy", 
        "service": "Secure Agentic Browser",
        "version": "1.0.0",
        "endpoints": {
            "agent_execute": "POST /api/v1/agent_execute",
            "task_status": "GET /api/v1/task-status",
            "stop_task": "POST /api/v1/stop-task",
            "health": "GET /api/v1/health"
        }
    }

if __name__ == "__main__":
    uvicorn.run(
        "main:app",
        host="0.0.0.0",
        port=8001,
        reload=True,
        log_level="info"
    )