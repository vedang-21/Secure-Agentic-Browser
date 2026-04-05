import uvicorn
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from fastapi.responses import RedirectResponse

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

# Serve ORIX dashboard/static pages
app.mount("/orix", StaticFiles(directory="orix", html=True), name="orix")

@app.get("/", include_in_schema=False)
async def root_redirect():
    return RedirectResponse(url="/orix/dashboard.html")

# Keep a health endpoint (moved to /api/v1/health)
@app.get("/healthz", include_in_schema=False)
async def healthz():
    return {"status": "ok"}

if __name__ == "__main__":
    uvicorn.run(
        "main:app",
        host="0.0.0.0",
        port=8001,
        reload=True,
        log_level="info"
    )