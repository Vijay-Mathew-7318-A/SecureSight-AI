"""SecureSight AI - FastAPI application entry point."""

import logging

from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse

from app.api.routes import router
from app.core.config import get_settings
from app.core.url_validator import UnsafeURLError

logger = logging.getLogger("securesight")

settings = get_settings()

app = FastAPI(
    title=settings.app_name,
    description="AI-powered OWASP web security assessment platform.",
    version=settings.app_version,
)

app.include_router(router)


@app.exception_handler(UnsafeURLError)
async def unsafe_url_handler(request: Request, exc: UnsafeURLError):
    """Unsafe or invalid URLs become a clear 400 error."""
    return JSONResponse(status_code=400, content={"detail": str(exc)})


@app.exception_handler(Exception)
async def unexpected_error_handler(request: Request, exc: Exception):
    """Unexpected crashes become a generic 500. Details go to the server log only."""
    logger.exception("Unexpected error while handling %s", request.url.path)
    return JSONResponse(
        status_code=500,
        content={"detail": "An unexpected server error occurred."},
    )


@app.get("/")
def root():
    """Simple welcome message to confirm the server is running."""
    return {
        "message": f"Welcome to {settings.app_name}",
        "docs": "/docs",
        "health": "/api/health",
    }