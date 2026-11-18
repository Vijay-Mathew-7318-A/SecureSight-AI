"""SecureSight AI - FastAPI application entry point."""

from fastapi import FastAPI

APP_NAME = "SecureSight AI"
APP_VERSION = "0.1.0"

app = FastAPI(
    title=APP_NAME,
    description="AI-powered OWASP web security assessment platform.",
    version=APP_VERSION,
)


@app.get("/")
def root():
    """Simple welcome message to confirm the server is running."""
    return {
        "message": f"Welcome to {APP_NAME}",
        "docs": "/docs",
        "health": "/api/health",
    }


@app.get("/api/health")
def health_check():
    """Health check endpoint used to verify the API is alive."""
    return {
        "status": "ok",
        "app": APP_NAME,
        "version": APP_VERSION,
    }