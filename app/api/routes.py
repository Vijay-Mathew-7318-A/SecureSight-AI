"""API routes for SecureSight AI."""

from fastapi import APIRouter

from app.api.schemas import (
    ErrorResponse,
    HealthResponse,
    ValidateURLRequest,
    ValidateURLResponse,
)
from app.core.config import get_settings
from app.core.url_validator import validate_target_url

router = APIRouter(prefix="/api")


@router.get("/health", response_model=HealthResponse)
def health_check():
    """Health check endpoint used to verify the API is alive."""
    settings = get_settings()
    return HealthResponse(
        status="ok",
        app=settings.app_name,
        version=settings.app_version,
    )


@router.post(
    "/validate-url",
    response_model=ValidateURLResponse,
    responses={400: {"model": ErrorResponse}},
)
def validate_url(request: ValidateURLRequest):
    """Check whether a URL is safe to scan.

    If the URL is unsafe, validate_target_url() raises UnsafeURLError,
    which main.py converts into a 400 response with a clear message.
    """
    target = validate_target_url(request.url)
    return ValidateURLResponse(
        url=target.url,
        scheme=target.scheme,
        hostname=target.hostname,
        port=target.port,
        ip_addresses=target.ip_addresses,
    )