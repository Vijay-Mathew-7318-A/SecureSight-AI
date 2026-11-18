"""Pydantic models describing API requests and responses."""

from pydantic import BaseModel, Field


class ValidateURLRequest(BaseModel):
    """Body of POST /api/validate-url."""

    url: str = Field(..., max_length=4096, examples=["example.com"])


class ValidateURLResponse(BaseModel):
    """Returned when a URL passes all safety checks."""

    valid: bool = True
    url: str
    scheme: str
    hostname: str
    port: int
    ip_addresses: list[str]


class HealthResponse(BaseModel):
    """Returned by GET /api/health."""

    status: str
    app: str
    version: str


class ErrorResponse(BaseModel):
    """Shape of every error returned by the API."""

    detail: str