
from typing import Any, Dict

from fastapi import APIRouter, Depends
from pydantic import BaseModel, Field

from app.security import require_permission


router = APIRouter()


class ChatRequest(BaseModel):
    message: str = Field(
        ...,
        min_length=1,
        max_length=4000,
        description="Message submitted to the SecureNova AI service.",
    )


@router.get("/health", tags=["System"])
async def health_check():
    """
    Public health-check endpoint.
    Confirms that the SecureNova backend is running.
    """
    return {
        "status": "healthy",
        "service": "SecureNova AI API",
        "authentication": "Auth0",
    }


@router.get("/ai-data", tags=["AI Data"])
async def get_ai_data(
    claims: Dict[str, Any] = Depends(
        require_permission("read:ai-data")
    ),
):
    """
    User-level protected endpoint.

    Requires:
        read:ai-data
    """
    return {
        "status": "success",
        "message": "AI data retrieved successfully.",
        "user_id": claims.get("sub"),
        "data": {
            "model": "SecureNova-Demo",
            "environment": "development",
            "records": [
                {
                    "id": 1,
                    "category": "identity-security",
                    "description": "Sample protected AI record.",
                },
                {
                    "id": 2,
                    "category": "access-control",
                    "description": "Sample authorization record.",
                },
            ],
        },
    }


@router.post("/admin", tags=["Administration"])
async def admin_operation(
    claims: Dict[str, Any] = Depends(
        require_permission("write:admin")
    ),
):
    """
    Administrative endpoint.

    Requires:
        write:admin

    The operation is simulated for this assignment.
    """
    return {
        "status": "success",
        "message": "Administrative access authorized.",
        "operation": "simulated-admin-operation",
        "actor": claims.get("sub"),
    }


@router.post("/chat", tags=["AI Chat"])
async def chat(
    request: ChatRequest,
    claims: Dict[str, Any] = Depends(
        require_permission("read:ai-data")
    ),
):
    """
    Protected AI chat demonstration endpoint.

    Requires:
        read:ai-data

    The response is simulated. A paid external LLM is not
    required for the OAuth and token-expiry demonstration.
    """
    return {
        "status": "success",
        "service": "SecureNova AI Chat",
        "message_received": request.message,
        "response": (
            "Your request was authenticated successfully. "
            "The SecureNova demonstration backend received your message."
        ),
        "authenticated_identity": claims.get("sub"),
        "llm_integration": "simulated",
    }
