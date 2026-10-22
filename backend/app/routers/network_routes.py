"""Feature 3: CyberMind Network status for the console (admin only). Read-only: the hub itself is operated separately."""
from fastapi import APIRouter, Depends

from .. import auth, network

router = APIRouter(prefix="/api/network", tags=["network"], dependencies=[Depends(auth.get_current_admin)])


@router.get("/status")
def network_status():
    return network.status()


@router.post("/refresh")
def network_refresh():
    return {"received": network.refresh(), **network.status()}
