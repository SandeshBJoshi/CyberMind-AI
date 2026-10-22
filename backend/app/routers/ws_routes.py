from fastapi import APIRouter, WebSocket, WebSocketDisconnect

from .. import auth
from ..database import SessionLocal
from ..websocket_manager import manager

router = APIRouter()


@router.websocket("/ws/live")
async def ws_live(websocket: WebSocket):
    """Live security feed. Admin only: the token comes in the query string (browsers cannot set WebSocket headers)."""
    token = websocket.query_params.get("token")
    db = SessionLocal()
    try:
        ok = auth.admin_from_token(token, db) is not None
    finally:
        db.close()
    if not ok:
        await websocket.close(code=4401)      # 4401 = unauthorised (custom close code)
        return
    await manager.connect(websocket)
    try:
        while True:
            # We don't expect inbound client messages, but keep the socket alive.
            await websocket.receive_text()
    except WebSocketDisconnect:
        manager.disconnect(websocket)
