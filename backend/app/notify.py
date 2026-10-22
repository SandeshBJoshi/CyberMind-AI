"""Optional outbound notifications (Slack-style webhook). Never blocks a request and never raises."""
import json
import threading
import urllib.request

from .config import settings


def send_webhook(event: dict) -> None:
    url = settings.webhook_url
    if not url:
        return

    def _post():
        try:
            req = urllib.request.Request(url, data=json.dumps(event, default=str).encode(), headers={"Content-Type": "application/json"})
            urllib.request.urlopen(req, timeout=4).read()
        except Exception:
            pass

    threading.Thread(target=_post, daemon=True).start()
