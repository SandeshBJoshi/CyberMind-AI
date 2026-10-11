"""Safe, static parsing of a raw email (.eml) for phishing analysis.

Nothing here executes, renders or opens anything from the message: attachments are only hashed and named, HTML is
parsed for its links, and sizes and counts are capped so a hostile message cannot exhaust memory.
"""
import hashlib
import re
from email import message_from_bytes, policy
from email.utils import getaddresses, parseaddr
from html.parser import HTMLParser
from urllib.parse import urlparse

MAX_BYTES = 5 * 1024 * 1024
MAX_LINKS = 200
MAX_ATTACHMENTS = 25
URL_RE = re.compile(r"https?://[^\s<>\"'()\[\]]+", re.IGNORECASE)


class _Anchors(HTMLParser):
    """Collects <a href> targets with their visible text, and form actions."""

    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.links: list[dict] = []
        self._href = None
        self._text: list[str] = []

    def handle_starttag(self, tag, attrs):
        a = dict(attrs)
        if tag == "a" and a.get("href"):
            self._href, self._text = a["href"].strip(), []
        elif tag == "form" and a.get("action"):
            self.links.append({"href": a["action"].strip(), "text": "(form submits here)", "kind": "form"})

    def handle_data(self, data):
        if self._href is not None:
            self._text.append(data)

    def handle_endtag(self, tag):
        if tag == "a" and self._href is not None:
            self.links.append({"href": self._href, "text": " ".join("".join(self._text).split())[:200], "kind": "anchor"})
            self._href = None


def _domain_of(address: str) -> str:
    _, addr = parseaddr(address or "")
    return addr.rsplit("@", 1)[-1].lower().strip(">") if "@" in addr else ""


def _header_list(msg, name):
    return [str(v) for v in msg.get_all(name, [])]


def parse_email(raw: bytes) -> dict:
    """Returns a plain dict describing the message. Raises ValueError for empty or oversized input."""
    if not raw or not raw.strip():
        raise ValueError("The email is empty.")
    if len(raw) > MAX_BYTES:
        raise ValueError(f"The email is larger than {MAX_BYTES // (1024 * 1024)} MB.")
    msg = message_from_bytes(raw, policy=policy.default)

    from_name, from_addr = parseaddr(str(msg.get("From", "")))
    reply_name, reply_addr = parseaddr(str(msg.get("Reply-To", "")))
    _, return_path = parseaddr(str(msg.get("Return-Path", "")))

    text_parts, html_parts, attachments = [], [], []
    for part in msg.walk():
        if part.is_multipart():
            continue
        ctype = part.get_content_type()
        fname = part.get_filename()
        disp = (part.get_content_disposition() or "").lower()
        if fname or disp == "attachment":
            if len(attachments) < MAX_ATTACHMENTS:
                data = part.get_payload(decode=True) or b""
                attachments.append({"filename": str(fname or "(unnamed)")[:200], "content_type": ctype, "size": len(data),
                                    "sha256": hashlib.sha256(data).hexdigest()})
            continue
        try:
            content = part.get_content()
        except Exception:
            content = (part.get_payload(decode=True) or b"").decode("utf-8", "replace")
        if ctype == "text/plain":
            text_parts.append(str(content))
        elif ctype == "text/html":
            html_parts.append(str(content))

    body_text = "\n".join(text_parts)
    anchors = _Anchors()
    for h in html_parts:
        try:
            anchors.feed(h)
        except Exception:
            pass
    links = list(anchors.links)
    seen = {l["href"] for l in links}
    for source in (body_text, *html_parts):
        for url in URL_RE.findall(source):
            url = url.rstrip(".,;:!?")
            if url not in seen:
                seen.add(url)
                links.append({"href": url, "text": "", "kind": "text"})
    links = links[:MAX_LINKS]

    # words the reader sees (for language checks): plain text, else the visible text of the HTML
    visible = body_text
    if not visible and html_parts:
        visible = re.sub(r"<[^>]+>", " ", " ".join(html_parts))
    visible = " ".join(visible.split())[:20000]

    return {
        "from_name": from_name, "from_addr": from_addr.lower(), "from_domain": _domain_of(from_addr),
        "reply_to_addr": reply_addr.lower(), "reply_to_domain": _domain_of(reply_addr),
        "return_path_domain": _domain_of(return_path),
        "to": [a for _, a in getaddresses([str(msg.get("To", ""))]) if a][:20],
        "subject": str(msg.get("Subject", ""))[:300], "date": str(msg.get("Date", ""))[:80],
        "message_id_domain": _domain_of(str(msg.get("Message-ID", "")).strip("<>")),
        "received_count": len(_header_list(msg, "Received")),
        "auth_results": " ".join(_header_list(msg, "Authentication-Results")).lower(),
        "received_spf": " ".join(_header_list(msg, "Received-SPF")).lower(),
        "has_dkim_signature": bool(msg.get("DKIM-Signature")),
        "body_text": visible, "links": links, "attachments": attachments,
        "raw_sha256": hashlib.sha256(raw).hexdigest(), "raw_size": len(raw),
    }


def host_of(url: str) -> str:
    try:
        return (urlparse(url if "://" in url else "http://" + url).hostname or "").lower()
    except ValueError:
        return ""
