"""Phishing verdict: parse the email, run the checks, add up the points, explain the result.

Same shape as decision_engine.py: fixed weights, a score, a tier, and a plain-English reason for every point.
The verdict never depends on an AI model: an email can contain text written to manipulate one.
"""
from . import phish_rules
from .email_parser import host_of, parse_email

SUSPICIOUS_AT = 3.0
PHISHING_AT = 6.0
VERSION = 1

LINK_CODES = {"link_text_mismatch", "lookalike_link_domain", "ip_address_link", "punycode_link", "userinfo_in_link", "form_to_other_domain",
              "url_shortener", "insecure_login_link", "risky_tld"}
ATTACK_INFO = {
    "T1566.002": "Phishing: Spearphishing Link",
    "T1566.001": "Phishing: Spearphishing Attachment",
    "T1204.001": "User Execution: Malicious Link",
    "T1204.002": "User Execution: Malicious File",
    "T1598": "Phishing for Information",
    "T1656": "Impersonation",
}

ACTIONS = {
    "PHISHING": ["Do not click any link or open any attachment.", "Report it to the security team and delete it from every mailbox that received it.",
                 "Block the sender and link domains listed under indicators.", "If anyone already clicked or typed a password, reset that password and review the account's recent logins and sessions."],
    "SUSPICIOUS": ["Do not click links or open attachments until it is verified.", "Confirm with the sender through a different channel (call or a known address).",
                   "If it cannot be verified, treat it as phishing and report it."],
    "SAFE": ["No strong phishing signs were found. Stay careful with unexpected requests; a clean result is not a guarantee."],
}


def _tier(score: float) -> str:
    return "PHISHING" if score >= PHISHING_AT else "SUSPICIOUS" if score >= SUSPICIOUS_AT else "SAFE"


def _attack(codes: set[str]) -> list[dict]:
    ids = []
    if codes & LINK_CODES:
        ids += ["T1566.002", "T1204.001"]
    if "dangerous_attachment" in codes or "risky_attachment" in codes:
        ids += ["T1566.001", "T1204.002"]
    if "language_credentials" in codes:
        ids.append("T1598")
    if codes & {"display_name_spoof", "lookalike_sender_domain", "official_name_free_mail"}:
        ids.append("T1656")
    return [{"id": i, "name": ATTACK_INFO[i]} for i in dict.fromkeys(ids)]


def _indicators(e: dict) -> dict:
    domains, urls, ips = [], [], []
    for d in (e["from_domain"], e["reply_to_domain"]):
        if d:
            domains.append(d)
    for l in e["links"]:
        h = host_of(l["href"])
        if not h:
            continue
        if h.replace(".", "").isdigit():
            ips.append(h)
        else:
            domains.append(h)
        urls.append(l["href"][:300])
    return {
        "domains": list(dict.fromkeys(domains))[:30], "urls": list(dict.fromkeys(urls))[:30], "ips": list(dict.fromkeys(ips))[:10],
        "emails": [a for a in dict.fromkeys([e["from_addr"], e["reply_to_addr"]]) if a],
        "file_hashes": [{"name": a["filename"], "sha256": a["sha256"]} for a in e["attachments"]],
    }


def analyze(raw: bytes) -> dict:
    """Returns the full analysis (JSON-serialisable). Raises ValueError for empty or oversized input."""
    return analyze_full(raw)[0]


def analyze_full(raw: bytes) -> tuple[dict, dict]:
    """Like analyze(), but also returns the parsed email (needed by the optional AI analyst; never stored)."""
    e = parse_email(raw)
    reasons, positives = [], []
    for check in phish_rules.CHECKS:
        found, good = check(e)
        reasons += found
        positives += good
    reasons = [r for r in reasons if r["points"] > 0]
    reasons.sort(key=lambda r: -r["points"])
    score = round(sum(r["points"] for r in reasons), 1)
    verdict = _tier(score)
    codes = {r["code"] for r in reasons}
    result = {
        "version": VERSION, "verdict": verdict, "score": score, "thresholds": {"suspicious": SUSPICIOUS_AT, "phishing": PHISHING_AT},
        "reasons": reasons, "positives": positives, "attack": _attack(codes), "actions": ACTIONS[verdict], "indicators": _indicators(e),
        "email": {"from_name": e["from_name"], "from_addr": e["from_addr"], "reply_to": e["reply_to_addr"], "subject": e["subject"], "date": e["date"],
                  "to": e["to"], "auth_results": e["auth_results"][:300], "links": [{"href": l["href"][:300], "text": l["text"], "kind": l["kind"]} for l in e["links"]],
                  "attachments": e["attachments"], "raw_sha256": e["raw_sha256"], "raw_size": e["raw_size"]},
    }
    return result, e
