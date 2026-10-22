"""The phishing checks. Each check inspects the parsed email and returns findings:

    {"code": ..., "points": float, "text": plain-English reason, "evidence": what exactly was seen}

Same idea as the rest of CYBERMIND: fixed, explainable weights; the verdict is the sum (see phish_engine.py).
Only static facts from the message are used; nothing is fetched, opened or run.
"""
import re

from .email_parser import host_of

# brand -> domains that really belong to it (anything else imitating the brand is suspicious)
BRANDS = {
    "paypal": {"paypal.com", "paypal.me"},
    "microsoft": {"microsoft.com", "office.com", "outlook.com", "live.com", "microsoftonline.com", "office365.com"},
    "google": {"google.com", "gmail.com", "googlemail.com", "youtube.com"},
    "apple": {"apple.com", "icloud.com"},
    "amazon": {"amazon.com", "amazon.in", "amazon.co.uk", "amazonses.com"},
    "netflix": {"netflix.com"},
    "facebook": {"facebook.com", "facebookmail.com", "meta.com"},
    "instagram": {"instagram.com"},
    "linkedin": {"linkedin.com"},
    "dropbox": {"dropbox.com"},
    "docusign": {"docusign.com", "docusign.net"},
    "github": {"github.com"},
    "zoom": {"zoom.us"},
    "dhl": {"dhl.com"},
    "fedex": {"fedex.com"},
    "vaultapp": {"vaultapp.com"},          # the demo bank of this project
    "hdfc": {"hdfcbank.com", "hdfcbank.net"},
    "icici": {"icicibank.com"},
    "sbi": {"sbi.co.in", "onlinesbi.sbi"},
    "chase": {"chase.com"},
    "wellsfargo": {"wellsfargo.com"},
    "bankofamerica": {"bankofamerica.com"},
}
FREE_MAIL = {"gmail.com", "yahoo.com", "outlook.com", "hotmail.com", "aol.com", "proton.me", "protonmail.com", "icloud.com", "mail.com", "gmx.com", "yandex.com"}
SHORTENERS = {"bit.ly", "tinyurl.com", "goo.gl", "ow.ly", "is.gd", "buff.ly", "rebrand.ly", "cutt.ly", "shorturl.at", "t.ly", "tiny.cc"}
RISKY_TLDS = {"zip", "xyz", "top", "click", "work", "loan", "gq", "tk", "ml", "cf", "ga", "country", "support", "rest", "icu", "monster", "cyou"}
TWO_PART_SUFFIXES = {"co.uk", "org.uk", "ac.uk", "com.au", "co.in", "ac.in", "org.in", "gov.in", "co.jp", "com.br", "co.za", "com.sg", "com.cn"}
DANGEROUS_EXT = {"exe", "scr", "bat", "cmd", "com", "js", "jse", "vbs", "vbe", "wsf", "jar", "msi", "ps1", "lnk", "hta", "cpl", "reg", "dll"}
MACRO_EXT = {"docm", "xlsm", "pptm", "dotm", "xlam"}
PAGE_EXT = {"html", "htm", "svg", "shtml"}
ARCHIVE_EXT = {"zip", "rar", "7z", "iso", "img", "gz", "tar"}
DOC_EXT = {"pdf", "doc", "docx", "xls", "xlsx", "ppt", "pptx", "jpg", "jpeg", "png", "txt", "csv", "mp3", "mp4"}
LOGINISH = re.compile(r"(login|log-in|signin|sign-in|verify|account|secure|update|confirm|password|wallet)", re.I)
DOMAIN_IN_TEXT = re.compile(r"(?:https?://)?((?:[a-z0-9-]+\.)+[a-z]{2,})(?:/\S*)?", re.I)

URGENCY = ["urgent", "immediately", "within 24 hours", "within 48 hours", "act now", "final notice", "last warning", "will be suspended",
           "will be closed", "will be locked", "account suspended", "expires today", "expire in", "limited time", "right away", "as soon as possible"]
CREDENTIALS = ["verify your account", "verify your password", "confirm your password", "confirm your identity", "update your password",
               "reset your password", "login to your account", "sign in to", "enter your password", "validate your account",
               "security alert", "unusual sign-in", "unusual activity", "re-enter your", "social security", "one-time password", "otp"]
PAYMENT = ["gift card", "wire transfer", "bitcoin", "crypto", "western union", "pay immediately", "overdue invoice", "outstanding payment",
           "bank details", "change of bank", "do not tell anyone", "keep this confidential", "itunes card"]
THREATS = ["legal action", "your account will", "penalty", "unauthorized login", "compromised", "we detected", "suspicious activity", "violation"]

_LEET = str.maketrans({"0": "o", "1": "l", "3": "e", "4": "a", "5": "s", "7": "t", "$": "s", "@": "a"})


def reg_domain(host: str) -> str:
    """Registrable domain (naive public-suffix handling): mail.example.co.uk -> example.co.uk."""
    parts = [p for p in (host or "").lower().strip(".").split(".") if p]
    if len(parts) <= 2:
        return ".".join(parts)
    if ".".join(parts[-2:]) in TWO_PART_SUFFIXES:
        return ".".join(parts[-3:])
    return ".".join(parts[-2:])


def _normalise(label: str) -> str:
    return label.lower().translate(_LEET).replace("rn", "m").replace("vv", "w")


def _edit_distance(a: str, b: str, limit: int = 2) -> int:
    if abs(len(a) - len(b)) > limit:
        return limit + 1
    prev = list(range(len(b) + 1))
    for i, ca in enumerate(a, 1):
        cur = [i]
        for j, cb in enumerate(b, 1):
            cur.append(min(prev[j] + 1, cur[j - 1] + 1, prev[j - 1] + (ca != cb)))
        prev = cur
    return prev[-1]


def brand_imitation(host: str):
    """If `host` imitates a known brand it does not belong to, return (brand, how); else None."""
    rd = reg_domain(host)
    if not rd:
        return None
    for brand, legit in BRANDS.items():
        if rd in legit:
            return None
    sld = rd.split(".")[0]
    subdomains = (host or "").lower()[: -len(rd)].strip(".") if (host or "").lower().endswith(rd) else ""
    for brand in BRANDS:
        if brand in re.split(r"[.-]", subdomains) or any(brand == t for t in subdomains.split(".")):
            return brand, f"the brand name '{brand}' is used as a subdomain of {rd}"
    norm = _normalise(sld)
    for brand in BRANDS:
        if len(brand) < 4:
            continue
        if norm == brand and sld != brand:
            return brand, f"'{sld}' is a look-alike spelling of '{brand}'"
        if brand in [_normalise(t) for t in re.split(r"[-_]", sld)] and sld != brand:
            return brand, f"'{rd}' wraps the brand name '{brand}' in extra words"
        if brand in norm and len(norm) <= len(brand) + 12 and sld != brand:
            return brand, f"'{rd}' contains the brand name '{brand}'"
        if len(norm) >= 5 and _edit_distance(norm, brand) <= 1 and norm != brand:
            return brand, f"'{sld}' differs from '{brand}' by one character"
    return None


def _f(code, points, text, evidence=""):
    return {"code": code, "points": float(points), "text": text, "evidence": evidence}


# --------------------------------------------------------------------------------------------- the checks
def check_authentication(e):
    blob = (e["auth_results"] + " " + e["received_spf"]).lower()
    results = {}
    for mech in ("spf", "dkim", "dmarc"):
        m = re.search(rf"\b{mech}=(\w+)", blob) or (re.search(r"^(pass|fail|softfail|neutral|none)\b", e["received_spf"]) if mech == "spf" else None)
        if m:
            results[mech] = m.group(1)
    out, good = [], []
    failed = [f"{k.upper()}={v}" for k, v in results.items() if v in ("fail", "permerror", "temperror")]
    soft = [f"{k.upper()}={v}" for k, v in results.items() if v in ("softfail", "none", "neutral")]
    if failed:
        out.append(_f("auth_failed", 3.0, "The sender's authentication checks failed, so the 'From' address may be forged", ", ".join(failed)))
    elif soft:
        out.append(_f("auth_weak", 1.5, "The sender's authentication is weak or missing", ", ".join(soft)))
    elif not results:
        out.append(_f("auth_unknown", 0.5, "No authentication results were in the message, so the sender could not be verified"))
    if results and all(results.get(k) == "pass" for k in results) and len(results) >= 2:
        good.append("Sender authentication passed (" + ", ".join(f"{k.upper()}={v}" for k, v in results.items()) + ")")
    return out, good


def check_sender(e):
    out = []
    fd, rd = reg_domain(e["from_domain"]), reg_domain(e["reply_to_domain"])
    if rd and fd and rd != fd:
        pts = 2.0 + (1.0 if rd in FREE_MAIL and fd not in FREE_MAIL else 0.0)
        out.append(_f("reply_to_mismatch", pts, "Replies would go to a different domain than the sender's", f"From {e['from_domain']} but Reply-To {e['reply_to_domain']}"))
    rp = reg_domain(e["return_path_domain"])
    if rp and fd and rp != fd and "dkim=pass" not in e["auth_results"]:
        out.append(_f("return_path_mismatch", 0.5, "The bounce address belongs to a different domain than the sender", f"{e['return_path_domain']} vs {e['from_domain']}"))
    name = e["from_name"].lower()
    spoofed = None
    for brand, legit in BRANDS.items():
        if brand in re.sub(r"[^a-z0-9]", "", name) and fd not in legit:
            spoofed = brand
            break
    if spoofed:
        out.append(_f("display_name_spoof", 2.5, f"The sender's display name claims to be '{spoofed}' but the address is from another domain",
                      f"'{e['from_name']}' <{e['from_addr']}>"))
    elif re.search(r"(security|support|helpdesk|admin|billing|account|service|ceo|cfo|director|president|manager|finance|payroll|hr\b)", name) and fd in FREE_MAIL:
        out.append(_f("official_name_free_mail", 2.0, "An official-sounding sender name is using a free personal mail address", f"'{e['from_name']}' <{e['from_addr']}>"))
    imitation = brand_imitation(e["from_domain"]) if e["from_domain"] else None
    if imitation:
        out.append(_f("lookalike_sender_domain", 3.0, "The sender's domain imitates a well-known brand", imitation[1]))
    return out, []


def check_links(e):
    out, mism, ipl, short, puny, at, brandy, tld, plain, forms = [], [], [], [], [], [], [], [], [], []
    from_rd = reg_domain(e["from_domain"])
    for l in e["links"]:
        href, text = l["href"], l["text"]
        host = host_of(href)
        if not host:
            continue
        rd = reg_domain(host)
        if l.get("kind") == "form" and rd != from_rd:
            forms.append(f"{href[:80]}")
        m = DOMAIN_IN_TEXT.search(text or "")
        if m and l.get("kind") == "anchor" and reg_domain(m.group(1).lower()) != rd:
            mism.append(f"shows '{m.group(1)}' but goes to {host}")
        if re.fullmatch(r"\d{1,3}(?:\.\d{1,3}){3}", host):
            ipl.append(host)
        if rd in SHORTENERS:
            short.append(host)
        if "xn--" in host:
            puny.append(host)
        if "@" in href.split("//", 1)[-1].split("/", 1)[0]:
            at.append(href[:80])
        imitation = brand_imitation(host)
        if imitation:
            brandy.append(f"{host}: {imitation[1]}")
        if rd.rsplit(".", 1)[-1] in RISKY_TLDS:
            tld.append(host)
        if href.lower().startswith("http://") and LOGINISH.search(href):
            plain.append(href[:80])

    def add(code, pts, text, items):
        if items:
            out.append(_f(code, pts, text, "; ".join(dict.fromkeys(items))[:300]))
    add("link_text_mismatch", 3.0, "A link's visible address is not where it really goes", mism)
    add("lookalike_link_domain", 3.0, "A link points to a domain imitating a well-known brand", brandy)
    add("ip_address_link", 3.0, "A link goes to a raw IP address instead of a website name", ipl)
    add("punycode_link", 2.5, "A link uses an encoded (punycode) domain, a trick for look-alike characters", puny)
    add("userinfo_in_link", 2.5, "A link hides its real destination behind an '@' sign", at)
    add("form_to_other_domain", 2.0, "A form in the email would send what you type to another domain", forms)
    add("url_shortener", 1.5, "A link is hidden behind a URL shortener", short)
    add("risky_tld", 1.0, "A link uses a domain ending often abused for scams", tld)
    add("insecure_login_link", 1.0, "A login-style link does not use HTTPS", plain)
    return out, []


def check_attachments(e):
    out, total = [], 0.0
    for a in e["attachments"]:
        name = a["filename"].lower()
        ext = name.rsplit(".", 1)[-1] if "." in name else ""
        parts = name.split(".")
        pts, why = 0.0, ""
        if len(parts) >= 3 and parts[-1] in DANGEROUS_EXT and parts[-2] in DOC_EXT:
            pts, why = 4.0, "A program disguised as a document (double extension)"
        elif ext in DANGEROUS_EXT:
            pts, why = 4.0, "An executable or script file attached"
        elif ext in MACRO_EXT:
            pts, why = 2.5, "An Office document that can contain macros"
        elif ext in PAGE_EXT:
            pts, why = 2.5, "An HTML/SVG file attached (often a fake login page)"
        elif ext in ARCHIVE_EXT:
            pts, why = 1.0, "An archive that can hide a malicious file"
        if pts:
            pts = max(0.0, min(pts, 6.0 - total))          # attachments together count for at most 6 points
            total += pts
            out.append(_f("dangerous_attachment" if pts >= 2.5 else "risky_attachment", pts, why, f"{a['filename']} (sha256 {a['sha256'][:12]}...)"))
    return out, []


def check_language(e):
    text = (e["subject"] + " " + e["body_text"]).lower()
    out, found = [], {}
    for name, words in (("urgency", URGENCY), ("credentials", CREDENTIALS), ("payment", PAYMENT), ("threats", THREATS)):
        hits = [w for w in words if w in text]
        if hits:
            found[name] = hits[:3]
    weights = {"urgency": (1.0, "Pressure to act quickly"), "credentials": (1.5, "Asks you to verify or enter account details"),
               "payment": (2.0, "Mentions risky payment methods or payment pressure"), "threats": (1.0, "Threatening or alarming wording")}
    total = 0.0
    for name, hits in found.items():
        pts = weights[name][0]
        if total + pts > 4.0:
            pts = max(0.0, 4.0 - total)
        total += pts
        if pts:
            out.append(_f(f"language_{name}", pts, weights[name][1], "found: " + ", ".join(f"'{h}'" for h in hits)))
    return out, []


CHECKS = [check_authentication, check_sender, check_links, check_attachments, check_language]
