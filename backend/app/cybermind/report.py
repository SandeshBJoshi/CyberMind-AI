"""Structure of the Analyst Assistant's report: validation of what the model returns, reference tagging, and the Markdown export.

The model writes the analysis (summary, attacks, actions). Everything that looks like an official reference is checked by code:
  * CVE ids are taken from the report text itself (never from the model) and then looked up in NVD (see nvd.py);
  * ATT&CK / CWE / CAPEC ids the model proposes are kept only if well-formed and are labelled either "cited in the report"
    (the id really appears in the source text) or "suggested by the model" (unverified), so nothing invented looks official.
"""
import re

CVE_RE = re.compile(r"\bCVE-\d{4}-\d{4,7}\b", re.I)
ATTACK_RE = re.compile(r"^T\d{4}(?:\.\d{3})?$")
CWE_RE = re.compile(r"^CWE-\d{1,5}$")
CAPEC_RE = re.compile(r"^CAPEC-\d{1,4}$")

ATTACK_NAMES = {
    "T1190": "Exploit Public-Facing Application", "T1566": "Phishing", "T1566.001": "Spearphishing Attachment", "T1566.002": "Spearphishing Link",
    "T1078": "Valid Accounts", "T1110": "Brute Force", "T1059": "Command and Scripting Interpreter", "T1003": "OS Credential Dumping",
    "T1021": "Remote Services", "T1486": "Data Encrypted for Impact", "T1490": "Inhibit System Recovery", "T1071": "Application Layer Protocol",
    "T1105": "Ingress Tool Transfer", "T1204": "User Execution", "T1027": "Obfuscated Files or Information", "T1055": "Process Injection",
    "T1547": "Boot or Logon Autostart Execution", "T1053": "Scheduled Task/Job", "T1082": "System Information Discovery",
    "T1083": "File and Directory Discovery", "T1041": "Exfiltration Over C2 Channel", "T1133": "External Remote Services",
    "T1499": "Endpoint Denial of Service", "T1090": "Proxy", "T1598": "Phishing for Information", "T1656": "Impersonation",
    "T1068": "Exploitation for Privilege Escalation", "T1203": "Exploitation for Client Execution", "T1189": "Drive-by Compromise",
    "T1195": "Supply Chain Compromise", "T1505.003": "Web Shell", "T1136": "Create Account", "T1018": "Remote System Discovery",
}
CWE_NAMES = {
    "CWE-20": "Improper Input Validation", "CWE-22": "Path Traversal", "CWE-78": "OS Command Injection", "CWE-79": "Cross-site Scripting",
    "CWE-89": "SQL Injection", "CWE-94": "Code Injection", "CWE-125": "Out-of-bounds Read", "CWE-200": "Exposure of Sensitive Information",
    "CWE-287": "Improper Authentication", "CWE-306": "Missing Authentication for Critical Function", "CWE-352": "Cross-Site Request Forgery",
    "CWE-400": "Uncontrolled Resource Consumption", "CWE-416": "Use After Free", "CWE-434": "Unrestricted Upload of Dangerous File Type",
    "CWE-476": "NULL Pointer Dereference", "CWE-502": "Deserialization of Untrusted Data", "CWE-522": "Insufficiently Protected Credentials",
    "CWE-611": "XML External Entity Reference", "CWE-787": "Out-of-bounds Write", "CWE-798": "Use of Hard-coded Credentials",
    "CWE-862": "Missing Authorization", "CWE-917": "Expression Language Injection", "CWE-918": "Server-Side Request Forgery",
    "CWE-1321": "Prototype Pollution", "CWE-119": "Memory Buffer Bounds Violation", "CWE-269": "Improper Privilege Management",
}
LEVELS = ("CRITICAL", "HIGH", "MEDIUM", "LOW", "UNKNOWN")
CATEGORIES = ("MITIGATION", "DETECTION", "RESPONSE", "HARDENING")
PRIORITIES = ("HIGH", "MEDIUM", "LOW")


def extract_cves(*texts: str) -> list[str]:
    seen: list[str] = []
    for t in texts:
        for m in CVE_RE.findall(t or ""):
            m = m.upper()
            if m not in seen:
                seen.append(m)
    return seen


def url_for(kind: str, ident: str) -> str:
    ident = ident.upper()
    if kind == "attack":
        return "https://attack.mitre.org/techniques/" + ident.replace(".", "/") + "/"
    if kind == "cwe":
        return f"https://cwe.mitre.org/data/definitions/{ident.split('-')[1]}.html"
    if kind == "capec":
        return f"https://capec.mitre.org/data/definitions/{ident.split('-')[1]}.html"
    return f"https://nvd.nist.gov/vuln/detail/{ident}"


def _s(value, limit) -> str:
    return re.sub(r"\s+", " ", str(value or "")).strip()[:limit]


def _tags(values, regex, kind, names, context_upper) -> list[dict]:
    out, seen = [], set()
    for v in values if isinstance(values, list) else []:
        ident = str(v).strip().upper().replace(" ", "")
        if not regex.match(ident) or ident in seen:
            continue
        seen.add(ident)
        out.append({"id": ident, "name": names.get(ident, ""), "url": url_for(kind, ident),
                    "source": "report" if ident in context_upper else "model"})
    return out[:6]


def validate_report(raw: dict, context_text: str) -> dict:
    """Clamp and normalise the model's JSON. Raises ValueError if it has no usable content."""
    if not isinstance(raw, dict):
        raise ValueError("not an object")
    ctx = (context_text or "").upper()
    summary = _s(raw.get("summary"), 1600)
    attacks = []
    for a in (raw.get("attacks") if isinstance(raw.get("attacks"), list) else [])[:6]:
        if not isinstance(a, dict) or not _s(a.get("name"), 160):
            continue
        attacks.append({"name": _s(a.get("name"), 160), "description": _s(a.get("description"), 700), "evidence": _s(a.get("evidence"), 300),
                        "attack_ids": _tags(a.get("attack_ids"), ATTACK_RE, "attack", ATTACK_NAMES, ctx),
                        "cwe_ids": _tags(a.get("cwe_ids"), CWE_RE, "cwe", CWE_NAMES, ctx),
                        "capec_ids": _tags(a.get("capec_ids"), CAPEC_RE, "capec", {}, ctx)})
    actions = []
    for a in (raw.get("actions") if isinstance(raw.get("actions"), list) else [])[:8]:
        if isinstance(a, str):
            a = {"action": a}
        if not isinstance(a, dict) or not _s(a.get("action"), 400):
            continue
        cat, pri = _s(a.get("category"), 20).upper(), _s(a.get("priority"), 10).upper()
        src = "report" if _s(a.get("source"), 20).lower() == "report" else "best_practice"       # unlabelled means not claimed to be from the report
        actions.append({"action": _s(a.get("action"), 400), "category": cat if cat in CATEGORIES else "MITIGATION", "priority": pri if pri in PRIORITIES else "MEDIUM", "source": src})
    if not summary and not attacks and not actions:
        raise ValueError("empty report")
    level = _s(raw.get("threat_level"), 12).upper()
    return {"title": _s(raw.get("title"), 160), "threat_level": level if level in LEVELS else "UNKNOWN", "summary": summary, "attacks": attacks,
            "affected_assets": [_s(x, 120) for x in (raw.get("affected_assets") if isinstance(raw.get("affected_assets"), list) else []) if _s(x, 120)][:8],
            "actions": actions, "gaps": _s(raw.get("gaps"), 500)}


def claims_text(report: dict) -> str:
    """Only what should be traceable to the source documents (summary, attacks, actions): this is what the fact-checker judges.
    The threat level is the analyst's own rating, and CVE details, reference tags and agent steps come from other sources."""
    L = ["SUMMARY: " + report["summary"], "ATTACKS:"]
    L += [f"- {a['name']}: {a['description']} (evidence: {a['evidence']})" for a in report["attacks"]]
    L += ["ACTIONS THE REPORT RECOMMENDS:"] + [f"- {a['action']}" for a in report["actions"] if a["source"] == "report"]
    return "\n".join(L)


def _ids(tags) -> str:
    return ", ".join(f"{t['id']}{' (' + t['name'] + ')' if t['name'] else ''}{'' if t['source'] == 'report' else ' [model-suggested]'}" for t in tags)


def build_markdown(report: dict, cves: list[dict], trace: list[dict], validation: dict | None = None, model: str = "") -> str:
    L = [f"# {report['title'] or 'Threat intelligence briefing'}", "", f"**Threat level:** {report['threat_level']}" +
         (f"  ·  **Affected:** {', '.join(report['affected_assets'])}" if report["affected_assets"] else ""), "",
         "## 1. Summary of the report", "", report["summary"] or "_The report did not provide enough to summarise._", "", "## 2. Attacks performed", ""]
    if not report["attacks"]:
        L.append("_No specific attack was described in the retrieved material._")
    for i, a in enumerate(report["attacks"], 1):
        L += [f"### 2.{i} {a['name']}", "", a["description"]]
        if a["evidence"]:
            L += ["", f"> {a['evidence']}"]
        refs = [("MITRE ATT&CK", a["attack_ids"]), ("CWE", a["cwe_ids"]), ("CAPEC", a["capec_ids"])]
        L += [""] + [f"- **{k}:** {_ids(v)}" for k, v in refs if v] + [""]
    L += ["## 3. Suggested actions and techniques", ""]
    for cat in CATEGORIES:
        rows = [a for a in report["actions"] if a["category"] == cat]
        if rows:
            L += [f"**{cat.title()}**", ""] + [f"- [{a['priority']}] {a['action']}" + ("" if a["source"] == "report" else " _(best practice, not in the report)_") for a in rows] + [""]
    if not report["actions"]:
        L += ["_No actions were suggested in the retrieved material._", ""]
    L += ["## 4. CVEs and what defines them (NVD)", ""]
    if not cves:
        L += ["_No CVE identifiers appear in the retrieved material._", ""]
    for c in cves:
        head = f"**{c['id']}**"
        if c["status"] == "verified":
            head += f" · CVSS {c['cvss']} {c['severity']}" if c.get("cvss") is not None else ""
            L += [head, "", f"- {c['description']}", "- **Weakness (CWE):** " + (", ".join(f"{w['id']} {w['name']}".strip() for w in c["cwes"]) or "not classified"),
                  f"- Published {c['published']} · {c['url']}", ""]
        else:
            L += [head, "", f"- {'Not found in NVD' if c['status'] == 'not_found' else 'NVD could not be reached'}: details unverified.", ""]
    L += ["## 5. Agents involved", "", "| # | Agent | Role | What it did | Time |", "|---|---|---|---|---|"]
    L += [f"| {i} | {t['agent']} | {t['role']} | {t['detail']} | {t['ms']} ms |" for i, t in enumerate(trace, 1)]
    if validation:
        L += ["", f"**Fact-check:** groundedness {validation.get('groundedness_score', '?')}/5" +
              (" · hallucination flagged" if validation.get("hallucination_detected") else "") + (f" · {validation['reasoning']}" if validation.get("reasoning") else "")]
    L += ["", "---", f"_Generated by CYBERMIND AI Analyst Assistant{' using ' + model if model else ''}. CVE details come from the NVD; ATT&CK/CWE/CAPEC tags marked [model-suggested] are unverified._", ""]
    return "\n".join(L)
