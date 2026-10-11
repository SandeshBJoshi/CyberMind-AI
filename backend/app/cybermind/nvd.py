"""CVE lookups against the NIST National Vulnerability Database (NVD API 2.0, free, no key needed for light use).

Given CVE ids found in the report text, returns severity, score, description and the CWE (the formal definition of the
weakness class) so the analyst sees what *kind* of flaw it is. Failures never break the analysis: a CVE simply shows as
unverified. Results are cached for a few hours because the keyless API allows only about 5 requests per 30 seconds.
"""
import json
import time
import urllib.error
import urllib.parse
import urllib.request

from .report import CWE_NAMES, url_for

NVD_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
MAX_IDS = 5
TTL = 6 * 3600
_cache: dict[str, tuple[float, dict]] = {}


def _fetch(cve_id: str) -> dict:
    req = urllib.request.Request(NVD_URL + "?" + urllib.parse.urlencode({"cveId": cve_id}), headers={"User-Agent": "CYBERMIND-AI/1.0"})
    with urllib.request.urlopen(req, timeout=10) as r:
        return json.loads(r.read())


def parse(cve_id: str, data: dict) -> dict:
    vulns = data.get("vulnerabilities") or []
    if not vulns:
        return {"id": cve_id, "status": "not_found", "url": url_for("cve", cve_id)}
    cve = vulns[0].get("cve", {})
    desc = next((d["value"] for d in cve.get("descriptions", []) if d.get("lang") == "en"), "")
    metric = None
    for key in ("cvssMetricV40", "cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
        if cve.get("metrics", {}).get(key):
            metric = cve["metrics"][key][0]
            break
    cvss = (metric or {}).get("cvssData", {})
    cwes = []
    for w in cve.get("weaknesses", []):
        for d in w.get("description", []):
            v = d.get("value", "")
            if v.startswith("CWE-") and v not in [c["id"] for c in cwes]:
                cwes.append({"id": v, "name": CWE_NAMES.get(v, ""), "url": url_for("cwe", v)})
    return {"id": cve_id, "status": "verified", "description": " ".join(desc.split())[:500], "published": (cve.get("published") or "")[:10],
            "cvss": cvss.get("baseScore"), "severity": cvss.get("baseSeverity") or (metric or {}).get("baseSeverity", ""),
            "cwes": cwes, "url": url_for("cve", cve_id)}


def lookup(cve_ids: list[str], fetch=_fetch) -> list[dict]:
    out, now = [], time.time()
    for i, cve_id in enumerate(cve_ids[:MAX_IDS]):
        hit = _cache.get(cve_id)
        if hit and now - hit[0] < TTL:
            out.append(hit[1])
            continue
        try:
            rec = parse(cve_id, fetch(cve_id))
            _cache[cve_id] = (now, rec)
        except urllib.error.HTTPError as exc:
            rec = {"id": cve_id, "status": "unavailable", "url": url_for("cve", cve_id), "note": f"NVD answered HTTP {exc.code}"}
        except (urllib.error.URLError, TimeoutError, OSError, ValueError):
            rec = {"id": cve_id, "status": "unavailable", "url": url_for("cve", cve_id), "note": "NVD could not be reached"}
        out.append(rec)
        if i < len(cve_ids) - 1 and rec["status"] != "unavailable":
            time.sleep(0.7)            # stay under the keyless rate limit
    for rec in out:
        rec.setdefault("cwes", [])
        rec.setdefault("description", "")
        rec.setdefault("published", "")
        rec.setdefault("cvss", None)
        rec.setdefault("severity", "")
    return out
