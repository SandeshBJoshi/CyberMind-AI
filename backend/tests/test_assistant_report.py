"""Analyst Assistant report structure: validation, reference labelling, Markdown layout, and the NVD lookup (with a fake fetcher)."""
import unittest
import urllib.error
from unittest import mock

from app.cybermind import nvd, report as rpt

CONTEXT = ("The actor exploited CVE-2021-44228 (Log4Shell) on an internet-facing server (T1190), then used cve-2021-44228 again. "
           "Phishing mail carried T1566.002 links. See CVE-2099-0001 and CVE-2021-4.")


def model_answer(**over):
    base = {"title": "Log4Shell intrusion", "threat_level": "high", "summary": "The actor exploited a public server.",
            "attacks": [{"name": "Exploit public-facing application", "description": "Used a JNDI string.", "evidence": "exploited CVE-2021-44228",
                         "attack_ids": ["T1190", "t1566.002", "T99", "T1078"], "cwe_ids": ["CWE-917", "CWE-abc"], "capec_ids": ["CAPEC-248"]}],
            "affected_assets": ["web server"], "actions": [{"action": "Patch Log4j", "category": "mitigation", "priority": "high"}, "Review logs"],
            "gaps": "", "cves": ["CVE-2000-9999"]}
    base.update(over)
    return base


class ValidateTests(unittest.TestCase):
    def test_cves_come_from_the_source_text_only_and_are_deduplicated(self):
        self.assertEqual(rpt.extract_cves(CONTEXT), ["CVE-2021-44228", "CVE-2099-0001"])      # malformed CVE-2021-4 ignored, case folded

    def test_model_supplied_cves_are_never_part_of_the_report(self):
        out = rpt.validate_report(model_answer(), CONTEXT)
        self.assertNotIn("cves", out)

    def test_reference_ids_are_checked_and_labelled_by_where_they_came_from(self):
        out = rpt.validate_report(model_answer(), CONTEXT)
        ids = {t["id"]: t for t in out["attacks"][0]["attack_ids"]}
        self.assertEqual(set(ids), {"T1190", "T1566.002", "T1078"})                         # T99 is malformed, so it is dropped
        self.assertEqual(ids["T1190"]["source"], "report")                                  # printed in the source
        self.assertEqual(ids["T1078"]["source"], "model")                                   # only the model's suggestion
        self.assertEqual(ids["T1190"]["name"], "Exploit Public-Facing Application")
        self.assertEqual([t["id"] for t in out["attacks"][0]["cwe_ids"]], ["CWE-917"])
        self.assertTrue(ids["T1190"]["url"].startswith("https://attack.mitre.org/techniques/T1190"))

    def test_levels_categories_and_priorities_are_normalised(self):
        out = rpt.validate_report(model_answer(threat_level="apocalyptic"), CONTEXT)
        self.assertEqual(out["threat_level"], "UNKNOWN")
        self.assertEqual(out["actions"][0]["category"], "MITIGATION")
        self.assertEqual(out["actions"][1], {"action": "Review logs", "category": "MITIGATION", "priority": "MEDIUM", "source": "best_practice"})

    def test_only_actions_the_report_recommends_are_fact_checked_against_it(self):
        out = rpt.validate_report(model_answer(actions=[{"action": "Patch Log4j", "source": "report"}, {"action": "Add a WAF", "source": "best_practice"}, {"action": "Unlabelled"}]), CONTEXT)
        claims = rpt.claims_text(out)
        self.assertIn("Patch Log4j", claims)
        self.assertNotIn("Add a WAF", claims)
        self.assertNotIn("Unlabelled", claims)
        md = rpt.build_markdown(out, [], [])
        self.assertIn("Add a WAF _(best practice, not in the report)_", md)

    def test_empty_or_wrong_shaped_answers_are_rejected(self):
        with self.assertRaises(ValueError):
            rpt.validate_report({"summary": "", "attacks": [], "actions": []}, CONTEXT)
        with self.assertRaises(ValueError):
            rpt.validate_report(["not", "an", "object"], CONTEXT)

    def test_oversized_text_is_truncated(self):
        out = rpt.validate_report(model_answer(summary="x" * 5000), CONTEXT)
        self.assertLessEqual(len(out["summary"]), 1600)


class MarkdownTests(unittest.TestCase):
    def test_the_five_requested_sections_are_present_in_order(self):
        report = rpt.validate_report(model_answer(), CONTEXT)
        cves = [{"id": "CVE-2021-44228", "status": "verified", "cvss": 10.0, "severity": "CRITICAL", "description": "Log4j JNDI RCE.",
                 "cwes": [{"id": "CWE-502", "name": "Deserialization of Untrusted Data", "url": "u"}], "published": "2021-12-10", "url": "https://nvd.nist.gov/x"},
                {"id": "CVE-2099-0001", "status": "not_found", "cwes": [], "url": "u"}]
        trace = [{"agent": "Planner", "role": "Decides", "detail": "d", "ms": 3, "status": "ok"}]
        md = rpt.build_markdown(report, cves, trace, {"groundedness_score": 5, "reasoning": "ok"}, "gpt")
        heads = [md.index(h) for h in ("## 1. Summary of the report", "## 2. Attacks performed", "## 3. Suggested actions and techniques",
                                       "## 4. CVEs and what defines them (NVD)", "## 5. Agents involved")]
        self.assertEqual(heads, sorted(heads))
        self.assertIn("[model-suggested]", md)                      # the unverified tag is flagged
        self.assertIn("CWE-502 Deserialization of Untrusted Data", md)
        self.assertIn("Not found in NVD", md)
        self.assertIn("| 1 | Planner |", md)
        self.assertIn("groundedness 5/5", md)


def _nvd_payload():
    return {"vulnerabilities": [{"cve": {"id": "CVE-2021-44228", "published": "2021-12-10T10:15:09.143", "descriptions": [{"lang": "en", "value": "Apache Log4j2 JNDI features do not protect against attacker controlled LDAP."}],
            "metrics": {"cvssMetricV31": [{"cvssData": {"baseScore": 10.0, "baseSeverity": "CRITICAL"}}]},
            "weaknesses": [{"description": [{"lang": "en", "value": "CWE-502"}, {"lang": "en", "value": "CWE-917"}, {"lang": "en", "value": "NVD-CWE-Other"}]}]}}]}


class NvdTests(unittest.TestCase):
    def setUp(self):
        nvd._cache.clear()

    def test_parse_extracts_score_severity_and_weaknesses(self):
        r = nvd.parse("CVE-2021-44228", _nvd_payload())
        self.assertEqual((r["status"], r["cvss"], r["severity"], r["published"]), ("verified", 10.0, "CRITICAL", "2021-12-10"))
        self.assertEqual([c["id"] for c in r["cwes"]], ["CWE-502", "CWE-917"])          # the NVD-specific placeholder is skipped
        self.assertEqual(r["cwes"][0]["name"], "Deserialization of Untrusted Data")

    def test_unknown_id_and_failures_are_reported_honestly_not_raised(self):
        self.assertEqual(nvd.parse("CVE-2099-0001", {"vulnerabilities": []})["status"], "not_found")

        def boom_http(_):
            raise urllib.error.HTTPError("u", 403, "rate limited", {}, None)

        def boom_net(_):
            raise urllib.error.URLError("offline")
        self.assertIn("403", nvd.lookup(["CVE-2021-44228"], fetch=boom_http)[0]["note"])
        nvd._cache.clear()
        r = nvd.lookup(["CVE-2021-44228"], fetch=boom_net)[0]
        self.assertEqual(r["status"], "unavailable")
        self.assertEqual(r["cwes"], [])

    def test_results_are_cached_and_the_number_of_lookups_is_capped(self):
        calls = []

        def fetch(i):
            calls.append(i)
            return _nvd_payload()
        with mock.patch.object(nvd.time, "sleep"):
            nvd.lookup(["CVE-2021-44228"], fetch=fetch)
            nvd.lookup(["CVE-2021-44228"], fetch=fetch)
            self.assertEqual(len(calls), 1)                          # second call served from the cache
            nvd._cache.clear()
            calls.clear()
            nvd.lookup([f"CVE-2020-{1000 + i}" for i in range(12)], fetch=fetch)
            self.assertEqual(len(calls), nvd.MAX_IDS)


if __name__ == "__main__":
    unittest.main()
