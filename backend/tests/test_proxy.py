"""Trusted-proxy handling: exact addresses and CIDR ranges, and a forged header from an untrusted peer."""
import unittest
from types import SimpleNamespace

from app import security
from app.config import settings


def req(peer, **headers):
    return SimpleNamespace(client=SimpleNamespace(host=peer), headers={k.replace("_", "-"): v for k, v in headers.items()})


class ProxyTests(unittest.TestCase):
    def setUp(self):
        self._old = (settings.trusted_proxies, settings.allow_client_ip_header)
        settings.trusted_proxies, settings.allow_client_ip_header = "10.0.0.0/8,172.16.5.4", False

    def tearDown(self):
        settings.trusted_proxies, settings.allow_client_ip_header = self._old

    def test_cidr_and_exact_proxies_are_trusted(self):
        self.assertTrue(security._is_trusted_proxy("10.9.8.7", settings.trusted_proxy_set))
        self.assertTrue(security._is_trusted_proxy("172.16.5.4", settings.trusted_proxy_set))
        self.assertFalse(security._is_trusted_proxy("8.8.8.8", settings.trusted_proxy_set))

    def test_real_client_ip_comes_from_a_trusted_proxy_header(self):
        self.assertEqual(security.resolve_client_ip(req("10.1.2.3", x_forwarded_for="203.0.113.9, 10.1.2.3")), "203.0.113.9")

    def test_forged_header_from_an_untrusted_peer_is_ignored(self):
        self.assertEqual(security.resolve_client_ip(req("198.51.100.20", x_forwarded_for="1.2.3.4")), "198.51.100.20")


if __name__ == "__main__":
    unittest.main()
