"""Classify an IP address. Works with no extra files; adds ASN/organisation hints when a GeoLite2-ASN
database is configured (GEOIP_ASN_DB) and the optional `geoip2` package is installed."""
import ipaddress

from .config import settings

_DC_WORDS = ("amazon", "google", "microsoft", "digitalocean", "ovh", "hetzner", "linode", "vultr", "choopa",
             "leaseweb", "contabo", "hosting", "cloud", "datacenter", "data center", "server", "colo")
_reader = None


def _asn_reader():
    global _reader
    if _reader is None and settings.geoip_asn_db:
        try:
            import geoip2.database  # type: ignore
            _reader = geoip2.database.Reader(settings.geoip_asn_db)
        except Exception:
            _reader = False
    return _reader or None


def network_type(ip: str | None) -> str | None:
    if not ip:
        return None
    try:
        a = ipaddress.ip_address(ip)
    except ValueError:
        return None
    if a.is_loopback:
        return "loopback"
    if a.is_private or a.is_link_local:
        return "private"
    reader = _asn_reader()
    if reader:
        try:
            org = (reader.asn(ip).autonomous_system_organization or "").lower()
            return "datacenter" if any(w in org for w in _DC_WORDS) else "residential"
        except Exception:
            pass
    return "public"
