from __future__ import annotations

from ipaddress import ip_network

from django.utils.translation import gettext_lazy as _


class DeviceCategory:
    DESKTOP = "desktop"
    MOBILE = "mobile"
    TABLET = "tablet"
    CRAWLER = "crawler"
    UNKNOWN = "unknown"


DEVICE_CATEGORY_LABELS = {
    DeviceCategory.DESKTOP: _("Desktop"),
    DeviceCategory.MOBILE: _("Mobile"),
    DeviceCategory.TABLET: _("Tablet"),
    DeviceCategory.CRAWLER: _("Crawler"),
    DeviceCategory.UNKNOWN: _("Unknown"),
}

# Prefix length kept when masking client IP addresses. The host part is zeroed,
# retaining only a coarse, network level geographic clue.
_IPV4_MASK_PREFIX = 24
_IPV6_MASK_PREFIX = 48


def mask_client_ip(ip: str | None) -> str | None:
    if not ip:
        return None
    try:
        network = ip_network(ip, strict=False)
    except ValueError:
        # Never persist a value that cannot be parsed as a valid address.
        return None
    prefix = _IPV4_MASK_PREFIX if network.version == 4 else _IPV6_MASK_PREFIX
    return str(network.supernet(new_prefix=prefix).network_address)


def device_category(user_agent: str | None) -> str:
    ua = (user_agent or "").lower()
    if not ua:
        return DeviceCategory.UNKNOWN
    if _contains_any(
        ua,
        (
            "bot",
            "crawler",
            "spider",
            "slurp",
            "facebookexternalhit",
            "mediapartners-google",
        ),
    ):
        return DeviceCategory.CRAWLER
    if _contains_any(
        ua,
        (
            "ipad",
            "tablet",
            "kindle",
            "silk",
            "playbook",
            "nintendo switch",
        ),
    ) or ("android" in ua and "mobile" not in ua):
        return DeviceCategory.TABLET
    if _contains_any(
        ua,
        (
            "iphone",
            "mobile",
            "android",
            "windows phone",
            "blackberry",
            "opera mini",
        ),
    ):
        return DeviceCategory.MOBILE
    if _contains_any(
        ua,
        (
            "windows nt",
            "macintosh",
            "mac os x",
            "x11",
            "linux",
            "cros",
            "crbook",
        ),
    ):
        return DeviceCategory.DESKTOP
    return DeviceCategory.UNKNOWN


def _contains_any(value: str, needles: tuple[str, ...]) -> bool:
    return any(needle in value for needle in needles)
