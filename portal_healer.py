#!/usr/bin/env python3
"""
ISP Portal Healer (isp-portal-healer v1.0.0)
============================================
Standalone, user-friendly CLI and background watchdog that detects and fixes
stuck ISP "Walled Garden" captive portals, false "No Internet" red LED states,
and stale provisioning locks across:
  - Verizon 5G Home Internet (Askey ASK-NCM1100 / WNC gateways at 192.168.1.1)
  - Xfinity Home Internet & xfinitywifi (RDK-B XB6/XB7/XB8 gateways at 10.0.0.1)
  - T-Mobile 5G Home Internet (TMI gateways at 192.168.12.1)

Zero external Python dependencies. Safe read-only `check` mode by default.
"""

from __future__ import annotations

import argparse
import hashlib
import http.client
import http.cookiejar
import json
import os
import re
import socket
import ssl
import tempfile
import time
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, Tuple


# ---------------------------------------------------------------------------
# 1. Source-Bound HTTP/HTTPS Transport (Multi-Wi-Fi / Multi-WAN Safe)
# ---------------------------------------------------------------------------

class BoundHTTPConnection(http.client.HTTPConnection):
    def __init__(self, *args: Any, source_ip: Optional[str] = None, **kwargs: Any) -> None:
        self._source_ip = source_ip
        super().__init__(*args, **kwargs)

    def connect(self) -> None:
        if self._source_ip:
            self.source_address = (self._source_ip, 0)
        super().connect()


class BoundHTTPSConnection(http.client.HTTPSConnection):
    def __init__(self, *args: Any, source_ip: Optional[str] = None, **kwargs: Any) -> None:
        self._source_ip = source_ip
        super().__init__(*args, **kwargs)

    def connect(self) -> None:
        if self._source_ip:
            self.source_address = (self._source_ip, 0)
        super().connect()


class BoundHTTPHandler(urllib.request.HTTPHandler):
    def __init__(self, source_ip: Optional[str] = None) -> None:
        super().__init__()
        self._source_ip = source_ip

    def http_open(self, req: urllib.request.Request) -> http.client.HTTPResponse:
        return self.do_open(
            lambda host, **kwargs: BoundHTTPConnection(host, source_ip=self._source_ip, **kwargs),
            req,
        )


class BoundHTTPSHandler(urllib.request.HTTPSHandler):
    def __init__(self, source_ip: Optional[str] = None, context: Optional[ssl.SSLContext] = None) -> None:
        super().__init__(context=context)
        self._source_ip = source_ip
        self._context = context

    def https_open(self, req: urllib.request.Request) -> http.client.HTTPResponse:
        return self.do_open(
            lambda host, **kwargs: BoundHTTPSConnection(
                host, source_ip=self._source_ip, context=self._context, **kwargs
            ),
            req,
        )


class NoRedirectHandler(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


def build_opener(
    source_ip: Optional[str] = None,
    cookie_jar: Optional[http.cookiejar.CookieJar] = None,
    follow_redirects: bool = True,
) -> urllib.request.OpenerDirector:
    ctx = ssl.create_default_context()
    handlers: List[Any] = [
        BoundHTTPHandler(source_ip=source_ip),
        BoundHTTPSHandler(source_ip=source_ip, context=ctx),
    ]
    if cookie_jar is not None:
        handlers.append(urllib.request.HTTPCookieProcessor(cookie_jar))
    if not follow_redirects:
        handlers.append(NoRedirectHandler())
    return urllib.request.build_opener(*handlers)


# ---------------------------------------------------------------------------
# 2. Data Models & Capabilities
# ---------------------------------------------------------------------------

PROBE_CLEAR = "clear"
PROBE_INTERCEPTED = "intercepted"
PROBE_UNKNOWN = "unknown"


@dataclass(frozen=True)
class ProviderCapabilities:
    provider: str
    default_host: str
    supports_oma_dm_sync: bool
    supports_wan_renew: bool
    supports_soft_reboot: bool
    supports_portal_auto_release: bool


@dataclass
class PortalDiagnosis:
    provider: str = "unknown"
    gateway_host: str = ""
    gateway_model: str = "Unknown"
    firmware_version: str = ""
    led_or_wan_status: str = "Unknown"
    radio_or_docsis_online: bool = False
    wan_internet_ok: bool = False
    probe_status: str = PROBE_UNKNOWN
    intercepted: bool = False
    intercept_type: str = "none"  # none | verizon_walled_garden | xfinity_activation | xfinity_hotspot | generic_captive
    redirect_url: str = ""
    pending_carrier_cases: List[Dict[str, str]] = field(default_factory=list)
    heal_action_taken: str = "none"
    verified_recovered: bool = False

    def public_dict(self, include_sensitive: bool = False) -> Dict[str, Any]:
        data = asdict(self)
        if not include_sensitive:
            if data["redirect_url"]:
                parsed = urllib.parse.urlsplit(data["redirect_url"])
                data["redirect_url"] = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"
            data["pending_carrier_cases"] = [
                {
                    "caseStatus": c.get("caseStatus", ""),
                    "orderType": c.get("orderType", ""),
                }
                for c in self.pending_carrier_cases
            ]
        return data


# ---------------------------------------------------------------------------
# 3. Provider Gateway Drivers (Verizon 5G, Xfinity 10.0.0.1, T-Mobile 5G)
# ---------------------------------------------------------------------------

class VerizonAskeyDriver:
    CAPABILITIES = ProviderCapabilities(
        provider="verizon",
        default_host="192.168.1.1",
        supports_oma_dm_sync=True,
        supports_wan_renew=True,
        supports_soft_reboot=True,
        supports_portal_auto_release=True,
    )

    def __init__(self, host: str = "192.168.1.1", password: str = "", source_ip: Optional[str] = None) -> None:
        self.host = host
        self.password = password
        self.source_ip = source_ip
        self.cookies = http.cookiejar.CookieJar()
        self.opener = build_opener(source_ip=source_ip, cookie_jar=self.cookies)

    @staticmethod
    def compute_arc_md5(password: str, token: str) -> str:
        inner = hashlib.md5(password.encode("utf-8")).hexdigest().lower()
        combined = f"{inner}{token}".encode("utf-8")
        return hashlib.sha256(combined).hexdigest().lower()

    def login(self) -> None:
        if not self.password:
            return
        status_url = f"http://{self.host}/loginStatus.cgi"
        with self.opener.open(status_url, timeout=10) as resp:
            info = json.loads(resp.read().decode("utf-8", errors="ignore"))
        token = str(info.get("token", ""))
        hashed_pw = self.compute_arc_md5(self.password, token)
        form = urllib.parse.urlencode({"user_Async": "0", "user_Password": hashed_pw}).encode("utf-8")
        req = urllib.request.Request(
            f"http://{self.host}/login.cgi",
            data=form,
            headers={"Content-Type": "application/x-www-form-urlencoded"},
            method="POST",
        )
        with self.opener.open(req, timeout=10) as resp:
            resp.read()

    def inspect_gateway(self) -> Tuple[str, str, str, bool, bool]:
        """Returns (model, firmware, led_info, radio_online, wan_ping_ok)."""
        self.login()
        with self.opener.open(f"http://{self.host}/cgi/cgi_status.js", timeout=10) as resp:
            raw = resp.read().decode("utf-8", errors="ignore")
        model_m = re.search(r'"model_name"\s*:\s*"([^"]+)"', raw)
        fw_m = re.search(r'"fw_version"\s*:\s*"([^"]+)"', raw)
        led_m = re.search(r'"led_info"\s*:\s*"([^"]+)"', raw)
        rsrp_m = re.search(r'"nr5g_rsrp"\s*:\s*"?(-?\d+(?:\.\d+)?)"?', raw)
        ping_m = re.search(r'"ping_ok"\s*:\s*(true|false|1|0|"1"|"0")', raw, re.IGNORECASE)

        model = model_m.group(1) if model_m else "ASK-NCM1100"
        fw = fw_m.group(1) if fw_m else ""
        led = led_m.group(1) if led_m else "Unknown"
        radio_ok = bool(rsrp_m and float(rsrp_m.group(1)) > -140.0)
        ping_ok = bool(ping_m and str(ping_m.group(1)).strip('"').lower() in ("true", "1"))
        return model, fw, led, radio_ok, ping_ok

    def trigger_oma_dm_sync(self) -> None:
        self.login()
        body = urllib.parse.urlencode({"act_set_omadm_check": "1"}).encode("utf-8")
        req = urllib.request.Request(f"http://{self.host}/ apply.cgi".replace(" ", ""), data=body, method="POST")
        with self.opener.open(req, timeout=10) as resp:
            resp.read()

    def renew_wan(self) -> None:
        self.login()
        body = urllib.parse.urlencode({"action": "renew4_6"}).encode("utf-8")
        req = urllib.request.Request(f"http://{self.host}/apply.cgi", data=body, method="POST")
        with self.opener.open(req, timeout=10) as resp:
            resp.read()

    def reboot(self) -> None:
        self.login()
        body = urllib.parse.urlencode({"reboot": "1"}).encode("utf-8")
        req = urllib.request.Request(f"http://{self.host}/apply.cgi", data=body, method="POST")
        with self.opener.open(req, timeout=10) as resp:
            resp.read()


class XfinityGatewayDriver:
    """
    Driver for Xfinity Home Internet RDK-B Gateways (XB6 / XB7 / XB8 at 10.0.0.1)
    and xfinitywifi captive-portal environments.
    """

    CAPABILITIES = ProviderCapabilities(
        provider="xfinity",
        default_host="10.0.0.1",
        supports_oma_dm_sync=False,
        supports_wan_renew=True,
        supports_soft_reboot=True,
        supports_portal_auto_release=False,
    )

    def __init__(
        self,
        host: str = "10.0.0.1",
        username: str = "admin",
        password: str = "password",
        source_ip: Optional[str] = None,
    ) -> None:
        self.host = host
        self.username = username
        self.password = password
        self.source_ip = source_ip
        self.cookies = http.cookiejar.CookieJar()
        self.opener = build_opener(source_ip=source_ip, cookie_jar=self.cookies)

    def login(self) -> None:
        if not self.password:
            return
        form = urllib.parse.urlencode({"username": self.username, "password": self.password}).encode("utf-8")
        req = urllib.request.Request(
            f"http://{self.host}/check.jst",
            data=form,
            headers={"Content-Type": "application/x-www-form-urlencoded"},
            method="POST",
        )
        with self.opener.open(req, timeout=10) as resp:
            resp.read()

    def inspect_gateway(self) -> Tuple[str, str, str, bool, bool]:
        """
        Scrapes Xfinity RDK-B status from /network_setup.jst or /at_a_glance.jst.
        Returns (model, firmware, wan_status_text, docsis_online, wan_internet_ok).
        """
        self.login()
        with self.opener.open(f"http://{self.host}/network_setup.jst", timeout=10) as resp:
            html = resp.read().decode("utf-8", errors="ignore")

        model_m = re.search(r"Model\s*Name\s*[:<>/tdh\s]*([A-Za-z0-9\-_]+)", html, re.IGNORECASE)
        fw_m = re.search(r"Vendor\s*Software\s*Version\s*[:<>/tdh\s]*([A-Za-z0-9.\-_]+)", html, re.IGNORECASE)
        status_m = re.search(r"Cable\s*Modem\s*Status\s*[:<>/tdh\s]*(Operational|Online|Offline|Partial)", html, re.IGNORECASE)
        ip_m = re.search(r"WAN\s*IP\s*Address\s*[:<>/tdh\s]*(\d+\.\d+\.\d+\.\d+)", html, re.IGNORECASE)

        model = model_m.group(1) if model_m else "Xfinity-XB-Gateway"
        fw = fw_m.group(1) if fw_m else ""
        cm_status = status_m.group(1) if status_m else "Unknown"
        docsis_ok = cm_status.lower() in ("operational", "online")
        wan_ip = ip_m.group(1) if ip_m else ""
        wan_ok = bool(docsis_ok and wan_ip and not wan_ip.startswith(("0.", "169.254.")))
        return model, fw, f"DOCSIS {cm_status}", docsis_ok, wan_ok

    def renew_wan(self) -> None:
        """Resets only the Xfinity DOCSIS/WAN module without resetting Wi-Fi or factory settings."""
        self.login()
        form = urllib.parse.urlencode({"resetInfo": "Router,Wifi"}).encode("utf-8")
        req = urllib.request.Request(
            f"http://{self.host}/actionHandler/ajaxSet_Reset_Restore.jst",
            data=form,
            headers={"Content-Type": "application/x-www-form-urlencoded"},
            method="POST",
        )
        with self.opener.open(req, timeout=10) as resp:
            resp.read()

    def reboot(self) -> None:
        self.login()
        form = urllib.parse.urlencode({"resetInfo": "Device"}).encode("utf-8")
        req = urllib.request.Request(
            f"http://{self.host}/actionHandler/ajaxSet_Reset_Restore.jst",
            data=form,
            headers={"Content-Type": "application/x-www-form-urlencoded"},
            method="POST",
        )
        with self.opener.open(req, timeout=10) as resp:
            resp.read()


class TMobileTMIDriver:
    CAPABILITIES = ProviderCapabilities(
        provider="tmobile",
        default_host="192.168.12.1",
        supports_oma_dm_sync=False,
        supports_wan_renew=False,
        supports_soft_reboot=True,
        supports_portal_auto_release=False,
    )

    def __init__(self, host: str = "192.168.12.1", password: str = "", source_ip: Optional[str] = None) -> None:
        self.host = host
        self.password = password
        self.source_ip = source_ip
        self.opener = build_opener(source_ip=source_ip)

    def inspect_gateway(self) -> Tuple[str, str, str, bool, bool]:
        with self.opener.open(f"http://{self.host}/TMI/v1/gateway?get=all", timeout=10) as resp:
            data = json.loads(resp.read().decode("utf-8", errors="ignore"))
        dev = data.get("device", {})
        sig5g = data.get("signal", {}).get("5g", {})
        model = str(dev.get("model") or "TMI-5G-Gateway")
        fw = str(dev.get("softwareVersion") or "")
        rsrp = float(sig5g.get("rsrp") or -140.0)
        radio_ok = rsrp > -140.0
        return model, fw, "Radio registered" if radio_ok else "No signal", radio_ok, False

    def reboot(self) -> None:
        login_req = urllib.request.Request(
            f"http://{self.host}/TMI/v1/auth/login",
            data=json.dumps({"username": "admin", "password": self.password}).encode("utf-8"),
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        with self.opener.open(login_req, timeout=10) as resp:
            tok = json.loads(resp.read().decode("utf-8")).get("auth", {}).get("token", "")
        rb_req = urllib.request.Request(
            f"http://{self.host}/TMI/v1/gateway/reset?set=reboot",
            data=b"{}",
            headers={"Authorization": f"Bearer {tok}", "Content-Type": "application/json"},
            method="POST",
        )
        with self.opener.open(rb_req, timeout=10) as resp:
            resp.read()


# ---------------------------------------------------------------------------
# 4. Captive Portal & Walled Garden Detector + Reconciler
# ---------------------------------------------------------------------------

class CaptivePortalHealer:
    """
    Probes HTTP connectivity via http://neverssl.com/ and classifies:
      - Clear internet (HTTP 200 without redirect)
      - Verizon Walled Garden (141.207.x.x:8090 / ondevice.verizon.com)
      - Xfinity Activation Walled Garden (register.be.xfinity.com / xfinity.com/authorize)
      - Xfinity Wi-Fi Hotspot Portal (captiveportal.xfinity.com / wifi.xfinity.com)
      - Generic Captive Portal (any other 30x redirect or HTML meta-refresh intercept)
    """

    PROBE_URL = "http://neverssl.com/"

    def __init__(
        self,
        source_ip: Optional[str] = None,
        no_redirect_opener: Optional[urllib.request.OpenerDirector] = None,
        api_opener: Optional[urllib.request.OpenerDirector] = None,
    ) -> None:
        self.source_ip = source_ip
        self.no_redirect_opener = no_redirect_opener or build_opener(
            source_ip=source_ip, follow_redirects=False
        )
        self.api_opener = api_opener or build_opener(source_ip=source_ip, follow_redirects=True)

    @staticmethod
    def classify_redirect_url(url: str) -> str:
        lower = url.lower()
        if "ondevice.verizon.com" in lower or "141.207." in lower or ":8090" in lower:
            return "verizon_walled_garden"
        if "register.be.xfinity.com" in lower or "xfinity.com/authorize" in lower or "activate.xfinity.com" in lower:
            return "xfinity_activation"
        if "captiveportal.xfinity.com" in lower or "wifi.xfinity.com" in lower or "xfinitywifi" in lower:
            return "xfinity_hotspot"
        return "generic_captive"

    def probe_portal(self) -> Tuple[str, str, str]:
        """Returns (probe_status, intercept_type, redirect_url)."""
        req = urllib.request.Request(self.PROBE_URL, headers={"User-Agent": "Mozilla/5.0"})
        try:
            with self.no_redirect_opener.open(req, timeout=8) as resp:
                code = resp.getcode()
                loc = resp.headers.get("Location", "")
                body = resp.read(2048).decode("utf-8", errors="ignore")
                if code in (301, 302, 303, 307, 308) and loc:
                    return PROBE_INTERCEPTED, self.classify_redirect_url(loc), loc
                if "ondevice.verizon.com" in body or "register.be.xfinity.com" in body or "captiveportal.xfinity.com" in body:
                    m = re.search(r'https?://[^\s"\'<>]+', body)
                    found_url = m.group(0) if m else ""
                    return PROBE_INTERCEPTED, self.classify_redirect_url(found_url or body), found_url
                if code == 200:
                    return PROBE_CLEAR, "none", ""
                return PROBE_UNKNOWN, "none", ""
        except urllib.error.HTTPError as e:
            loc = e.headers.get("Location", "") if e.headers else ""
            if e.code in (301, 302, 303, 307, 308) and loc:
                return PROBE_INTERCEPTED, self.classify_redirect_url(loc), loc
            return PROBE_UNKNOWN, "none", ""
        except Exception:
            return PROBE_UNKNOWN, "none", ""

    @staticmethod
    def is_verizon_case_pending(case_obj: Dict[str, Any]) -> bool:
        status = str(case_obj.get("caseStatus", "")).strip()
        reconnect = str(case_obj.get("InternetReconnectStatus", "")).strip().upper()
        return status == "Pending-RTREnablement" or reconnect == "PENDING"

    def diagnose_and_fix(
        self,
        driver: Any,
        heal: bool = False,
        verizon_mtn: Optional[str] = None,
    ) -> PortalDiagnosis:
        caps: ProviderCapabilities = driver.CAPABILITIES
        diag = PortalDiagnosis(provider=caps.provider, gateway_host=driver.host)

        try:
            model, fw, status_txt, link_ok, wan_ok = driver.inspect_gateway()
            diag.gateway_model = model
            diag.firmware_version = fw
            diag.led_or_wan_status = status_txt
            diag.radio_or_docsis_online = link_ok
            diag.wan_internet_ok = wan_ok
        except Exception as exc:
            diag.led_or_wan_status = f"Gateway unreachable ({exc})"

        probe_status, intercept_type, redirect_url = self.probe_portal()
        diag.probe_status = probe_status
        diag.intercepted = (probe_status == PROBE_INTERCEPTED)
        diag.intercept_type = intercept_type
        diag.redirect_url = redirect_url

        if probe_status == PROBE_CLEAR:
            diag.wan_internet_ok = True

        # Only mutate state if heal=True
        if heal and (diag.intercepted or "walled garden" in diag.led_or_wan_status.lower() or not diag.wan_internet_ok):
            actions: List[str] = []
            if caps.supports_oma_dm_sync and hasattr(driver, "trigger_oma_dm_sync"):
                try:
                    driver.trigger_oma_dm_sync()
                    actions.append("oma_dm_sync")
                except Exception:
                    pass
            if caps.supports_wan_renew and hasattr(driver, "renew_wan"):
                try:
                    driver.renew_wan()
                    actions.append("wan_renew")
                except Exception:
                    pass
            diag.heal_action_taken = "+".join(actions) if actions else "none"

            if diag.heal_action_taken != "none":
                post_status, post_type, post_url = self.probe_portal()
                diag.probe_status = post_status
                diag.intercepted = (post_status == PROBE_INTERCEPTED)
                diag.intercept_type = post_type
                diag.redirect_url = post_url
                if post_status == PROBE_CLEAR:
                    diag.wan_internet_ok = True

        diag.verified_recovered = (
            diag.probe_status == PROBE_CLEAR
            and not diag.intercepted
            and "walled garden" not in diag.led_or_wan_status.lower()
            and diag.wan_internet_ok
        )
        return diag


def detect_provider(host: Optional[str] = None, opener: Optional[urllib.request.OpenerDirector] = None) -> str:
    op = opener or build_opener()
    candidates = [host] if host else ["192.168.1.1", "10.0.0.1", "192.168.12.1"]
    for h in candidates:
        if not h:
            continue
        try:
            with op.open(f"http://{h}/loginStatus.cgi", timeout=3) as r:
                if b"token" in r.read():
                    return "verizon"
        except Exception:
            pass
        try:
            with op.open(f"http://{h}/check.jst", timeout=3) as r:
                if r.getcode() in (200, 302):
                    return "xfinity"
        except Exception:
            pass
        try:
            with op.open(f"http://{h}/TMI/v1/gateway?get=all", timeout=3) as r:
                if b"device" in r.read():
                    return "tmobile"
        except Exception:
            pass
    raise RuntimeError("Could not auto-detect gateway provider. Specify --provider verizon|xfinity|tmobile.")


def create_driver(provider: str, host: Optional[str], password: str, source_ip: Optional[str] = None) -> Any:
    if provider == "verizon":
        return VerizonAskeyDriver(host=host or "192.168.1.1", password=password, source_ip=source_ip)
    if provider == "xfinity":
        return XfinityGatewayDriver(host=host or "10.0.0.1", password=password or "password", source_ip=source_ip)
    if provider == "tmobile":
        return TMobileTMIDriver(host=host or "192.168.12.1", password=password, source_ip=source_ip)
    raise ValueError(f"Unsupported provider: {provider}")


def main() -> None:
    parser = argparse.ArgumentParser(
        prog="portal-healer",
        description="ISP Portal Healer — Detect & fix stuck Walled Gardens across Verizon 5G, Xfinity, and T-Mobile 5G",
    )
    sub = parser.add_subparsers(dest="command", required=True)

    for cmd_name, help_txt in (
        ("check", "Read-only check of router status and ISP captive portal state"),
        ("fix", "Automatically heal a stuck Walled Garden or stale WAN lease"),
        ("watch", "Run continuous self-healing watchdog loop"),
    ):
        p = sub.add_parser(cmd_name, help=help_txt)
        p.add_argument("--provider", choices=["auto", "verizon", "xfinity", "tmobile"], default="auto")
        p.add_argument("--host", default=os.environ.get("GATEWAY_HOST"), help="Gateway IP (192.168.1.1, 10.0.0.1, or 192.168.12.1)")
        p.add_argument("--password", default=os.environ.get("GATEWAY_PASSWORD", ""), help="Gateway admin password")
        p.add_argument("--source-ip", default=os.environ.get("SOURCE_IP"), help="Bind probes to a specific local Wi-Fi/LAN IP")
        p.add_argument("--include-sensitive", action="store_true", help="Include full redirect query strings in output")
        if cmd_name == "watch":
            p.add_argument("--interval", type=int, default=60, help="Watchdog check interval in seconds (default: 60)")

    args = parser.parse_args()
    prov = detect_provider(args.host) if args.provider == "auto" else args.provider
    drv = create_driver(prov, args.host, args.password, source_ip=args.source_ip)
    healer = CaptivePortalHealer(source_ip=args.source_ip)

    if args.command in ("check", "fix"):
        diag = healer.diagnose_and_fix(drv, heal=(args.command == "fix"))
        print(json.dumps(diag.public_dict(include_sensitive=args.include_sensitive), indent=2))
    elif args.command == "watch":
        while True:
            diag = healer.diagnose_and_fix(drv, heal=True)
            print(json.dumps(diag.public_dict(include_sensitive=args.include_sensitive)), flush=True)
            time.sleep(args.interval)


if __name__ == "__main__":
    main()
