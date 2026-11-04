#!/usr/bin/env python3
"""
5G Home Internet Portal Healer (5g-home-portal-healer v1.1.0)
=============================================================
The 1-Click "Blinking Red Light & Walled Garden" Unbricker for:
  - Verizon 5G Home Internet (Askey ASK-NCM1100 / WNC gateways at 192.168.1.1)
  - T-Mobile 5G Home Internet (TMI gateways at 192.168.12.1)
  - Xfinity Home Internet & xfinitywifi (RDK-B XB6/XB7/XB8 gateways at 10.0.0.1)

Includes:
  - Zero-Config Multi-Wi-Fi Adapter Auto-Discovery (`adapters` & `--interface`)
  - Interactive Local Web Control Center (`ui` at http://127.0.0.1:8890/)
  - Safe read-only `check` mode by default + `fix` and `watch` modes.
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
import subprocess
import time
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import asdict, dataclass, field
from http.server import BaseHTTPRequestHandler, HTTPServer
from typing import Any, Dict, List, Optional, Tuple


# ---------------------------------------------------------------------------
# 1. Zero-Config Multi-Wi-Fi & Network Adapter Auto-Discovery
# ---------------------------------------------------------------------------

@dataclass
class NetworkAdapterInfo:
    interface_name: str
    description: str
    state: str
    ssid: str
    ipv4_address: str
    gateway_ip: str
    inferred_provider: str


def infer_provider_from_adapter(ssid: str, gateway_ip: str, ipv4_address: str) -> str:
    s_low = ssid.lower()
    if "verizon" in s_low or gateway_ip == "192.168.1.1" or ipv4_address.startswith("192.168.1."):
        return "verizon"
    if "xfinity" in s_low or gateway_ip == "10.0.0.1" or ipv4_address.startswith("10.0.0."):
        return "xfinity"
    if "t-mobile" in s_low or "tmobile" in s_low or gateway_ip == "192.168.12.1" or ipv4_address.startswith("192.168.12."):
        return "tmobile"
    return "generic"


def parse_netsh_wlan_interfaces(raw_text: str) -> Dict[str, Dict[str, str]]:
    interfaces: Dict[str, Dict[str, str]] = {}
    current_name = ""
    current: Dict[str, str] = {}
    for line in raw_text.splitlines():
        if ":" not in line:
            continue
        k, v = [part.strip() for part in line.split(":", 1)]
        k_low = k.lower()
        if k_low == "name":
            if current_name and current:
                interfaces[current_name] = current
            current_name = v
            current = {"name": v, "description": "", "state": "", "ssid": ""}
        elif k_low == "description":
            current["description"] = v
        elif k_low == "state":
            current["state"] = v
        elif k_low == "ssid":
            current["ssid"] = v
    if current_name and current:
        interfaces[current_name] = current
    return interfaces


def discover_network_adapters() -> List[NetworkAdapterInfo]:
    adapters: List[NetworkAdapterInfo] = []
    wlan_map: Dict[str, Dict[str, str]] = {}

    if os.name == "nt":
        try:
            proc = subprocess.run(
                ["netsh", "wlan", "show", "interfaces"],
                capture_output=True,
                text=True,
                timeout=5,
                check=False,
            )
            wlan_map = parse_netsh_wlan_interfaces(proc.stdout)
        except Exception:
            pass

        try:
            ps_cmd = (
                "Get-NetIPConfiguration | ForEach-Object { "
                "[PSCustomObject]@{ "
                "Alias = $_.InterfaceAlias; "
                "Desc = $_.InterfaceDescription; "
                "Status = [string]$_.NetAdapter.Status; "
                "IPv4 = ($_.IPv4Address.IPAddress | Select-Object -First 1); "
                "GW = ($_.IPv4DefaultGateway.NextHop | Select-Object -First 1) "
                "} } | ConvertTo-Json -Compress"
            )
            proc_ip = subprocess.run(
                ["powershell", "-NoProfile", "-Command", ps_cmd],
                capture_output=True,
                text=True,
                timeout=6,
                check=False,
            )
            raw_json = proc_ip.stdout.strip()
            if raw_json:
                parsed = json.loads(raw_json)
                if isinstance(parsed, dict):
                    parsed = [parsed]
                for item in parsed:
                    alias = str(item.get("Alias") or "")
                    ipv4 = str(item.get("IPv4") or "")
                    gw = str(item.get("GW") or "")
                    w_info = wlan_map.get(alias, {})
                    ssid = w_info.get("ssid", "")
                    state = w_info.get("state") or str(item.get("Status") or "Up")
                    desc = w_info.get("description") or str(item.get("Desc") or alias)
                    if not gw and ipv4.startswith("192.168.1."):
                        gw = "192.168.1.1"
                    elif not gw and ipv4.startswith("10.0.0."):
                        gw = "10.0.0.1"
                    elif not gw and ipv4.startswith("192.168.12."):
                        gw = "192.168.12.1"
                    prov = infer_provider_from_adapter(ssid, gw, ipv4)
                    adapters.append(
                        NetworkAdapterInfo(
                            interface_name=alias,
                            description=desc,
                            state=state,
                            ssid=ssid,
                            ipv4_address=ipv4,
                            gateway_ip=gw,
                            inferred_provider=prov,
                        )
                    )
        except Exception:
            pass

    if not adapters:
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
                s.connect(("1.1.1.1", 80))
                local_ip = s.getsockname()[0]
        except Exception:
            local_ip = "127.0.0.1"
        gw = "192.168.1.1" if local_ip.startswith("192.168.1.") else (
            "10.0.0.1" if local_ip.startswith("10.0.0.") else "192.168.12.1"
        )
        adapters.append(
            NetworkAdapterInfo(
                interface_name="Primary",
                description="Default Network Interface",
                state="connected",
                ssid="",
                ipv4_address=local_ip,
                gateway_ip=gw,
                inferred_provider=infer_provider_from_adapter("", gw, local_ip),
            )
        )
    return adapters


# ---------------------------------------------------------------------------
# 2. Source-Bound HTTP/HTTPS Transport
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
    verify_tls: bool = False,
) -> urllib.request.OpenerDirector:
    ctx = ssl.create_default_context()
    if not verify_tls:
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
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
# 3. Data Models & Provider Drivers (Verizon 5G, Xfinity, T-Mobile 5G)
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
    intercept_type: str = "none"
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
        self.base_url = f"https://{host}"
        self.password = password
        self.source_ip = source_ip
        self.cookies = http.cookiejar.CookieJar()
        self.opener = build_opener(source_ip=source_ip, cookie_jar=self.cookies, verify_tls=False)
        self.token: str = ""

    @staticmethod
    def compute_arc_md5(password: str, token: str = "") -> str:
        md5_hex = hashlib.md5(password.encode("utf-8")).hexdigest()
        pw_hash = hashlib.sha512(md5_hex.encode("utf-8")).hexdigest()
        if token:
            return hashlib.sha512((token + pw_hash).encode("utf-8")).hexdigest()
        return pw_hash

    def _get(self, path: str) -> str:
        req = urllib.request.Request(f"{self.base_url}{path}", headers={"Referer": f"{self.base_url}/"})
        with self.opener.open(req, timeout=10) as resp:
            return resp.read().decode("utf-8", errors="ignore")

    def _post(self, path: str, form_body: str) -> str:
        req = urllib.request.Request(
            f"{self.base_url}{path}",
            data=form_body.encode("utf-8"),
            headers={"Content-Type": "application/x-www-form-urlencoded", "Referer": f"{self.base_url}/"},
            method="POST",
        )
        with self.opener.open(req, timeout=10) as resp:
            return resp.read().decode("utf-8", errors="ignore")

    def login(self) -> None:
        if not self.password:
            return
        info = json.loads(self._get("/loginStatus.cgi"))
        login_token = str(info.get("loginToken", ""))
        verify = self.compute_arc_md5(self.password, login_token)
        form = urllib.parse.urlencode(
            {
                "luci_username": self.compute_arc_md5("admin"),
                "luci_password": verify,
                "luci_view": "Desktop",
                "luci_token": login_token,
                "luci_keep_login": "1",
            }
        )
        self._post("/login.cgi", form)
        post_info = json.loads(self._get("/loginStatus.cgi"))
        self.token = str(post_info.get("token", ""))

    def inspect_gateway(self) -> Tuple[str, str, str, bool, bool]:
        if not self.password:
            st = json.loads(self._get("/loginStatus.cgi"))
            online = "loginToken" in st or "token" in st
            return "ASK-NCM1100", "", "Normal operation" if online else "Unreachable", online, online
        self.login()
        raw = self._get("/cgi/cgi_status.js")
        cell_raw = self._get("/cgi/cgi_cellular_signal.js")
        model_m = re.search(r'addROD\(\s*"hardware_model"\s*,\s*["\']([^"\']*)["\']', raw)
        fw_m = re.search(r'addROD\(\s*"router_version"\s*,\s*["\']([^"\']*)["\']', raw)
        led_m = re.search(r'addROD\(\s*"led_info"\s*,\s*["\']([^"\']*)["\']', raw)
        rsrp_m = re.search(r'"rsrp"\s*:\s*(-?\d+(?:\.\d+)?)', cell_raw)

        model = model_m.group(1) if model_m else "ASK-NCM1100"
        fw = fw_m.group(1) if fw_m else ""
        led = led_m.group(1) if led_m else "Normal operation"
        radio_ok = bool(rsrp_m and float(rsrp_m.group(1)) > -140.0)
        ping_ok = "walled garden" not in led.lower()
        return model, fw, led, radio_ok, ping_ok

    def trigger_oma_dm_sync(self) -> None:
        self.login()
        self._post("/apply_abstract.cgi", f"token={self.token}&action=oma_upgrade_trigger")

    def renew_wan(self) -> None:
        self.login()
        self._post("/apply_abstract.cgi", f"token={self.token}&action=renew4_6")

    def reboot(self) -> None:
        self.login()
        self._post("/apply_abstract.cgi", f"token={self.token}&action=ui_reboot_reason&action_params=1")
        self._post("/apply_abstract.cgi", f"token={self.token}&action=reboot")


class XfinityGatewayDriver:
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
# 4. Captive Portal Detector, Reconciler & Interactive Web Control Center
# ---------------------------------------------------------------------------

class CaptivePortalHealer:
    PROBE_URL = "http://connectivitycheck.gstatic.com/generate_204"

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
                if code in (200, 204):
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


def render_portal_healer_ui_html(
    adapters: List[NetworkAdapterInfo],
    diag: PortalDiagnosis,
) -> str:
    d = diag.public_dict(include_sensitive=False)
    adapter_rows = "\n".join(
        f"<tr><th>{a.interface_name}</th><td><code>{a.ssid or 'Wired/Standby'}</code></td>"
        f"<td><code>{a.ipv4_address or 'N/A'}</code></td><td><code>{a.gateway_ip or 'N/A'}</code> ({a.inferred_provider.upper()})</td></tr>"
        for a in adapters
    )
    status_badge = "CLEAR & ONLINE" if d["verified_recovered"] else (
        f"INTERCEPTED ({d['intercept_type']})" if d["intercepted"] else "UNVERIFIED / CHECK NEEDED"
    )
    return f"""<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <!-- MANDATORY: Declare support for both light and dark themes -->
  <meta name="color-scheme" content="light dark">
  <title>5G Home Internet Portal Healer &amp; Red-LED Unbricker</title>
  <style>
    :root {{
      --bg-light: #f8fafc;
      --bg-dark: #090d16;
      --card-light: #ffffff;
      --card-dark: #111827;
      --text-light: #0f172a;
      --text-dark: #f8fafc;
      --muted-light: #475569;
      --muted-dark: #94a3b8;
      --border-light: #e2e8f0;
      --border-dark: #1f2937;
      --brand-accent-light: #059669;
      --brand-accent-dark: #34d399;

      --bg: var(--bg-light);
      --card: var(--card-light);
      --text: var(--text-light);
      --muted: var(--muted-light);
      --border: var(--border-light);
      --accent-color: var(--brand-accent-light);

      @media (prefers-color-scheme: dark) {{
        --bg: var(--bg-dark);
        --card: var(--card-dark);
        --text: var(--text-dark);
        --muted: var(--muted-dark);
        --border: var(--border-dark);
        --accent-color: var(--brand-accent-dark);
      }}

      @supports (color: light-dark(white, black)) {{
        --bg: light-dark(var(--bg-light), var(--bg-dark));
        --card: light-dark(var(--card-light), var(--card-dark));
        --text: light-dark(var(--text-light), var(--text-dark));
        --muted: light-dark(var(--muted-light), var(--muted-dark));
        --border: light-dark(var(--border-light), var(--border-dark));
        --accent-color: light-dark(var(--brand-accent-light), var(--brand-accent-dark));
      }}

      color-scheme: light dark;
      accent-color: var(--accent-color);
    }}

    @supports not (accent-color: var(--accent-color)) {{
      progress {{
        -webkit-appearance: none;
        appearance: none;
        border: none;
        background: #ccc;
        height: 8px;
        border-radius: 4px;
      }}
      progress::-webkit-progress-value {{
        background-color: var(--accent-color);
        border-radius: 4px;
      }}
    }}

    * {{ box-sizing: border-box; }}
    body {{ margin: 0; font-family: system-ui, sans-serif; background: var(--bg); color: var(--text); padding: 24px; }}
    .wrap {{ max-width: 980px; margin: 0 auto; }}
    .hero {{
      background: var(--card);
      border: 1px solid var(--border);
      border-radius: 14px;
      padding: 24px;
      margin-bottom: 20px;
      display: flex;
      flex-wrap: wrap;
      justify-content: space-between;
      align-items: center;
      gap: 16px;
    }}
    .btn {{
      background: var(--accent-color);
      color: #090d16;
      font-weight: 700;
      border: none;
      border-radius: 10px;
      padding: 12px 18px;
      cursor: pointer;
    }}
    .grid {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(210px, 1fr)); gap: 16px; margin-bottom: 20px; }}
    .card {{ background: var(--card); border: 1px solid var(--border); border-radius: 12px; padding: 18px; }}
    .lbl {{ font-size: 0.75rem; text-transform: uppercase; color: var(--muted); }}
    .val {{ font-size: 1.25rem; font-weight: 700; margin-top: 6px; }}
    .table-wrap {{ container-type: inline-size; overflow-x: auto; background: var(--card); border: 1px solid var(--border); border-radius: 12px; margin-bottom: 20px; }}
    table {{ width: 100%; border-collapse: collapse; text-align: left; font-size: 0.9rem; }}
    th, td {{ padding: 12px 16px; border-bottom: 1px solid var(--border); }}
    pre, code {{ color-scheme: dark; accent-color: var(--accent-color); font-family: ui-monospace, monospace; }}
  </style>
</head>
<body>
  <div class="wrap">
    <section class="hero">
      <div>
        <h1 style="margin:0 0 6px 0;">5G Home Internet Portal Healer</h1>
        <p style="margin:0;color:var(--muted);">1-Click Walled Garden &amp; Blinking Red LED Unbricker (Verizon 5G, T-Mobile 5G &amp; Xfinity)</p>
      </div>
      <div style="display:flex;gap:10px;">
        <button class="btn" onclick="runAction('/api/check')">Check Status</button>
        <button class="btn" onclick="runAction('/api/fix')">1-Click Fix Walled Garden</button>
      </div>
    </section>

    <div class="grid">
      <div class="card"><div class="lbl">Portal Status</div><div class="val" id="st-badge">{status_badge}</div></div>
      <div class="card"><div class="lbl">Gateway Model</div><div class="val" id="gw-model">{d["gateway_model"]}</div></div>
      <div class="card"><div class="lbl">LED / WAN State</div><div class="val" id="led-state">{d["led_or_wan_status"]}</div></div>
      <div class="card">
        <div class="lbl">Recovery Verification</div>
        <div class="val" id="rec-state">{"VERIFIED" if d["verified_recovered"] else "ACTION NEEDED"}</div>
        <progress id="heal-progress" max="100" value="{100 if d["verified_recovered"] else 40}" style="width:100%;margin-top:8px;"></progress>
      </div>
    </div>

    <div tabindex="0" role="region" aria-label="Detected Wi-Fi Adapters" class="table-wrap">
      <table>
        <thead><tr><th>Adapter</th><th>Wi-Fi SSID</th><th>Local IPv4</th><th>Gateway &amp; Provider</th></tr></thead>
        <tbody>{adapter_rows}</tbody>
      </table>
    </div>
  </div>
  <script>
    async function runAction(endpoint) {{
      const badge = document.getElementById('st-badge');
      const pr = document.getElementById('heal-progress');
      badge.textContent = 'Running...';
      pr.value = 50;
      const r = await fetch(endpoint, {{ method: endpoint.includes('fix') ? 'POST' : 'GET' }});
      const data = await r.json();
      badge.textContent = data.verified_recovered ? 'CLEAR & ONLINE' : ('PROBE: ' + data.probe_status);
      document.getElementById('gw-model').textContent = data.gateway_model;
      document.getElementById('led-state').textContent = data.led_or_wan_status;
      document.getElementById('rec-state').textContent = data.verified_recovered ? 'VERIFIED' : (data.heal_action_taken || 'CHECKED');
      pr.value = data.verified_recovered ? 100 : 60;
    }}
  </script>
</body>
</html>"""


def detect_provider(host: Optional[str] = None, opener: Optional[urllib.request.OpenerDirector] = None) -> str:
    if not host:
        adapters = discover_network_adapters()
        for a in adapters:
            if a.inferred_provider in ("verizon", "xfinity", "tmobile") and not a.ipv4_address.startswith("169.254."):
                return a.inferred_provider
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
    return "verizon"


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
        prog="5g-home-portal-healer",
        description="5G Home Internet Portal Healer — Detect & fix stuck Walled Gardens across Verizon 5G, T-Mobile 5G, and Xfinity",
    )
    sub = parser.add_subparsers(dest="command", required=True)

    sub.add_parser("adapters", help="Auto-discover local Wi-Fi and LAN adapters")

    for cmd_name, help_txt in (
        ("check", "Read-only check of router status and ISP captive portal state"),
        ("fix", "Automatically heal a stuck Walled Garden or stale WAN lease"),
        ("watch", "Run continuous self-healing watchdog loop"),
        ("ui", "Launch Interactive Local Web Control Center (http://127.0.0.1:8890)"),
    ):
        p = sub.add_parser(cmd_name, help=help_txt)
        p.add_argument("--provider", choices=["auto", "verizon", "xfinity", "tmobile"], default="auto")
        p.add_argument("--interface", default=None, help="Select adapter by Wi-Fi name or SSID (e.g. 'Wi-Fi', 'xfinitywifi')")
        p.add_argument("--host", default=os.environ.get("GATEWAY_HOST"), help="Gateway IP (192.168.1.1, 10.0.0.1, or 192.168.12.1)")
        p.add_argument("--password", default=os.environ.get("GATEWAY_PASSWORD", ""), help="Gateway admin password")
        p.add_argument("--source-ip", default=os.environ.get("SOURCE_IP"), help="Bind probes to a specific local Wi-Fi/LAN IP")
        p.add_argument("--include-sensitive", action="store_true", help="Include full redirect query strings in output")
        if cmd_name == "watch":
            p.add_argument("--interval", type=int, default=60, help="Watchdog check interval in seconds (default: 60)")
        if cmd_name == "ui":
            p.add_argument("--bind", default="127.0.0.1", help="HTTP bind address (default: 127.0.0.1)")
            p.add_argument("--port", type=int, default=8890, help="HTTP port (default: 8890)")

    args = parser.parse_args()
    if args.command == "adapters":
        print(json.dumps([asdict(a) for a in discover_network_adapters()], indent=2))
        return

    adapters = discover_network_adapters()
    src_ip = args.source_ip
    if not src_ip and getattr(args, "interface", None):
        needle = args.interface.strip().lower()
        for a in adapters:
            if needle in (a.interface_name.lower(), a.ssid.lower()):
                src_ip = a.ipv4_address or None
                break

    prov = detect_provider(args.host) if args.provider == "auto" else args.provider
    drv = create_driver(prov, args.host, args.password, source_ip=src_ip)
    healer = CaptivePortalHealer(source_ip=src_ip)

    if args.command in ("check", "fix"):
        diag = healer.diagnose_and_fix(drv, heal=(args.command == "fix"))
        print(json.dumps(diag.public_dict(include_sensitive=args.include_sensitive), indent=2))
    elif args.command == "watch":
        while True:
            diag = healer.diagnose_and_fix(drv, heal=True)
            print(json.dumps(diag.public_dict(include_sensitive=args.include_sensitive)), flush=True)
            time.sleep(args.interval)
    elif args.command == "ui":
        class UIHandler(BaseHTTPRequestHandler):
            def do_GET(self) -> None:
                if self.path in ("/", "/dashboard"):
                    cur_diag = healer.diagnose_and_fix(drv, heal=False)
                    body = render_portal_healer_ui_html(discover_network_adapters(), cur_diag).encode("utf-8")
                    self.send_response(200)
                    self.send_header("Content-Type", "text/html; charset=utf-8")
                    self.send_header("Content-Length", str(len(body)))
                    self.end_headers()
                    self.wfile.write(body)
                elif self.path == "/api/check":
                    cur_diag = healer.diagnose_and_fix(drv, heal=False)
                    body = json.dumps(cur_diag.public_dict(include_sensitive=False), indent=2).encode("utf-8")
                    self.send_response(200)
                    self.send_header("Content-Type", "application/json")
                    self.send_header("Content-Length", str(len(body)))
                    self.end_headers()
                    self.wfile.write(body)
                else:
                    self.send_response(404)
                    self.end_headers()

            def do_POST(self) -> None:
                if self.path == "/api/fix":
                    cur_diag = healer.diagnose_and_fix(drv, heal=True)
                    body = json.dumps(cur_diag.public_dict(include_sensitive=False), indent=2).encode("utf-8")
                    self.send_response(200)
                    self.send_header("Content-Type", "application/json")
                    self.send_header("Content-Length", str(len(body)))
                    self.end_headers()
                    self.wfile.write(body)
                else:
                    self.send_response(404)
                    self.end_headers()

            def log_message(self, format: str, *args: Any) -> None:
                return

        srv = HTTPServer((args.bind, args.port), UIHandler)
        print(f"[5G Home Portal Healer UI] Control Center running at http://{args.bind}:{args.port}/", flush=True)
        srv.serve_forever()


if __name__ == "__main__":
    main()
