# 5G Home Internet Portal Healer (`5g-home-portal-healer`)

**The 1-Click "Blinking Red Light & Walled Garden" Unbricker for Verizon 5G Home (`192.168.1.1`), T-Mobile 5G Home (`192.168.12.1`), and Xfinity Home Internet (`10.0.0.1` / `xfinitywifi`).**

---

## Why This Stands Out
Home 5G cubes and cable gateways frequently get stuck in a **"healthy signal, no internet"** loop where:
- **Verizon 5G Home (`192.168.1.1`)** shows a blinking red/white LED (`Walled garden active`) or redirects web traffic to `ondevice.verizon.com` even when your bill is paid and 5G signal is strong.
- **Xfinity Home Internet (`10.0.0.1` XB6/XB7/XB8 & `xfinitywifi`)** locks into `register.be.xfinity.com` or `captiveportal.xfinity.com` after a modem firmware update or provisioning hiccup.
- **T-Mobile 5G Home (`192.168.12.1`)** stays registered to the cell tower (`RSRP` present) while upstream WAN routing drops.

`5g-home-portal-healer` includes **Zero-Config Multi-Wi-Fi Auto-Discovery** and a **1-Click Local Web Control Center** (`http://127.0.0.1:8890/`) that detects your connected router and clears stuck Walled Gardens without wiping your Wi-Fi settings.

---

## Quick Start

```bash
# 1. Launch the Interactive Web Control Center at http://127.0.0.1:8890/
python portal_healer.py ui --password "<YOUR_ROUTER_PASSWORD>"

# 2. See all auto-discovered Wi-Fi & LAN adapters (SSID, Local IP, Gateway, Provider)
python portal_healer.py adapters

# 3. Read-only check (auto-detects Verizon 192.168.1.1, Xfinity 10.0.0.1, or T-Mobile 192.168.12.1)
python portal_healer.py check --password "<YOUR_ROUTER_PASSWORD>"

# 4. Automatically fix a stuck Walled Garden or stale WAN session
python portal_healer.py fix --password "<YOUR_ROUTER_PASSWORD>"
```

---

## Running Offline Tests

```bash
python test_portal_healer.py
```
