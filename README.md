# ISP Portal Healer (`isp-portal-healer`)

**Detect and fix stuck ISP "Walled Garden" captive portals, false "No Internet" red LEDs, and stale WAN leases across Verizon 5G Home, Xfinity Home Internet (`10.0.0.1` / `xfinitywifi`), and T-Mobile 5G Home.**

---

## Why Use This?
Home 5G and cable gateways frequently get stuck in a **"healthy signal, no internet"** loop where:
- **Verizon 5G Home (`192.168.1.1`)** shows a blinking red/white LED (`Walled garden active`) or redirects web traffic to `ondevice.verizon.com` even when your account is paid and 5G signal is strong.
- **Xfinity Home Internet (`10.0.0.1` XB6/XB7/XB8 & `xfinitywifi`)** locks into `register.be.xfinity.com` or `captiveportal.xfinity.com` after a modem firmware update or provisioning hiccup.
- **T-Mobile 5G Home (`192.168.12.1`)** stays registered to the cell tower (`RSRP` present) while upstream WAN routing drops.

`isp-portal-healer` diagnoses the exact cause in read-only mode (`check`) and automatically triggers the gateway's internal OMA-DM sync or WAN lease renewal (`fix`) without wiping your Wi-Fi settings.

---

## Quick Start

```bash
# 1. Read-only check (auto-detects Verizon 192.168.1.1, Xfinity 10.0.0.1, or T-Mobile 192.168.12.1)
python portal_healer.py check --password "<YOUR_ROUTER_PASSWORD>"

# 2. Check a specific Xfinity gateway (10.0.0.1) or secondary Wi-Fi adapter (--source-ip)
python portal_healer.py check --provider xfinity --host 10.0.0.1 --password "password"

# 3. Automatically fix a stuck Walled Garden or stale WAN session
python portal_healer.py fix --provider verizon --host 192.168.1.1 --password "<YOUR_ROUTER_PASSWORD>"

# 4. Run continuous self-healing watchdog every 60 seconds
python portal_healer.py watch --interval 60 --password "<YOUR_ROUTER_PASSWORD>"
```

---

## Running Offline Tests

```bash
python test_portal_healer.py
```
