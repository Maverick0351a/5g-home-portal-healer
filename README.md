# 5G Home Internet & Xfinity WiFi Captive Portal Auto-Healer (`5g-home-portal-healer`)

[![CI & Windows EXE Release](https://github.com/Maverick0351a/5g-home-portal-healer/actions/workflows/ci-and-release.yml/badge.svg)](https://github.com/Maverick0351a/5g-home-portal-healer/actions/workflows/ci-and-release.yml)
[![Latest Release](https://img.shields.io/github/v/release/Maverick0351a/5g-home-portal-healer?label=Windows%20EXE)](https://github.com/Maverick0351a/5g-home-portal-healer/releases/latest)

Automatically detect and recover from silent **Verizon 5G Home Internet** (`192.168.1.1`), **T-Mobile 5G Home Internet** (`192.168.12.1`), and **Xfinity Home Internet / `xfinitywifi`** (`10.0.0.1`) captive-portal hijacks, OMA-DM firmware stalls, and frozen cellular WAN leases without manual router reboots.

---

## Quick Start

### Option A: Standalone Windows `.exe`
Download `5g-home-portal-healer.exe` from [**Releases**](https://github.com/Maverick0351a/5g-home-portal-healer/releases/latest):
```powershell
.\5g-home-portal-healer.exe ui --port 8890
```

### Option B: Python CLI & Web Dashboard (Zero External Dependencies)
```powershell
# 1. Launch Interactive Web Healer Dashboard (http://127.0.0.1:8890/)
python portal_healer.py ui --port 8890

# 2. Run a live captive-portal & gateway check
python portal_healer.py check --provider auto

# 3. Run continuous background auto-healing daemon
python portal_healer.py watch --provider auto --interval 30
```

## Run Offline Unit Tests
```powershell
python test_portal_healer.py
```
