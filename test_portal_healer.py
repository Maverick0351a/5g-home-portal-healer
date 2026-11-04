#!/usr/bin/env python3
"""
Offline Socket-Free Unit Test Suite for ISP Portal Healer (v1.0.0)
"""

import unittest
from typing import List, Tuple

from portal_healer import (
    CaptivePortalHealer,
    PROBE_CLEAR,
    PROBE_INTERCEPTED,
    PROBE_UNKNOWN,
    VerizonAskeyDriver,
    XfinityGatewayDriver,
    TMobileTMIDriver,
)


class FakeDriver:
    def __init__(self, caps, status_tuple: Tuple[str, str, str, bool, bool], actions: List[str]) -> None:
        self.CAPABILITIES = caps
        self.host = caps.default_host
        self._status = status_tuple
        self.actions = actions

    def inspect_gateway(self) -> Tuple[str, str, str, bool, bool]:
        return self._status

    def trigger_oma_dm_sync(self) -> None:
        self.actions.append("oma_dm_sync")

    def renew_wan(self) -> None:
        self.actions.append("wan_renew")


class TestISPPortalHealer(unittest.TestCase):
    def test_1_redirect_classification_verizon_and_xfinity(self) -> None:
        self.assertEqual(
            CaptivePortalHealer.classify_redirect_url("https://ondevice.verizon.com/landing?encryptedinfo=abc"),
            "verizon_walled_garden",
        )
        self.assertEqual(
            CaptivePortalHealer.classify_redirect_url("https://register.be.xfinity.com/activate?mac=001122"),
            "xfinity_activation",
        )
        self.assertEqual(
            CaptivePortalHealer.classify_redirect_url("https://captiveportal.xfinity.com/login"),
            "xfinity_hotspot",
        )

    def test_2_check_mode_never_mutates_gateway(self) -> None:
        actions: List[str] = []
        drv = FakeDriver(
            VerizonAskeyDriver.CAPABILITIES,
            ("ASK-NCM1100", "3.6.0.5", "Walled garden active", True, False),
            actions,
        )
        healer = CaptivePortalHealer()
        healer.probe_portal = lambda: (  # type: ignore
            PROBE_INTERCEPTED,
            "verizon_walled_garden",
            "https://ondevice.verizon.com/w?secret=123",
        )
        diag = healer.diagnose_and_fix(drv, heal=False)
        self.assertTrue(diag.intercepted)
        self.assertEqual(diag.intercept_type, "verizon_walled_garden")
        self.assertEqual(actions, [])
        self.assertEqual(diag.heal_action_taken, "none")
        # Sensitive query string redacted by default
        pub = diag.public_dict(include_sensitive=False)
        self.assertEqual(pub["redirect_url"], "https://ondevice.verizon.com/w")

    def test_3_fix_mode_executes_recovery_and_verifies_clear_probe(self) -> None:
        actions: List[str] = []
        drv = FakeDriver(
            VerizonAskeyDriver.CAPABILITIES,
            ("ASK-NCM1100", "3.6.0.5", "Normal operation", True, False),
            actions,
        )
        healer = CaptivePortalHealer()
        calls = [0]

        def fake_probe():
            calls[0] += 1
            if calls[0] == 1:
                return PROBE_INTERCEPTED, "verizon_walled_garden", "https://ondevice.verizon.com/w"
            return PROBE_CLEAR, "none", ""

        healer.probe_portal = fake_probe  # type: ignore
        diag = healer.diagnose_and_fix(drv, heal=True)
        self.assertEqual(actions, ["oma_dm_sync", "wan_renew"])
        self.assertTrue(diag.verified_recovered)
        self.assertFalse(diag.intercepted)

    def test_4_xfinity_driver_capabilities_and_unknown_probe_guard(self) -> None:
        actions: List[str] = []
        drv = FakeDriver(
            XfinityGatewayDriver.CAPABILITIES,
            ("CGM4981COM", "7.6p9s1", "DOCSIS Operational", True, True),
            actions,
        )
        healer = CaptivePortalHealer()
        healer.probe_portal = lambda: (PROBE_UNKNOWN, "none", "")  # type: ignore
        diag = healer.diagnose_and_fix(drv, heal=False)
        # Even if DOCSIS is Operational, an unknown HTTP probe must not set verified_recovered
        self.assertFalse(diag.verified_recovered)


if __name__ == "__main__":
    unittest.main(verbosity=2)
