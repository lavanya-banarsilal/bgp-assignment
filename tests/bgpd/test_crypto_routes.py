# SPDX-License-Identifier: GPL-2.0-or-later
# Python test runner for test_crypto_routes.
# Consumed by pytest via frrtest.TestMultiOut — same pattern as test_mp_attr.py.
#
# frrtest is NOT a PyPI package. It lives in tests/helpers/python/frrtest.py
# inside the FRR source tree. We locate it relative to this file so pytest
# can be invoked from any working directory.
import os
import sys

# Walk up from tests/bgpd/ → tests/ → helpers/python/
_TESTS_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
_HELPERS = os.path.join(_TESTS_DIR, "helpers", "python")
if _HELPERS not in sys.path:
    sys.path.insert(0, _HELPERS)

import frrtest


class TestCryptoRoutes(frrtest.TestMultiOut):
    program = "./test_crypto_routes"


# ── T1: TLV encode ───────────────────────────────────────────────────────────
TestCryptoRoutes.okfail("T1: TLV encode basic")

# ── T2–T3: TLV encode edge cases ─────────────────────────────────────────────
TestCryptoRoutes.okfail("T2: TLV encode null path returns 0")
TestCryptoRoutes.okfail("T2: TLV encode null path writes 0 bytes")
TestCryptoRoutes.okfail("T3: TLV encode unsigned (sig_len=0) returns 0")

# ── T4–T7: NLRI parse ────────────────────────────────────────────────────────
TestCryptoRoutes.okfail("T4: NLRI parse good buffer returns OK")
TestCryptoRoutes.okfail("T5: NLRI parse truncated TLV header returns OVERFLOW")
TestCryptoRoutes.okfail("T6: NLRI parse truncated sig returns OVERFLOW")
TestCryptoRoutes.okfail("T7: NLRI parse wrong TLV type returns OVERFLOW")

# ── T8–T9: Constants ─────────────────────────────────────────────────────────
TestCryptoRoutes.okfail("T8: SAFI_CRYPTO_ROUTES == 10")
TestCryptoRoutes.okfail("T8: IANA_SAFI_CRYPTO_ROUTES == 200")
TestCryptoRoutes.okfail("T9: BGP_CRYPTO_SIG_TLV_TYPE == 0xCE")

# ── T10: afindex ─────────────────────────────────────────────────────────────
TestCryptoRoutes.okfail("T10: AFI_IP  SAFI_CRYPTO_ROUTES afindex in range")
TestCryptoRoutes.okfail("T10: AFI_IP6 SAFI_CRYPTO_ROUTES afindex in range")
TestCryptoRoutes.okfail("T10: AFI_IP and AFI_IP6 afindex values are distinct")
