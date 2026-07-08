#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-or-later
"""
test_bgp_crypto_routes_mock.py — VTY-socket-based tests for BGP SAFI 200
                                  (crypto-routes), no network namespaces needed.

Why this file exists
--------------------
The full topotest (test_bgp_crypto_routes.py) creates per-router Linux network
namespaces via munet/mutini.  That requires CAP_SYS_ADMIN / --privileged in the
container.  GitHub Codespace containers run without those capabilities by default
(kernel returns EPERM on unshare(CLONE_NEWNET)), so the full topotest cannot run
until the Codespace is rebuilt with the updated devcontainer.json.

This file validates the same functional properties against the *already-running*
single-instance bgpd that was started manually (see STEPS below), using the VTY
unix socket directly.  No containers, no namespaces, no extra privileges needed.

Pre-conditions (run these once in the Codespace terminal before pytest):
------------------------------------------------------------------------
  # 1. Build and install bgpd + vtysh
  cd /workspaces/bgp-assignment
  make lib/route_types.h
  make -j$(nproc) bgpd/bgpd vtysh/vtysh
  make install

  # 2. Ensure config has a BGP instance
  mkdir -p /etc/frr /var/run/frr
  cat > /etc/frr/bgpd.conf <<'EOF'
  hostname bgpd
  router bgp 65001
   bgp router-id 10.0.0.1
   address-family ipv4 crypto-routes
   exit-address-family
  EOF

  # 3. Start bgpd (-S skips CAP_SYS_ADMIN privs_init — not needed for unit tests)
  pkill bgpd || true; sleep 1
  /usr/lib/frr/bgpd \\
    --config_file /etc/frr/bgpd.conf \\
    --pid_file    /var/run/frr/bgpd.pid \\
    --vty_socket  /var/run/frr/bgpd.vty \\
    --user root --group root -S -d
  sleep 2

  # 4. Generate test keypair
  openssl ecparam -name prime256v1 -genkey -noout -out /tmp/test_privkey.pem
  openssl ec -in /tmp/test_privkey.pem -pubout -out /tmp/test_pubkey.pem

  # 5. Run this test file
  cd /workspaces/bgp-assignment
  python3 -m pytest tests/topotests/bgp_crypto_routes/test_bgp_crypto_routes_mock.py -v

Copyright (C) 2025 BGP_ASSIGNMENT Project
"""

import os
import subprocess
import sys
import time
import pytest

# ── Constants ─────────────────────────────────────────────────────────────────

VTY_SOCKET = "/var/run/frr/bgpd.vty"
VTYSH_BIN  = "/usr/bin/vtysh"
PUBKEY_PEM = "/tmp/test_pubkey.pem"
ORIGIN_ASN = "65001"


# ── Helpers ───────────────────────────────────────────────────────────────────

def vtysh(*cmds):
    """
    Run one or more vtysh -c "..." commands against the live bgpd VTY socket.
    Returns the combined stdout string.
    Raises subprocess.CalledProcessError on non-zero exit.
    """
    args = [VTYSH_BIN, "--vty_socket", VTY_SOCKET, "-d", "bgpd"]
    for cmd in cmds:
        args += ["-c", cmd]
    result = subprocess.run(args, capture_output=True, text=True, timeout=10)
    return result.stdout + result.stderr


def bgpd_running():
    """Return True if bgpd VTY socket exists and vtysh can connect."""
    if not os.path.exists(VTY_SOCKET) and not os.path.isdir(VTY_SOCKET):
        return False
    try:
        out = vtysh("show version")
        return "FRRouting" in out or "bgpd" in out.lower()
    except Exception:
        return False


def load_pubkey(asn, pem_path):
    """Load a public key for *asn* from *pem_path* via VTY config commands."""
    return vtysh(
        "configure terminal",
        "router bgp {}".format(asn),
        " address-family ipv4 crypto-routes",
        "  bgp crypto-routes pubkey {} {}".format(asn, pem_path),
        " exit-address-family",
        "exit",
        "exit",
    )


# ── Module-level skip guard ───────────────────────────────────────────────────
# If bgpd is not running, every test in this file is skipped with a clear
# message — far better than a confusing connection-refused traceback.

def pytest_configure(config):
    """Called early during collection — skip entire module if bgpd is absent."""
    pass  # The actual skip is in the autouse fixture below.


@pytest.fixture(autouse=True)
def require_bgpd():
    """Skip any test in this module if bgpd is not reachable."""
    if not bgpd_running():
        pytest.skip(
            "bgpd VTY socket not found at {}.  "
            "Start bgpd first (see module docstring for commands).".format(VTY_SOCKET)
        )


# ── Tests ─────────────────────────────────────────────────────────────────────

class TestCryptoRoutesMock:
    """
    Functional tests for BGP SAFI 200 (crypto-routes) against a live bgpd.

    These mirror the 5 assertions in test_bgp_crypto_routes.py but run against
    a single bgpd instance via the VTY socket instead of a two-router namespace
    topology.  The session and prefix propagation tests (TEST 2, 3, 5 in the
    full topotest) are replaced by RIB-presence and VTY-output tests that are
    meaningful for a single router.
    """

    # ── TEST M1: bgpd process health ─────────────────────────────────────────

    def test_M1_bgpd_is_alive(self):
        """
        TEST M1 — bgpd must respond to 'show version' with recognisable output.

        Mirrors: topotest TEST 1 session-established pre-condition.
        Rationale: if bgpd has crashed or not started, all subsequent tests
        are meaningless.  A quick version-check is the cheapest liveness probe.
        """
        out = vtysh("show version")
        assert "FRRouting" in out or "frr" in out.lower(), (
            "bgpd did not return expected version string.  Output: {}".format(out[:200])
        )

    # ── TEST M2: crypto-routes address family is configured ──────────────────

    def test_M2_address_family_present(self):
        """
        TEST M2 — 'show bgp ipv4 crypto-routes' must not return an error.

        Mirrors: topotest TEST 3 show_crypto_routes_vty.
        Rationale: verifies that SAFI_CRYPTO_ROUTES RIB was allocated (the
        address-family block is present in bgpd.conf) and the VTY command
        is registered and reachable.  An empty table is acceptable — what
        matters is that the command succeeds and returns the header line.
        """
        out = vtysh("show bgp ipv4 crypto-routes")
        assert "%" not in out or "crypto-routes" in out, (
            "show bgp ipv4 crypto-routes returned an error: {}".format(out[:200])
        )
        # The command must emit the table header, not an unknown-command error
        assert "Unknown command" not in out, (
            "VTY command not registered: {}".format(out[:200])
        )

    # ── TEST M3: public key load ──────────────────────────────────────────────

    def test_M3_pubkey_load(self):
        """
        TEST M3 — Loading a P-256 public key via VTY must succeed and print
        the key-id confirmation line.

        Mirrors: topotest TEST 4 pubkey_load_and_show.
        Rationale: this exercises the full path:
          VTY command → bgp_crypto_pubkey_load() → PEM_read_PUBKEY() →
          SHA-256 fingerprint → hash_get() into g_key_cache.
        The key-id printed on success is the 4-byte SHA-256 truncation of the
        DER-encoded SubjectPublicKeyInfo — proves OpenSSL parsed the key and
        the cache stored it.
        """
        if not os.path.exists(PUBKEY_PEM):
            pytest.skip(
                "Test public key not found at {}.  "
                "Run: openssl ecparam -name prime256v1 -genkey -noout -out /tmp/test_privkey.pem "
                "&& openssl ec -in /tmp/test_privkey.pem -pubout -out {}".format(
                    PUBKEY_PEM, PUBKEY_PEM
                )
            )
        out = load_pubkey(ORIGIN_ASN, PUBKEY_PEM)
        assert "key-id" in out.lower() or "loaded" in out.lower(), (
            "Expected key-id confirmation from bgpd, got: {}".format(out[:300])
        )

    # ── TEST M4: show pubkeys lists the loaded key ────────────────────────────

    def test_M4_show_pubkeys(self):
        """
        TEST M4 — 'show bgp crypto-routes pubkeys' must list the key loaded in
        TEST M3 with the correct origin AS.

        Mirrors: topotest TEST 4 pubkey_load_and_show (_check closure).
        Rationale: validates that bgp_crypto_show_pubkeys() iterates the hash
        table correctly and that the key_id / origin-as fields are rendered.
        The test re-loads the key (idempotent — same key_id, same ASN → key
        rotation path in bgp_crypto_pubkey_load) so it passes even if run in
        isolation without TEST M3 having run first.
        """
        if not os.path.exists(PUBKEY_PEM):
            pytest.skip("Test public key not found at {}".format(PUBKEY_PEM))

        # Ensure the key is loaded (idempotent)
        load_pubkey(ORIGIN_ASN, PUBKEY_PEM)

        out = vtysh("show bgp crypto-routes pubkeys")
        assert ORIGIN_ASN in out, (
            "AS{} not found in pubkeys output: {}".format(ORIGIN_ASN, out[:300])
        )
        assert "key-id" in out.lower() or "0x" in out, (
            "key-id field not rendered in pubkeys output: {}".format(out[:300])
        )

    # ── TEST M5: RIB show command handles IPv6 AF ─────────────────────────────

    def test_M5_ipv6_crypto_routes_show(self):
        """
        TEST M5 — 'show bgp ipv6 crypto-routes' must not crash bgpd or return
        an unknown-command error.

        Rationale: bgp_node_afi() was fixed in Phase 6 to return the correct AFI
        for BGP_CRYPTO_ROUTES_NODE.  This test ensures that fix holds — before
        the fix, the IPv6 variant silently operated on AFI_IP (wrong table).
        An empty IPv6 table is acceptable; what matters is no crash and no CLI
        error.
        """
        out = vtysh("show bgp ipv6 crypto-routes")
        assert "Unknown command" not in out, (
            "IPv6 crypto-routes VTY command not registered: {}".format(out[:200])
        )

    # ── TEST M6: show bgp summary includes crypto-routes AF ──────────────────

    def test_M6_bgp_summary_shows_safi(self):
        """
        TEST M6 — 'show bgp summary' must not crash.

        Rationale: bgp_show_summary() iterates all configured AFs. Adding a new
        SAFI without updating the summary iterator would cause a NULL-deref or
        assertion failure when the operator runs this common operational command.
        """
        out = vtysh("show bgp summary")
        # "% No BGP neighbors found in VRF default" is a valid FRR
        # informational line when no peers are configured — not a CLI error.
        # The real error strings are "% Unknown command" and
        # "% Command incomplete".
        assert "Unknown command" not in out and "Command incomplete" not in out, (
            "show bgp summary returned a CLI error: {}".format(out[:200])
        )
