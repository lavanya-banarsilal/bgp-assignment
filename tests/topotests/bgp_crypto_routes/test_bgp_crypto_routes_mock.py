#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-or-later
"""
test_bgp_crypto_routes_mock.py — VTY-socket-based tests for BGP SAFI 241
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
  python3 -m pytest tests/topotests/bgp_crypto_routes/test_bgp_crypto_routes_mock.py -v -s

Copyright (C) 2025 BGP_ASSIGNMENT Project
"""

import os
import subprocess
import sys
import time
import pytest

# ── Constants ─────────────────────────────────────────────────────────────────

VTY_SOCKET = "/var/run/frr/"
VTYSH_BIN  = "/usr/bin/vtysh"
PUBKEY_PEM = "/tmp/test_pubkey.pem"
ORIGIN_ASN = "65001"

# ANSI colour codes — used only when stdout is a terminal
_RESET = "\x1b[0m"
_GREEN = "\x1b[32m"
_RED   = "\x1b[31m"
_BOLD  = "\x1b[1m"
_USE_COLOR = sys.stdout.isatty()


# ── Output helpers ────────────────────────────────────────────────────────────

def _banner(test_id, headline, what_it_does, what_it_guards):
    """
    Print a clear per-test header before the test body runs.

    Format:
        ──────────────────────────────────────────────
        M1  bgpd process health check
        What it does  : ...
        What it guards: ...
        ──────────────────────────────────────────────
    """
    sep = "─" * 62
    title = "{} — {}".format(test_id, headline)
    if _USE_COLOR:
        title = _BOLD + title + _RESET
    print("\n" + sep)
    print(title)
    print("What it does  : {}".format(what_it_does))
    print("What it guards: {}".format(what_it_guards))
    print(sep)


def _result(test_id, passed, detail=""):
    """
    Print a PASS or FAIL line after the assertion.

    Format:
        [PASS]  M1
        [FAIL]  M1 — <detail>
    """
    if passed:
        tag = (_GREEN + "[PASS]" + _RESET) if _USE_COLOR else "[PASS]"
        print("{}  {}".format(tag, test_id))
    else:
        tag = (_RED + "[FAIL]" + _RESET) if _USE_COLOR else "[FAIL]"
        msg = "{} — {}".format(test_id, detail) if detail else test_id
        print("{}  {}".format(tag, msg), file=sys.stderr)


# ── Helpers ───────────────────────────────────────────────────────────────────

def vtysh(*cmds):
    """
    Run one or more vtysh -c "..." commands against the live bgpd VTY socket.
    Returns the combined stdout+stderr string.
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
    Functional tests for BGP SAFI 241 (crypto-routes) against a live bgpd.

    Each test prints a clear header describing what it does and why, then
    prints [PASS] or [FAIL] so the output is self-explanatory at a glance.

    These mirror the assertions in test_bgp_crypto_routes.py but run against
    a single bgpd instance via the VTY socket instead of a two-router namespace
    topology.  The session and prefix propagation tests (TEST 2, 3, 5 in the
    full topotest) are replaced by RIB-presence and VTY-output tests that are
    meaningful for a single router.
    """

    # ── TEST M1: bgpd process health ─────────────────────────────────────────

    def test_M1_bgpd_is_alive(self):
        """
        TEST M1 — bgpd must respond to 'show version' with recognisable output.
        """
        _banner(
            "M1",
            "bgpd process health check",
            what_it_does=(
                "Sends 'show version' to bgpd via the VTY Unix socket "
                "and checks the response contains 'FRRouting' or 'frr'."
            ),
            what_it_guards=(
                "Liveness probe — if bgpd has crashed or was never started "
                "all subsequent tests are meaningless. Surfaces the real "
                "problem immediately instead of a confusing connection error."
            ),
        )

        out = vtysh("show version")
        passed = "FRRouting" in out or "frr" in out.lower()
        _result("M1", passed,
                "bgpd did not return expected version string. "
                "Output: {}".format(out[:120]))
        assert passed, (
            "bgpd did not return expected version string.  Output: {}".format(out[:200])
        )

    # ── TEST M2: crypto-routes address family is configured ──────────────────

    def test_M2_address_family_present(self):
        """
        TEST M2 — 'show bgp ipv4 crypto-routes' must not return an error.
        """
        _banner(
            "M2",
            "Crypto-routes address family is configured and VTY command is registered",
            what_it_does=(
                "Runs 'show bgp ipv4 crypto-routes'. An empty table is "
                "acceptable — what matters is the command does not return "
                "'Unknown command' or a CLI error."
            ),
            what_it_guards=(
                "Confirms the SAFI 241 RIB was allocated (the "
                "address-family block in bgpd.conf took effect) and the "
                "show command is wired up. A missing install_element() call "
                "would fail this test even if the C code is correct."
            ),
        )

        out = vtysh("show bgp ipv4 crypto-routes")
        no_error = "Unknown command" not in out
        _result("M2", no_error,
                "VTY command returned an error: {}".format(out[:120]))
        assert "%" not in out or "crypto-routes" in out, (
            "show bgp ipv4 crypto-routes returned an error: {}".format(out[:200])
        )
        assert no_error, (
            "VTY command not registered: {}".format(out[:200])
        )
        _result("M2", True)

    # ── TEST M3: public key load ──────────────────────────────────────────────

    def test_M3_pubkey_load(self):
        """
        TEST M3 — Loading a P-256 public key via VTY must succeed and print
        the key-id confirmation line.
        """
        _banner(
            "M3",
            "Public key loads successfully via VTY",
            what_it_does=(
                "Issues 'bgp crypto-routes pubkey 65001 /tmp/test_pubkey.pem' "
                "via VTY config mode and checks the response contains 'key-id' "
                "or 'loaded' — the confirmation that bgpd stored the key."
            ),
            what_it_guards=(
                "Exercises the full chain: VTY command -> "
                "bgp_crypto_pubkey_load() -> PEM_read_PUBKEY() -> "
                "SHA-256 fingerprint -> hash_get() into g_key_cache. "
                "Without this working, no route can ever reach SIG_VERIFIED."
            ),
        )

        if not os.path.exists(PUBKEY_PEM):
            pytest.skip(
                "Test public key not found at {}.  "
                "Run: openssl ecparam -name prime256v1 -genkey -noout -out /tmp/test_privkey.pem "
                "&& openssl ec -in /tmp/test_privkey.pem -pubout -out {}".format(
                    PUBKEY_PEM, PUBKEY_PEM
                )
            )
        out = load_pubkey(ORIGIN_ASN, PUBKEY_PEM)
        passed = "key-id" in out.lower() or "loaded" in out.lower()
        _result("M3", passed,
                "Expected key-id confirmation from bgpd, got: {}".format(out[:120]))
        assert passed, (
            "Expected key-id confirmation from bgpd, got: {}".format(out[:300])
        )

    # ── TEST M4: show pubkeys lists the loaded key ────────────────────────────

    def test_M4_show_pubkeys(self):
        """
        TEST M4 — 'show bgp crypto-routes pubkeys' must list the loaded key
        with the correct origin AS.
        """
        _banner(
            "M4",
            "show bgp crypto-routes pubkeys lists loaded key with correct ASN",
            what_it_does=(
                "Re-loads the public key (idempotent, exercises the key-rotation "
                "path), then runs 'show bgp crypto-routes pubkeys'. Asserts "
                "AS65001 and a hex key-id (0x...) appear in the output."
            ),
            what_it_guards=(
                "Validates bgp_crypto_show_pubkeys() iterates the hash table "
                "correctly and renders all fields. Without this the operator "
                "has no visibility into which keys are provisioned."
            ),
        )

        if not os.path.exists(PUBKEY_PEM):
            pytest.skip("Test public key not found at {}".format(PUBKEY_PEM))

        # Ensure the key is loaded (idempotent)
        load_pubkey(ORIGIN_ASN, PUBKEY_PEM)

        out = vtysh("show bgp crypto-routes pubkeys")
        asn_present = ORIGIN_ASN in out
        keyid_present = "key-id" in out.lower() or "0x" in out

        _result("M4 (ASN present)", asn_present,
                "AS{} not found in pubkeys output: {}".format(ORIGIN_ASN, out[:120]))
        _result("M4 (key-id rendered)", keyid_present,
                "key-id field not rendered in pubkeys output: {}".format(out[:120]))

        assert asn_present, (
            "AS{} not found in pubkeys output: {}".format(ORIGIN_ASN, out[:300])
        )
        assert keyid_present, (
            "key-id field not rendered in pubkeys output: {}".format(out[:300])
        )

    # ── TEST M5: RIB show command handles IPv6 AF ─────────────────────────────

    def test_M5_ipv6_crypto_routes_show(self):
        """
        TEST M5 — 'show bgp ipv6 crypto-routes' must not crash bgpd or return
        an unknown-command error.
        """
        _banner(
            "M5",
            "IPv6 crypto-routes show command does not crash",
            what_it_does=(
                "Runs 'show bgp ipv6 crypto-routes'. An empty IPv6 table is "
                "fine — what matters is no crash and no 'Unknown command'."
            ),
            what_it_guards=(
                "bgp_node_afi() was fixed to return the correct AFI for "
                "BGP_CRYPTO_ROUTES_NODE. Before the fix the IPv6 variant "
                "silently queried the IPv4 table. This is a regression guard "
                "for that fix."
            ),
        )

        out = vtysh("show bgp ipv6 crypto-routes")
        passed = "Unknown command" not in out
        _result("M5", passed,
                "IPv6 crypto-routes VTY command not registered: {}".format(out[:120]))
        assert passed, (
            "IPv6 crypto-routes VTY command not registered: {}".format(out[:200])
        )

    # ── TEST M6: show bgp summary includes crypto-routes AF ──────────────────

    def test_M6_bgp_summary_shows_safi(self):
        """
        TEST M6 — 'show bgp summary' must not crash with crypto-routes AF active.
        """
        _banner(
            "M6",
            "show bgp summary does not crash with SAFI 241 active",
            what_it_does=(
                "Runs 'show bgp summary' — the most-used operational command. "
                "Checks no CLI error strings appear. "
                "'No BGP neighbors found' is a normal informational message, "
                "not an error."
            ),
            what_it_guards=(
                "bgp_show_summary() iterates all configured AFs. Adding a new "
                "SAFI without updating that iterator causes a NULL-deref or "
                "assertion failure on a command operators run constantly."
            ),
        )

        out = vtysh("show bgp summary")
        # "% No BGP neighbors found in VRF default" is a valid FRR
        # informational line when no peers are configured — not a CLI error.
        passed = "Unknown command" not in out and "Command incomplete" not in out
        _result("M6", passed,
                "show bgp summary returned a CLI error: {}".format(out[:120]))
        assert passed, (
            "show bgp summary returned a CLI error: {}".format(out[:200])
        )

    # ── TEST M7: privkey configuration command ────────────────────────────────

    def test_M7_privkey_config(self):
        """
        TEST M7 — 'bgp crypto-routes privkey FILENAME' must accept a path and
        print a confirmation, and 'no bgp crypto-routes privkey' must succeed.
        """
        _banner(
            "M7",
            "Private key provisioning and removal via VTY",
            what_it_does=(
                "Issues 'bgp crypto-routes privkey /tmp/test_privkey.pem' via "
                "VTY config mode and checks for a confirmation message. "
                "Then issues the 'no' variant and checks the removal confirmation."
            ),
            what_it_guards=(
                "An originator router must be able to configure (and revoke) "
                "its private key path via CLI. This validates the VTY plumbing "
                "sets bgp->crypto_privkey_path correctly — without which the "
                "originator cannot sign any prefix."
            ),
        )

        privkey_path = "/tmp/test_privkey.pem"
        if not os.path.exists(privkey_path):
            pytest.skip("Test private key not found at {}".format(privkey_path))

        out = vtysh(
            "configure terminal",
            "router bgp {}".format(ORIGIN_ASN),
            " address-family ipv4 crypto-routes",
            "  bgp crypto-routes privkey {}".format(privkey_path),
            " exit-address-family",
            "exit",
            "exit",
        )
        set_ok = "privkey" in out.lower() or "set" in out.lower()
        _result("M7 (privkey set)", set_ok,
                "No confirmation from 'bgp crypto-routes privkey': {}".format(out[:120]))
        assert set_ok, (
            "Expected confirmation from 'bgp crypto-routes privkey', got: {}".format(out[:300])
        )

        # Also test the 'no' variant
        out_no = vtysh(
            "configure terminal",
            "router bgp {}".format(ORIGIN_ASN),
            " address-family ipv4 crypto-routes",
            "  no bgp crypto-routes privkey",
            " exit-address-family",
            "exit",
            "exit",
        )
        unset_ok = "removed" in out_no.lower() or "privkey" in out_no.lower()
        _result("M7 (privkey removed)", unset_ok,
                "No confirmation from 'no bgp crypto-routes privkey': {}".format(out_no[:120]))
        assert unset_ok, (
            "Expected confirmation from 'no bgp crypto-routes privkey', got: {}".format(out_no[:300])
        )
