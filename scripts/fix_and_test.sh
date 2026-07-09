#!/usr/bin/env bash
# fix_and_test.sh — rebuild bgpd, install cleanly, run crypto-routes topotest
# Run from: /workspaces/bgp-assignment/frr
# Usage:    sudo bash scripts/fix_and_test.sh
# ─────────────────────────────────────────────────────────────────────────────
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"   # .../frr
TEST_SUITE="${REPO_ROOT}/../tests/topotests/bgp_crypto_routes"
INSTALL_DIR="/usr/lib/frr"
LOG_FILE="/tmp/topotest_full.log"
TOPO_LOG_DIR="/tmp/topotests/bgp_crypto_routes.test_bgp_crypto_routes"

RED='\033[0;31m'; GRN='\033[0;32m'; YLW='\033[1;33m'; NC='\033[0m'
info()  { echo -e "${GRN}[INFO]${NC}  $*"; }
warn()  { echo -e "${YLW}[WARN]${NC}  $*"; }
die()   { echo -e "${RED}[FAIL]${NC}  $*" >&2; exit 1; }
gate()  { info "──────────────────────────────────────────────"; }

gate
info "REPO ROOT : $REPO_ROOT"
info "INSTALL   : $INSTALL_DIR/bgpd"
info "TEST DIR  : $TEST_SUITE"
gate

# ─── 0. Sanity checks ────────────────────────────────────────────────────────
[[ $EUID -eq 0 ]] || die "Must run as root (sudo bash scripts/fix_and_test.sh)"
cd "$REPO_ROOT"
[[ -f bgpd/bgpd ]] || die "bgpd/bgpd not found — run 'make -j\$(nproc) bgpd/bgpd' first"
[[ -d "$TEST_SUITE" ]] || die "Test suite not found at $TEST_SUITE"

# ─── 1. Show what is currently installed vs what we just built ───────────────
gate
info "STEP 1 — binary freshness check"
echo "  installed : $(stat -c '%y' $INSTALL_DIR/bgpd 2>/dev/null || echo 'missing')"
echo "  built     : $(stat -c '%y' bgpd/bgpd)"
echo "  DIAG-5a in installed binary : $(strings $INSTALL_DIR/bgpd 2>/dev/null | grep -c 'DIAG-5a' || echo 0)"
echo "  DIAG-5a in built binary     : $(strings bgpd/bgpd | grep -c 'DIAG-5a')"

# ─── 2. Kill every running bgpd so the binary is not busy ────────────────────
gate
info "STEP 2 — kill all bgpd processes"
pkill -9 bgpd 2>/dev/null && info "killed existing bgpd" || info "no bgpd running"
sleep 2
pkill -9 bgpd 2>/dev/null || true   # second pass for stragglers
sleep 1

BUSY=$(lsof "$INSTALL_DIR/bgpd" 2>/dev/null | wc -l)
[[ $BUSY -gt 1 ]] && warn "something still has $INSTALL_DIR/bgpd open (lsof shows $BUSY lines)" || true

# ─── 3. Atomic install: remove old inode first, then copy ────────────────────
gate
info "STEP 3 — install fresh binary"
rm -f "$INSTALL_DIR/bgpd"
cp bgpd/bgpd "$INSTALL_DIR/bgpd"
chmod 755 "$INSTALL_DIR/bgpd"
info "installed: $(stat -c '%y' $INSTALL_DIR/bgpd)"

# ─── 4. Verify the installed binary is functional ────────────────────────────
gate
info "STEP 4 — sanity-test installed binary"
"$INSTALL_DIR/bgpd" --version || die "bgpd --version failed — binary is broken"

MISSING_LIBS=$(ldd "$INSTALL_DIR/bgpd" 2>&1 | grep "not found" || true)
[[ -n "$MISSING_LIBS" ]] && die "Missing shared libraries:\n$MISSING_LIBS"
info "All shared libraries found"

DIAG_COUNT=$(strings "$INSTALL_DIR/bgpd" | grep -c "DIAG-5a")
[[ "$DIAG_COUNT" -eq 1 ]] || die "DIAG-5a not found in installed binary (count=$DIAG_COUNT) — wrong binary was installed"
info "DIAG probes confirmed in installed binary ✓"

# ─── 5. Run mock tests (fast gate — no network namespaces needed) ─────────────
gate
info "STEP 5 — mock tests (fast gate)"

# Start a minimal bgpd for the mock tests
mkdir -p /var/run/frr /etc/frr
cat > /etc/frr/bgpd_mock.conf << 'CONF'
hostname bgpd
router bgp 65001
 bgp router-id 10.0.0.1
 address-family ipv4 crypto-routes
 exit-address-family
CONF

"$INSTALL_DIR/bgpd" \
    --config_file /etc/frr/bgpd_mock.conf \
    --pid_file    /var/run/frr/bgpd_mock.pid \
    --vty_socket  /var/run/frr/bgpd_mock.vty \
    --user root --group root -S -d
sleep 2

# Generate a test keypair if openssl is available
if command -v openssl &>/dev/null; then
    openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-256 \
        -out /tmp/test_privkey.pem 2>/dev/null
    openssl pkey -in /tmp/test_privkey.pem -pubout \
        -out /tmp/test_pubkey.pem 2>/dev/null
    info "test keypair generated in /tmp/"
fi

cd "$REPO_ROOT/.."   # pytest must run from repo root so 'tests/' is found

MOCK_RESULT=0
python3 -m pytest \
    tests/topotests/bgp_crypto_routes/test_bgp_crypto_routes_mock.py \
    -v --tb=short || MOCK_RESULT=$?

pkill bgpd 2>/dev/null || true

if [[ $MOCK_RESULT -ne 0 ]]; then
    die "Mock tests FAILED (exit $MOCK_RESULT) — fix before running full topotest"
fi
info "Mock tests PASSED ✓"

# ─── 6. Full two-router topotest ──────────────────────────────────────────────
gate
info "STEP 6 — full topotest (this takes ~2 min)"

FULL_RESULT=0
python3 -m pytest \
    tests/topotests/bgp_crypto_routes/test_bgp_crypto_routes.py \
    -v --tb=short 2>&1 | tee "$LOG_FILE" || FULL_RESULT=$?

# ─── 7. Collect evidence ──────────────────────────────────────────────────────
gate
info "STEP 7 — evidence collection"

echo ""
info "▶  r1 bgpd.err (startup errors):"
cat "$TOPO_LOG_DIR/r1/bgpd.err" 2>/dev/null || echo "  (not found)"

echo ""
info "▶  r1 DIAG probe lines:"
DIAG_LINES=$(grep "DIAG-[5-8]" "$TOPO_LOG_DIR/r1/bgpd.log" 2>/dev/null | head -100)
if [[ -z "$DIAG_LINES" ]]; then
    warn "  ZERO DIAG lines — bgpd startup failed or binary is still wrong"
    echo ""
    info "▶  r1 bgpd.log first 10 lines:"
    head -10 "$TOPO_LOG_DIR/r1/bgpd.log" 2>/dev/null || echo "  (not found)"
else
    echo "$DIAG_LINES"
fi

echo ""
info "▶  r2 DIAG probe lines:"
grep "DIAG-[5-8]" "$TOPO_LOG_DIR/r2/bgpd.log" 2>/dev/null | head -20 || echo "  (none)"

echo ""
info "▶  r1 UPDATE counter:"
grep -A 40 "BGP neighbor is 10.0.0.2" "$TOPO_LOG_DIR/r1/bgpd.log" 2>/dev/null \
    | grep -E "Updates|Established|bgpState" | head -5 || echo "  (not found)"

echo ""
info "▶  r2 show bgp ipv4 crypto-routes (last appearance):"
grep "192.168.100" "$TOPO_LOG_DIR/r2/bgpd.log" 2>/dev/null | tail -5 || echo "  (not found)"

gate
if [[ $FULL_RESULT -eq 0 ]]; then
    info "ALL TESTS PASSED ✓"
else
    warn "Full topotest exit code: $FULL_RESULT — scroll up for DIAG lines"
fi

echo ""
info "Full topotest log: $LOG_FILE"
info "Router logs     : $TOPO_LOG_DIR/"
