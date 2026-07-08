#!/usr/bin/env bash
# =============================================================================
# BGP_ASSIGNMENT — Codespaces / devcontainer setup script
#
# Runs ONCE when the Codespace is first created (onCreateCommand).
# Installs every FRR build dependency and builds libyang 3.13.6 from source.
#
# Source references:
#   frr/doc/developer/building-frr-for-ubuntu2x04.rst
#   frr/docker/ubuntu-ci/Dockerfile
#   frr/doc/developer/building-libyang.rst
# =============================================================================
set -euo pipefail

# ── 1. System package dependencies ───────────────────────────────────────────
echo ">>> [1/3] Installing apt build dependencies..."
export DEBIAN_FRONTEND=noninteractive

apt-get update -qq
apt-get install -y --no-install-recommends \
    \
    `# Build infrastructure` \
    autoconf automake libtool make build-essential pkg-config \
    git curl wget ca-certificates \
    \
    `# Parser generators (FRR uses bison grammar files and flex lexers)` \
    bison flex \
    \
    `# Documentation / info pages` \
    texinfo install-info \
    \
    `# Perl — used by lib/route_types.pl code-gen script` \
    perl \
    \
    `# Python — clippy code generator + configure-time scripts` \
    python3 python3-dev python3-pip python3-sphinx \
    \
    `# FRR mandatory runtime libraries` \
    libreadline-dev \
    libjson-c-dev \
    libc-ares-dev \
    libcap-dev \
    libelf-dev \
    libssl-dev \
    libpam0g-dev \
    libunwind-dev \
    libsqlite3-dev \
    libsnmp-dev \
    \
    `# Protobuf (mgmtd; safe to include even without --enable-grpc)` \
    libprotobuf-c-dev \
    protobuf-c-compiler \
    \
    `# libyang build requirements` \
    cmake libpcre2-dev \
    \
    `# Debugging tools` \
    gdb sudo

apt-get clean
rm -rf /var/lib/apt/lists/*

echo ">>> [1/3] apt dependencies installed."

# ── 2. Build libyang 3.13.6 from source ──────────────────────────────────────
# Ubuntu 22.04 ships libyang 2.0 which is too old (FRR requires >= 2.1.128).
# v3 is recommended per FRR docs (support added in FRR 10.2).
echo ">>> [2/3] Building libyang v3.13.6 from source..."

git clone --depth 1 --branch v3.13.6 \
    https://github.com/CESNET/libyang.git /tmp/libyang

cmake -S /tmp/libyang \
      -B /tmp/libyang/build \
      -DCMAKE_INSTALL_PREFIX=/usr \
      -DCMAKE_BUILD_TYPE=Release

make -C /tmp/libyang/build -j"$(nproc)"
make -C /tmp/libyang/build install
ldconfig
rm -rf /tmp/libyang

# Verify pkg-config can find it — if this fails the FRR configure will abort
pkg-config --modversion libyang
echo ">>> [2/3] libyang $(pkg-config --modversion libyang) installed."

# ── 3. Python packages ────────────────────────────────────────────────────────
echo ">>> [3/3] Installing Python build + test helpers..."
python3 -m pip install --quiet --no-cache-dir \
    wheel \
    pytest \
    "pytest-xdist>=3.6.1" \
    "scapy>=2.4.5" \
    pyyaml \
    xmltodict \
    frrtest
echo ">>> [3/3] Done."

# ── Done ─────────────────────────────────────────────────────────────────────
echo ""
echo "============================================================"
echo " Setup complete. To build bgpd:"
echo ""
echo "   cd /workspaces/bgp-assignment"
echo "   ./bootstrap.sh"
echo "   ./configure --enable-bgpd --disable-doc --disable-grpc \\"
echo "               --disable-rpki --disable-ospfapi \\"
echo "               --enable-user=root --enable-group=root"
echo "   make bgpd/bgp_crypto_routes.o   # compile our new file first"
echo "   make -j\$(nproc) bgpd/bgpd        # full link"
echo ""
echo " To run unit tests:"
echo "   make tests/bgpd/test_crypto_routes"
echo "   pytest tests/bgpd/test_crypto_routes.py -v"
echo ""
echo " To run topotests (requires kernel network namespaces):"
echo "   cd tests/topotests"
echo "   sudo pytest bgp_crypto_routes/ -v"
echo "============================================================"
