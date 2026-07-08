#!/usr/bin/env bash
# =============================================================================
# BGP_ASSIGNMENT — Codespaces / devcontainer setup script
#
# Runs ONCE when the Codespace is first created (onCreateCommand).
# Target: mcr.microsoft.com/devcontainers/base:ubuntu-22.04
#   → Ubuntu 22.04 LTS, apt-get available, runs as root inside Codespace.
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
    `# Build infrastructure` \
    autoconf \
    automake \
    libtool \
    make \
    build-essential \
    pkg-config \
    git \
    curl \
    wget \
    ca-certificates \
    `# Parser generators` \
    bison \
    flex \
    `# Docs / info` \
    texinfo \
    install-info \
    `# Perl — used by lib/route_types.pl` \
    perl \
    `# Python — clippy code-gen + configure scripts` \
    python3 \
    python3-dev \
    python3-pip \
    python3-sphinx \
    `# FRR mandatory libraries` \
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
    `# Protobuf` \
    libprotobuf-c-dev \
    protobuf-c-compiler \
    `# libyang build requirements` \
    cmake \
    libpcre2-dev \
    `# Runtime / debug` \
    gdb \
    iproute2 \
    sudo

apt-get clean
rm -rf /var/lib/apt/lists/*
echo ">>> [1/3] apt dependencies installed."

# ── 2. Build libyang 3.13.6 from source ──────────────────────────────────────
# Ubuntu 22.04 ships libyang 2.0 — FRR requires >= 2.1.128.
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

# Verify pkg-config finds it — configure will fail if not
pkg-config --modversion libyang
echo ">>> [2/3] libyang $(pkg-config --modversion libyang) installed."

# ── 3. Python packages ────────────────────────────────────────────────────────
echo ">>> [3/3] Installing Python build + test helpers..."
# NOTE: frrtest is NOT a PyPI package — it lives in the repo at
# tests/helpers/python/frrtest.py  (see tests/bgpd/test_crypto_routes.py
# for how sys.path is set up). Do NOT try to pip install it.
python3 -m pip install --quiet --no-cache-dir \
    wheel \
    pytest \
    "pytest-xdist>=3.6.1" \
    "scapy>=2.4.5" \
    pyyaml \
    xmltodict
echo ">>> [3/3] Done."

# ── Done ─────────────────────────────────────────────────────────────────────
echo ""
echo "============================================================"
echo " Setup complete. Run these commands to build bgpd:"
echo ""
echo "   cd /workspaces/bgp-assignment"
echo "   ./bootstrap.sh"
echo "   ./configure --enable-bgpd --disable-doc --disable-grpc \\"
echo "               --disable-rpki --disable-ospfapi     \\"
echo "               --enable-user=root --enable-group=root"
echo "   make -j\$(nproc) bgpd/bgpd"
echo ""
echo " Unit tests (no network required):"
echo "   make tests/bgpd/test_crypto_routes"
echo "   ./tests/bgpd/test_crypto_routes"
echo ""
echo " Topotests (requires kernel netns support):"
echo "   make install"
echo "   cd tests/topotests && sudo pytest bgp_crypto_routes/ -v"
echo "============================================================"
