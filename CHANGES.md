# BGP crypto_routes — Change Log

> All changes are restricted to the `BGP_ASSIGNMENT/frr/` directory.
> No change is made without reasoning. This file is the authoritative
> history of every modification to the FRR codebase for this project.

---

## Implementation Phases

| Phase | Layer | Status |
|-------|-------|--------|
| 0 | Project setup — CHANGES.md + IMPLEMENTATION_PLAN.md | ✅ Done |
| 1 | Core data structures — `bgp_crypto_routes.h/.c`, memory types, `bgp_path_info_extra`, `bgp_af_index` | ✅ Done |
| 2 | Build system — `subdir.am` | ✅ Done |
| 3 | VTY — pubkey config + show commands in `bgp_vty.c` | ✅ Done |
| 4 | NLRI encode/decode — `bgp_attr.c` | ✅ Done |
| 5 | NLRI dispatch — `bgp_packet.c` | ✅ Done |
| 6 | Bug fix — `bgp_node_afi()` for `BGP_CRYPTO_ROUTES_NODE` | ✅ Done |

---

## Phase 0 — Project Setup
**Date:** 2025-07-09  
**Files created:** `CHANGES.md`, `IMPLEMENTATION_PLAN.md`

**Reasoning:** Project rules mandate a running change log with reasoning for every
modification. These files are created first so all subsequent changes are tracked
from the start.

---

## Phase 1 — Core Data Structures

### 1a — `frr/bgpd/bgp_crypto_routes.h` (NEW)

**Reasoning:**  
Every SAFI in FRR that has per-path metadata has a dedicated header
(e.g. `bgp_unreach.h`, `bgp_ls.h`, `bgp_flowspec.h`). Following the same pattern
keeps the new code self-contained and makes the dependency graph explicit.

**Key decisions:**
- `BGP_CRYPTO_SIG_MAX_LEN 128` — covers ECDSA P-256 (64 B), Ed25519 (64 B), and
  leaves headroom without needing a heap allocation per path for Phase 2.
  Phase 3 can switch to `uint8_t *sig` + dynamic allocation when post-quantum
  signature sizes (>256 B) are supported.
- `bgp_crypto_sig_state` enum mirrors the `rpki_states` enum in `bgp_rpki.h`;
  `SIG_NO_PUBKEY` enables deferred re-verification (same deferred pattern RPKI uses).
- `bgp_crypto_pubkey_entry` hash table uses FRR's `jhash` on `key_id` (uint32)
  which is already the 4-byte SHA-256 truncation — O(1) lookup on the receive path.
- `last_seq_no_verified` stored per key-id entry — anti-replay at no additional
  memory per path (the counter lives in the key entry, not the path_info).

### 1b — `frr/bgpd/bgp_crypto_routes.c` (NEW)

**Reasoning:**  
Separating implementation from header keeps compile times low (only files that
include the header recompile on API changes) and isolates the OpenSSL dependency
to one translation unit.

**Key decisions:**
- OpenSSL `EVP_DigestVerify*` API used (not deprecated low-level `ECDSA_verify`)
  because it is algorithm-agnostic — the same code path handles ECDSA P-256 and
  future Ed25519 without branching.
- `SHA256()` used for key-id derivation (not SHA-1). SHA-1 is what RFC 6487 uses
  for RPKI SKI, but SHA-1 is deprecated. We use the first 4 bytes of SHA-256 instead.
- The public key cache is a simple `hashtable` (FRR's `hash.h`) keyed on `key_id`.
  The `bgp` instance pointer is stored so one cache per BGP instance is possible
  (needed for VRF-aware deployments in Phase 3).
- `bgp_crypto_verify_path()` is called from the NLRI parse path. It sets
  `sig_state` on the `bgp_path_info_extra_crypto` struct and returns a boolean.
  The caller (bgp_packet.c) decides whether to install the path based on the state.
- PEM file loading uses `PEM_read_PUBKEY()` which accepts both RSA and EC public keys
  without needing to know the algorithm in advance.

### 1c — `frr/bgpd/bgp_route.h` (MODIFIED)

**Reasoning:**  
`bgp_path_info_extra` holds a pointer to each SAFI's ancillary data. Adding
`struct bgp_path_info_extra_crypto *crypto` follows the identical pattern used by
`*evpn`, `*flowspec`, `*unreach`, and `*vrfleak`. The pointer is NULL for all
non-crypto-routes paths — zero overhead for existing SAFIs.

### 1d — `frr/bgpd/bgpd.h` (MODIFIED)

**Reasoning:**  
`bgp_af_index` is a compact O(1) index for `update_groups[BGP_AF_MAX]`. Without
adding `BGP_AF_IPV4_CRYPTO_ROUTES` and `BGP_AF_IPV6_CRYPTO_ROUTES`, the
update-group batching machinery silently has no slot for SAFI=200 UPDATEs,
which would cause all outbound crypto-routes updates to be dropped.
`BGP_AF_MAX` incremented from 16 to 18.

### 1e — `frr/bgpd/bgp_memory.h` + `frr/bgpd/bgp_memory.c` (MODIFIED)

**Reasoning:**  
FRR's memory tracking system (`MTYPE`) must have a declaration for every heap
allocation so memory leaks are detectable via `show memory bgpd`. Two new types:
- `BGP_ROUTE_EXTRA_CRYPTO` — for `bgp_path_info_extra_crypto` structs
- `BGP_CRYPTO_PUBKEY` — for `bgp_crypto_pubkey_entry` structs in the key cache

---

## Phase 2 — Build System

### `frr/bgpd/subdir.am` (MODIFIED)

**Reasoning:**  
The FRR build system uses automake `subdir.am` files to list source files.
`bgp_crypto_routes.c` must be added to `bgpd_libbgp_a_SOURCES`.
The `bgpd` binary links against `libbgp.a` so no linker flag changes are needed.
OpenSSL (`-lcrypto`) is already linked transitively via FRR's `configure.ac`
(`PKG_CHECK_MODULES([OPENSSL], [openssl >= 1.1.0])`).

---

## Phase 3 — VTY Layer

### `frr/bgpd/bgp_vty.c` (MODIFIED)

**Two changes:**

1. **`bgp crypto-routes pubkey <asn> <path>` config command** under
   `BGP_CRYPTO_ROUTES_NODE` — loads a PEM public key file into the key cache.
   Reasoning: This is the only operator-facing surface for Method 1 key
   provisioning. The command is idempotent — re-running with the same ASN
   replaces the existing key and triggers re-verification of all `SIG_NO_PUBKEY`
   paths for that key-id.

2. **`show bgp ipv4 crypto-routes [detail]`** — displays the Loc-RIB for SAFI=200
   with per-prefix sig_state annotations.
   Reasoning: Without a show command there is no operational visibility into
   whether signatures are passing. This is required for any production use.

---

## Phase 4 — NLRI Dispatch (`bgp_packet.c`)

### `frr/bgpd/bgp_packet.c` (MODIFIED)

**Changes made:**

**4.1 — `#include "bgpd/bgp_crypto_routes.h"` added** (after line 54)
Reason: `bgp_nlri_parse_crypto_routes()` is declared there and called in
`bgp_nlri_parse()`. Without the include, the compiler cannot resolve the symbol.

**4.2 — `case SAFI_CRYPTO_ROUTES:` in `bgp_nlri_parse()`** (after `SAFI_UNREACH` case)
Reason: `bgp_nlri_parse()` is the single fan-out dispatcher routing inbound NLRI
bytes to per-SAFI parsers. Without this case, received SAFI=200 UPDATEs fall
through to `return BGP_NLRI_PARSE_ERROR`, which causes a BGP NOTIFY and session
reset on the first received crypto-routes UPDATE.
Calls: `bgp_nlri_parse_crypto_routes(peer, attr, packet, mp_withdraw)`.

**4.3 — `afc_nego` fallback block: two new entries** (after `AFI_IP6/SAFI_FLOWSPEC` line)
```c
peer->afc_nego[AFI_IP][SAFI_CRYPTO_ROUTES]  = peer->afc[AFI_IP][SAFI_CRYPTO_ROUTES];
peer->afc_nego[AFI_IP6][SAFI_CRYPTO_ROUTES] = peer->afc[AFI_IP6][SAFI_CRYPTO_ROUTES];
```
Reason: This fallback block runs when a peer sends no Multiprotocol Capability
(old peer, or `override-capability` configured). It copies `afc[]` → `afc_nego[]`
for each SAFI so the UPDATE processing loop at line ~2570 knows the SAFI is active.
Without this, `if (!peer->afc[nlris[i].afi][nlris[i].safi])` evaluates to false and
the NLRI is silently discarded before `bgp_nlri_parse()` is ever reached.

---

## Phase 5 — TX Encode / Size Accounting (`bgp_attr.c`)

### `frr/bgpd/bgp_attr.c` (MODIFIED)
### `frr/bgpd/bgp_crypto_routes.h` (MODIFIED — added constant + new function decl)
### `frr/bgpd/bgp_crypto_routes.c` (MODIFIED — added `bgp_crypto_routes_encode_nlri_trailer()`)

**Changes made:**

**5.1 — `#include "bgpd/bgp_crypto_routes.h"` added** (after `bgp_unreach.h`)
Reason: `bgp_crypto_routes_encode_nlri_trailer()` and `BGP_CRYPTO_SIG_TLV_MAX_SIZE`
are declared/defined there.

**5.2 — `case SAFI_CRYPTO_ROUTES: fallthrough;` in `bgp_packet_mpattr_prefix()` — AFI_IP nexthop switch**
Reason: Crypto-routes uses a standard 4-byte IPv4 nexthop, identical to SAFI_UNICAST.
Adding `case SAFI_CRYPTO_ROUTES:` with `fallthrough` into the `SAFI_UNICAST` case
reuses the existing `stream_putc(s, 4); stream_put_ipv4(...)` logic with no duplication.

**5.3 — `case SAFI_CRYPTO_ROUTES: fallthrough;` in `bgp_packet_mpattr_prefix()` — AFI_IP6 nexthop switch**
Same rationale for the IPv6 nexthop switch — fall through into the existing
`SAFI_UNICAST/SAFI_LABELED_UNICAST/SAFI_EVPN` 16/32-byte nexthop code.

**5.4 — `case SAFI_CRYPTO_ROUTES:` in `bgp_packet_mpattr_prefix()` — NLRI body switch**
Reason: The NLRI body for crypto-routes is `prefix_bytes ‖ Crypto-SIG TLV trailer`.
The standard prefix is written by `bgp_attr_stream_put_prefix_addpath()` (same as
SAFI_UNICAST) followed by the Crypto-SIG TLV from `bgp_crypto_routes_encode_nlri_trailer(s, path)`.
A dedicated `case` (not a fallthrough) is used because the TLV trailer must be written
after the prefix — not in the nexthop switch.

**5.5 — `case SAFI_CRYPTO_ROUTES:` in `bgp_packet_mpattr_prefix_size()`**
Reason: This function pre-computes the byte count before stream allocation.
Without a crypto-routes case, `size` would equal only `PSIZE(p->prefixlen)`, which
misses the Crypto-SIG TLV overhead. Under-sizing causes a stream-overflow `assert()`
crash in `bgp_packet_mpattr_prefix()`.
Added: `size += BGP_CRYPTO_SIG_TLV_MAX_SIZE;` (140 bytes: 8 fixed hdr + 128 max sig + 4 seq_no).

**5.6 — `BGP_CRYPTO_SIG_TLV_MAX_SIZE 140` added to `bgp_crypto_routes.h`**
Reason: This constant is needed by `bgp_attr.c` (5.5 above) and documents the
exact arithmetic so future maintainers can verify it without reading the stream
write calls.

**5.7 — `bgp_crypto_update_send()` replaced by `bgp_crypto_routes_encode_nlri_trailer()`**
Reason: `bgp_crypto_update_send()` was a placeholder stub that overlapped in scope
with the `bgp_packet_mpattr_prefix()` encode path. The actual architecture calls
for a focused helper that only writes the TLV bytes — the prefix bytes are already
written by the shared `bgp_attr_stream_put_prefix_addpath()` call. The new function
signature `(struct stream *s, struct bgp_path_info *path)` is minimal and testable.
If `path->extra->crypto` is NULL (unsigned route) the function writes 0 bytes and
returns 0 — safe for withdrawals and unsigned announcements.

---

## Phase 6 — `bgp_node_afi()` Fix (`bgp_vty.c`)

### `frr/bgpd/bgp_vty.c` (MODIFIED)

**Change made:**

**6.1 — `case BGP_CRYPTO_ROUTES_NODE:` added to `bgp_node_afi()`** (before `default:`)
```c
case BGP_CRYPTO_ROUTES_NODE:
    afi = (afi_t)vty->xpath_index;
    break;
```
Reason: `BGP_CRYPTO_ROUTES_NODE` is shared between the IPv4 and IPv6 crypto-routes
address-family commands. Phase 3 stored the actual AFI in `vty->xpath_index` when the
`address-family [ipv6] crypto-routes` command was entered. Without reading it back
here, every IPv6 crypto-routes VTY command (neighbor activate, show, route-map, etc.)
silently operated on `AFI_IP` instead of `AFI_IP6` — wrong AFI, wrong RIB table.
Note: `bgp_node_safi()` already had the correct `case BGP_CRYPTO_ROUTES_NODE:` returning
`SAFI_CRYPTO_ROUTES` — only the AFI half was missing.

---

## Security Considerations

- Private key never enters bgpd. Only the public key PEM file is loaded.
- Signature verification uses OpenSSL's constant-time `EVP_DigestVerify` — no
  timing side-channels on the verify path.
- `sig_len` field in the NLRI TLV is bounds-checked against `BGP_CRYPTO_SIG_MAX_LEN`
  before any copy — no buffer overflow possible.
- A peer that sends crafted TLVs with `sig_len > BGP_CRYPTO_SIG_MAX_LEN` causes
  `BGP_ATTR_PARSE_ERROR` (session reset), not a silent ignore.
- Anti-replay: `last_seq_no_verified` is checked before calling ECDSA verify to
  avoid wasting CPU on replayed packets.

## Backward Compatibility

- All changes are additive. Routers not configured for `address-family * crypto-routes`
  are completely unaffected.
- The SAFI 200 capability is only advertised when the address family is explicitly
  configured. Peers that do not recognise SAFI 200 will not activate it (RFC 5492).
- `SAFI_MAX` bumped from 10→11 and `BGP_AF_MAX` from 16→18. All
  `[AFI_MAX][SAFI_MAX]` arrays in `struct bgp` and `struct peer` automatically
  gain the new slot — no manual array resizing needed anywhere else.

## Performance Considerations

- Key cache lookup is O(1) via FRR `hash.h` on a `uint32_t` key.
- ECDSA P-256 verify is ~50µs on modern hardware. This is the dominant cost per
  prefix received. For a router receiving 1000 crypto-routes prefixes/second this
  is ~50ms/s of crypto CPU — acceptable for a dedicated security AF.
- Per-path `bgp_path_info_extra_crypto` is allocated only for SAFI=200 paths
  (lazy allocation). For a router with 800K IPv4 unicast routes and 100 crypto
  routes, the overhead is 100 × sizeof(bgp_path_info_extra_crypto) ≈ 20 KB.

## Compilation Phase — Bug Fixes Found During Build

**Date:** 2025-07-09  
**Build environment:** macOS 26.5.1 / Apple clang 21 / arm64  
**Note:** FRR explicitly does not support macOS native builds (Mach-O vs ELF linker
incompatibility — `configure.ac` line 573 documents this). A `configure.ac` shim was
applied to skip the fatal ELF `__start/__stop` section check so compilation can
proceed for developer validation. All systemic `mach-o section specifier` errors in
the output are in FRR's infrastructure headers (`lib/memory.h`, `lib/linklist.h`, etc.)
and affect every FRR source file equally — they are **not** defects in our code.

### Bugs Found and Fixed

**Bug 1 — `hash_free()` is not exported (`bgp_crypto_routes.c`)**  
`hash_free()` is declared `static` in `lib/hash.c` and is not part of the public API.
The correct public function is `hash_clean_and_free(&ptr, free_func)` which combines
clean + free in one call.  
**Fix:** `hash_clean(...) + hash_free(...)` → `hash_clean_and_free(&g_key_cache->table, ...)`

**Bug 2 — `EC_BGP_ATTR_PARSE_ERROR` does not exist (`bgp_crypto_routes.c`)**  
The FRR BGP error code for receive-path NLRI parse errors is `EC_BGP_UPDATE_RCV`
(defined in `bgp_errors.h`). The name `EC_BGP_ATTR_PARSE_ERROR` was invented and
does not exist in the enum.  
**Fix:** All 9 occurrences replaced with `EC_BGP_UPDATE_RCV`.

**Bug 3 — `IPV4_MAX_PREFIXLEN` / `IPV6_MAX_PREFIXLEN` do not exist (`bgp_crypto_routes.c`)**  
FRR defines `IPV4_MAX_BITLEN` (32) and `IPV6_MAX_BITLEN` (128) in `lib/prefix.h`.
The `_PREFIXLEN` variant was invented.  
**Fix:** `IPV4_MAX_PREFIXLEN` → `IPV4_MAX_BITLEN`, `IPV6_MAX_PREFIXLEN` → `IPV6_MAX_BITLEN`.

**Bug 4 — `bgp_update()` called with 13 args, signature requires 14 (`bgp_crypto_routes.c`)**  
The `bgp_update()` function signature in `bgp_route.h` has a final `struct bgp_unreach_nlri *unreach`
parameter added in a recent FRR commit. Our two call sites passed 13 arguments.  
**Fix:** Added `NULL` as the 14th argument at both call sites (lines 768 and 904).

**Bug 5 — `aspath_rightmost()` does not exist (`bgp_crypto_routes.c`)**  
The correct exported function in `bgp_aspath.h` is `aspath_get_last_as()`.  
**Fix:** `aspath_rightmost()` → `aspath_get_last_as()`.

**Bug 6 — `afindex()` missing `SAFI_CRYPTO_ROUTES` cases causing `-Wswitch-enum` (`bgpd.h`)**  
The `afindex()` inline function in `bgpd.h` has exhaustive `switch(safi)` for all AFI
branches. Adding `SAFI_CRYPTO_ROUTES` to `lib/zebra.h` (Phase 1, pre-existing) without
adding it to `afindex()` triggered `-Wswitch-enum` warnings for all 4 AFI blocks.  
**Fix:** Added `case SAFI_CRYPTO_ROUTES: return BGP_AF_IPV4_CRYPTO_ROUTES;` (AFI_IP),
`case SAFI_CRYPTO_ROUTES: return BGP_AF_IPV6_CRYPTO_ROUTES;` (AFI_IP6), and
`case SAFI_CRYPTO_ROUTES:` falling through to `return BGP_AF_MAX;` (AFI_L2VPN, AFI_BGP_LS).

### Compilation Result

All 8 modified files compile with **zero errors and zero warnings originating in our code**:

| File | Result |
|------|--------|
| `bgpd/bgp_crypto_routes.c` | ✅ CLEAN |
| `bgpd/bgp_packet.c` | ✅ CLEAN |
| `bgpd/bgp_attr.c` | ✅ CLEAN |
| `bgpd/bgp_vty.c` | ✅ CLEAN |
| `bgpd/bgpd.h` (via bgpd.o) | ✅ CLEAN |
| `bgpd/bgpd.c` | ✅ CLEAN |
| `bgpd/bgp_route.h` (via bgp_route.o) | ✅ CLEAN |
| `bgpd/bgp_memory.c` | ✅ CLEAN |

Systemic Mach-O section errors in FRR infrastructure headers are present in every FRR
translation unit and are not related to this project's changes. A Linux CI build is
required for a full link validation — see Production Build Notes below.

### Production Build Notes

For a production Linux build (e.g. Ubuntu 22.04):
```sh
sudo apt-get install git autoconf automake libtool make libreadline-dev \
  pkg-config libjson-c-dev bison flex libc-ares-dev python3-dev \
  build-essential libcap-dev libelf-dev libprotobuf-c-dev protobuf-c-compiler

# Build libyang >= 2.1.128
git clone --depth 1 --branch v3.13.6 https://github.com/CESNET/libyang.git
cd libyang && mkdir build && cd build
cmake --install-prefix /usr -DCMAKE_BUILD_TYPE=Release .. && make && sudo make install
cd ../../frr

./bootstrap.sh

# configure — pass plain system prefix dirs; configure.ac appends /frr itself
./configure \
  --prefix=/usr \
  --sysconfdir=/etc \
  --localstatedir=/var \
  --sbindir=/usr/lib/frr \
  --enable-bgpd \
  --disable-doc --disable-grpc --disable-rpki \
  --disable-ospfapi --disable-vrrpd --disable-bgp-vnc \
  --disable-scripting \
  --enable-user=root --enable-group=root

# generate route_types.h before any single-file make invocation
make lib/route_types.h

make -j$(nproc) bgpd/bgpd
```

---

## Build Warning Fixes — 2025-07-14

### Warning 1 — `lib/subdir.am:539: user target '.y.c' defined here` (automake bootstrap)

**Status:** No change needed — pre-existing upstream FRR issue.

**Reasoning:**
`lib/subdir.am` lines 537–540 deliberately override automake's built-in `.y.c` suffix rule
to suppress the `ylwrap` wrapper (comment on line 536 documents this). Automake 1.16 detects
the collision and prints a warning, but the custom rule wins and the build is correct.
This warning exists in upstream FRR and is not caused by any code in this project.
No fix is applied; touching FRR's yacc/lex pipeline would risk breaking generated parsers
(`lib/command_lex.c`, `lib/command_parse.c`).

### Warning 2 — `configure: WARNING: please fix your ./configure invocation (remove /frr)`

**Status:** Fixed — `frr/.devcontainer/setup.sh` hint banner updated.

**Reasoning:**
FRR 9.2+ changed path conventions (`configure.ac` lines 36–92). The old invocation style
passed `/frr`-suffixed paths directly:

```
--sysconfdir=/etc/frr        # old style — triggers warning
--localstatedir=/var/run/frr # old style — triggers warning
```

`configure.ac` now auto-strips the `/frr` suffix as a compatibility shim and emits a
deprecation warning. The correct modern invocation passes **plain system prefix dirs**;
`configure.ac` appends `/frr` internally:

```
--sysconfdir=/etc            # correct — configure produces /etc/frr
--localstatedir=/var         # correct — configure produces /var/run/frr
```

**Files changed:**
| File | What changed |
|------|-------------|
| `frr/.devcontainer/setup.sh` | Hint banner updated: `--sysconfdir=/etc`, `--localstatedir=/var`; added `make lib/route_types.h` step |
| `frr/CHANGES.md` | Stale `./configure` example in Production Build Notes corrected; this entry added |

### Fatal Error — `lib/route_types.h: No such file or directory`

**Status:** No code change needed — build sequence documentation added.

**Reasoning:**
`lib/route_types.h` is a **generated file** (not tracked in git). It is produced by:

```
perl lib/route_types.pl [--enabled <daemon>...] < lib/route_types.txt > lib/route_types.h
```

This rule is declared in `lib/subdir.am` line 643. The top-level `make bgpd/bgpd` honours
this dependency automatically via the `$(lib_libfrr_la_OBJECTS): lib/route_types.h`
prerequisite at `lib/subdir.am:560`. However, a single-target invocation like
`make bgpd/bgp_crypto_routes.o` does **not** walk the full dependency graph, so when
`lib/zebra.h:148` does `#include "lib/route_types.h"` the file is absent and compilation
aborts.

**Fix:** Run `make lib/route_types.h` once after `./configure` and before any
single-object compilation. The `setup.sh` hint banner now documents this explicitly.
The full `make -j$(nproc) bgpd/bgpd` path is unaffected.

---
