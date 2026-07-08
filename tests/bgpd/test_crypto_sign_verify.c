// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * Phase 1e — Standalone sign/verify unit test for BGP crypto-routes.
 *
 * Tests ECDSA P-256 sign + verify using exactly the same signed-data
 * layout as bgp_crypto_routes.c:build_signed_data():
 *
 *   signed_data = prefix_bytes (ceil(prefixlen/8) B)
 *              || origin_asn   (4 B, big-endian uint32)
 *              || sequence_no  (4 B, big-endian uint32)
 *
 * This program links ONLY against libcrypto (OpenSSL).
 * It does NOT depend on FRR, libfrr, libbgp, or any FRR headers.
 *
 * Build command (run from the frr/ source root after ./configure):
 *   gcc -o /tmp/test_crypto_sign_verify \
 *       tests/bgpd/test_crypto_sign_verify.c \
 *       -lcrypto
 *
 * Three test cases:
 *   T-SV1  Sign 10.0.0.0/8, verify with correct key   -> PASS (expect valid)
 *   T-SV2  Sign 10.0.0.0/8, tamper 1 byte of sig      -> PASS (expect rejected)
 *   T-SV3  Sign 10.0.0.0/8, tamper prefix byte         -> PASS (expect rejected)
 *
 * Copyright (C) 2025 BGP_ASSIGNMENT Project
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <arpa/inet.h>   /* htonl */

#include <openssl/evp.h>
#include <openssl/err.h>
#include <openssl/ec.h>

/* ── helpers ─────────────────────────────────────────────────────────────── */

static int g_failed = 0;

static void check(const char *name, int ok)
{
	if (ok)
		printf("  %-60s  OK\n", name);
	else {
		fprintf(stderr, "  %-60s  FAILED\n", name);
		g_failed++;
	}
}

static void clear_openssl_err(void)
{
	while (ERR_get_error() != 0)
		;
}

/*
 * Replicate bgp_crypto_routes.c:build_signed_data() exactly.
 *
 * Signed-data layout (matches production code, all big-endian):
 *   prefix_bytes  ceil(prefixlen/8) bytes  (network-order address)
 *   origin_asn    4 bytes uint32_t BE
 *   sequence_no   4 bytes uint32_t BE
 */
static size_t build_signed_data(
		const uint8_t *prefix_addr,
		uint8_t        prefixlen,
		uint32_t       origin_asn,
		uint32_t       seq_no,
		uint8_t       *out)          /* caller provides >= 40 bytes */
{
	size_t   pfx_bytes = (prefixlen + 7) / 8;
	size_t   off       = 0;
	uint32_t asn_be    = htonl(origin_asn);
	uint32_t seq_be    = htonl(seq_no);

	memcpy(out + off, prefix_addr, pfx_bytes);  off += pfx_bytes;
	memcpy(out + off, &asn_be, 4);              off += 4;
	memcpy(out + off, &seq_be, 4);              off += 4;
	return off;
}

/*
 * Generate a fresh ECDSA P-256 key pair in memory.
 * Returns the EVP_PKEY which contains both private and public components.
 * Caller must EVP_PKEY_free() the returned pointer.
 */
static EVP_PKEY *generate_ec_keypair(void)
{
	EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_EC, NULL);
	if (!ctx) return NULL;

	if (EVP_PKEY_keygen_init(ctx) <= 0
	    || EVP_PKEY_CTX_set_ec_paramgen_curve_nid(ctx,
					NID_X9_62_prime256v1) <= 0) {
		EVP_PKEY_CTX_free(ctx);
		return NULL;
	}

	EVP_PKEY *pkey = NULL;
	if (EVP_PKEY_keygen(ctx, &pkey) <= 0) {
		EVP_PKEY_CTX_free(ctx);
		return NULL;
	}
	EVP_PKEY_CTX_free(ctx);
	return pkey;
}

/*
 * Sign data[] with pkey (must carry private component).
 * sig_buf must be at least 128 bytes.
 * Returns actual sig length on success, -1 on failure.
 */
static int do_sign(EVP_PKEY *pkey,
		   const uint8_t *data, size_t data_len,
		   uint8_t *sig_buf, size_t *sig_len)
{
	EVP_MD_CTX *ctx = EVP_MD_CTX_new();
	if (!ctx) return -1;

	/* NULL digest → algorithm default (SHA-256 for ECDSA P-256).
	 * Same idiom used by bgp_crypto_routes.c lines 655 and 666. */
	int ok = (EVP_DigestSignInit(ctx, NULL, NULL, NULL, pkey) == 1)
		&& (EVP_DigestSign(ctx, sig_buf, sig_len, data, data_len) == 1);

	EVP_MD_CTX_free(ctx);
	return ok ? 0 : -1;
}

/*
 * Verify sig over data[] with pkey (public component sufficient).
 * Returns: 1=valid, 0=invalid, -1=openssl error.
 */
static int do_verify(EVP_PKEY *pkey,
		     const uint8_t *data, size_t data_len,
		     const uint8_t *sig,  size_t sig_len)
{
	EVP_MD_CTX *ctx = EVP_MD_CTX_new();
	if (!ctx) return -1;

	if (EVP_DigestVerifyInit(ctx, NULL, NULL, NULL, pkey) != 1) {
		EVP_MD_CTX_free(ctx);
		return -1;
	}
	int rc = EVP_DigestVerify(ctx, sig, sig_len, data, data_len);
	EVP_MD_CTX_free(ctx);
	return rc;   /* 1=ok, 0=bad sig, <0=openssl error */
}

/* ── main ─────────────────────────────────────────────────────────────────── */

int main(void)
{
	printf("=== BGP crypto-routes Phase 1e: sign/verify unit tests ===\n\n");

	/* ── 1. Generate ECDSA P-256 key pair in memory ─────────────────── */
	EVP_PKEY *keypair = generate_ec_keypair();
	if (!keypair) {
		fprintf(stderr, "FATAL: ECDSA P-256 key generation failed\n");
		return 1;
	}
	printf("  Key gen : ECDSA P-256 key pair generated in memory.\n");

	/*
	 * Test parameters — same as the wire-format example in the header:
	 *   Prefix   : 10.0.0.0/8
	 *   Origin AS: 65001
	 *   Seq no   : 1
	 */
	uint8_t  prefix_addr[4] = { 0x0A, 0x00, 0x00, 0x00 };
	uint8_t  prefixlen       = 8;
	uint32_t origin_asn      = 65001;
	uint32_t seq_no          = 1;

	uint8_t signed_data[40];
	size_t  signed_data_len = build_signed_data(prefix_addr, prefixlen,
						    origin_asn, seq_no,
						    signed_data);

	uint8_t sig[128];
	size_t  sig_len = sizeof(sig);

	if (do_sign(keypair, signed_data, signed_data_len, sig, &sig_len) != 0) {
		fprintf(stderr, "FATAL: signing 10.0.0.0/8 failed\n");
		EVP_PKEY_free(keypair);
		return 1;
	}
	printf("  Sign    : 10.0.0.0/8  AS%u  seq %u  -> sig_len=%zu bytes\n\n",
	       origin_asn, seq_no, sig_len);

	/* ─────────────────────────────────────────────────────────────────
	 * T-SV1: verify with unmodified signature and unmodified data
	 * Expected: EVP_DigestVerify returns 1 (VALID)
	 * ───────────────────────────────────────────────────────────────── */
	printf("T-SV1: verify correct signature over 10.0.0.0/8\n");
	{
		int rc = do_verify(keypair, signed_data, signed_data_len,
				   sig, sig_len);
		check("T-SV1: verify returns 1 (signature valid)", rc == 1);
	}
	printf("\n");

	/* ─────────────────────────────────────────────────────────────────
	 * T-SV2: flip all bits in sig[0], then verify
	 * Expected: EVP_DigestVerify returns 0 or negative (INVALID)
	 * ───────────────────────────────────────────────────────────────── */
	printf("T-SV2: tamper sig[0] (XOR 0xFF), verify same data\n");
	{
		uint8_t tampered_sig[128];
		memcpy(tampered_sig, sig, sig_len);
		tampered_sig[0] ^= 0xFF;

		int rc = do_verify(keypair, signed_data, signed_data_len,
				   tampered_sig, sig_len);
		check("T-SV2: verify returns !=1 (tampered sig rejected)", rc != 1);
		clear_openssl_err();
	}
	printf("\n");

	/* ─────────────────────────────────────────────────────────────────
	 * T-SV3: change prefix byte 0x0A -> 0x0B (10.x.x.x -> 11.x.x.x),
	 * rebuild signed_data, then verify against the original signature.
	 * Expected: EVP_DigestVerify returns 0 or negative (INVALID)
	 * ───────────────────────────────────────────────────────────────── */
	printf("T-SV3: tamper prefix (0x0A->0x0B, i.e. 11.0.0.0/8), verify with original sig\n");
	{
		uint8_t tampered_addr[4] = { 0x0B, 0x00, 0x00, 0x00 };
		uint8_t tampered_data[40];
		size_t  tampered_len = build_signed_data(tampered_addr, prefixlen,
							 origin_asn, seq_no,
							 tampered_data);

		int rc = do_verify(keypair, tampered_data, tampered_len,
				   sig, sig_len);
		check("T-SV3: verify returns !=1 (tampered prefix rejected)", rc != 1);
		clear_openssl_err();
	}
	printf("\n");

	/* ── cleanup + summary ───────────────────────────────────────────── */
	EVP_PKEY_free(keypair);

	if (g_failed == 0)
		printf("=== All 3 tests PASSED ===\n");
	else
		fprintf(stderr, "=== %d/3 test(s) FAILED ===\n", g_failed);

	return g_failed ? 1 : 0;
}
