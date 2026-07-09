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
 * Test cases:
 *   T-SV1  Sign 10.0.0.0/8, verify with correct key   -> PASS (expect valid)
 *   T-SV2  Sign 10.0.0.0/8, tamper 1 byte of sig      -> PASS (expect rejected)
 *   T-SV3  Sign 10.0.0.0/8, tamper prefix byte         -> PASS (expect rejected)
 *   T-SV4  Sign 10.0.0.0/8, verify with wrong key      -> PASS (expect rejected)
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
static int g_total  = 0;

/*
 * check() — print a single assertion result as PASS or FAIL.
 *
 * Output format:
 *   [PASS]  <name>
 *   [FAIL]  <name>
 *
 * Using "PASS"/"FAIL" (not "OK"/"FAILED") so the output is immediately
 * readable without knowing the convention.
 */
static void check(const char *name, int ok)
{
	g_total++;
	if (ok)
		printf("  [PASS]  %s\n", name);
	else {
		fprintf(stderr, "  [FAIL]  %s\n", name);
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
 *
 * This is the exact buffer that bgp_crypto_verify() feeds to
 * EVP_DigestVerify() in production — so these tests exercise the real path.
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
 * Returns 0 on success, -1 on failure.
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
	printf("============================================================\n");
	printf("  BGP crypto-routes: ECDSA P-256 sign/verify unit tests\n");
	printf("  Prefix: 10.0.0.0/8  |  AS: 65001  |  seq: 1\n");
	printf("  Signed data = prefix_bytes || origin_asn || sequence_no\n");
	printf("============================================================\n\n");

	/* ── Setup: generate two independent ECDSA P-256 key pairs ──────── */
	EVP_PKEY *keypair = generate_ec_keypair();
	if (!keypair) {
		fprintf(stderr, "FATAL: ECDSA P-256 key generation failed (keypair 1)\n");
		return 1;
	}

	/*
	 * T-SV4 requires a second, completely independent key pair to simulate
	 * an attacker-controlled key that is NOT in our public-key cache.
	 */
	EVP_PKEY *wrong_keypair = generate_ec_keypair();
	if (!wrong_keypair) {
		fprintf(stderr, "FATAL: ECDSA P-256 key generation failed (keypair 2)\n");
		EVP_PKEY_free(keypair);
		return 1;
	}
	printf("  Setup   : Two independent ECDSA P-256 key pairs generated in memory.\n\n");

	/* Shared test parameters */
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
	 * T-SV1: Happy path — correct key verifies correctly signed data.
	 *
	 * What it does: calls EVP_DigestVerify with the original signature
	 * and the matching public key. No tampering of any kind.
	 *
	 * What it guards: the basic sign→verify round-trip works end to end.
	 * If this fails, no legitimate BGP UPDATE from any router can ever
	 * be accepted.
	 *
	 * Expected result: EVP_DigestVerify returns 1 (VALID).
	 * ───────────────────────────────────────────────────────────────── */
	printf("T-SV1  Correct signature over 10.0.0.0/8 must verify successfully\n");
	printf("       (proves the sign->verify round-trip works end to end)\n");
	{
		int rc = do_verify(keypair, signed_data, signed_data_len,
				   sig, sig_len);
		check("T-SV1: EVP_DigestVerify returns 1 — signature accepted", rc == 1);
	}
	printf("\n");

	/* ─────────────────────────────────────────────────────────────────
	 * T-SV2: Tampered signature byte — must be rejected.
	 *
	 * What it does: copies the valid signature, flips all bits in
	 * sig[0] (XOR 0xFF), then verifies with the correct key and
	 * unchanged data.
	 *
	 * What it guards: a corrupted UPDATE packet, or an attacker who
	 * modifies the signature bytes in transit. The router must set
	 * sig_state = SIG_INVALID and block FIB installation.
	 *
	 * Expected result: EVP_DigestVerify returns != 1 (INVALID).
	 * ───────────────────────────────────────────────────────────────── */
	printf("T-SV2  Tampered signature byte (sig[0] XOR 0xFF) must be rejected\n");
	printf("       (guards against corrupted UPDATE or in-transit modification)\n");
	{
		uint8_t tampered_sig[128];
		memcpy(tampered_sig, sig, sig_len);
		tampered_sig[0] ^= 0xFF;

		int rc = do_verify(keypair, signed_data, signed_data_len,
				   tampered_sig, sig_len);
		check("T-SV2: EVP_DigestVerify returns !=1 — tampered signature rejected", rc != 1);
		clear_openssl_err();
	}
	printf("\n");

	/* ─────────────────────────────────────────────────────────────────
	 * T-SV3: Tampered prefix — must be rejected (prefix hijack test).
	 *
	 * What it does: rebuilds signed_data with prefix 11.0.0.0/8
	 * (byte 0x0A changed to 0x0B), then verifies the *original*
	 * signature (produced for 10.0.0.0/8) against this new data.
	 *
	 * What it guards: prefix hijacking — an attacker cannot take a valid
	 * signature for 10.0.0.0/8 and reuse it to authenticate 11.0.0.0/8
	 * because the prefix bytes are part of the signed data.
	 *
	 * Expected result: EVP_DigestVerify returns != 1 (INVALID).
	 * ───────────────────────────────────────────────────────────────── */
	printf("T-SV3  Signature for 10.0.0.0/8 must not verify for 11.0.0.0/8\n");
	printf("       (guards against prefix hijack: sig is bound to exact prefix)\n");
	{
		uint8_t tampered_addr[4] = { 0x0B, 0x00, 0x00, 0x00 };
		uint8_t tampered_data[40];
		size_t  tampered_len = build_signed_data(tampered_addr, prefixlen,
							 origin_asn, seq_no,
							 tampered_data);

		int rc = do_verify(keypair, tampered_data, tampered_len,
				   sig, sig_len);
		check("T-SV3: EVP_DigestVerify returns !=1 — tampered prefix rejected", rc != 1);
		clear_openssl_err();
	}
	printf("\n");

	/* ─────────────────────────────────────────────────────────────────
	 * T-SV4: Wrong public key — must be rejected (cross-AS key attack).
	 *
	 * What it does: verifies the original (valid) signature with
	 * wrong_keypair's public key instead of the correct keypair.
	 *
	 * What it guards: in production this maps to a BGP peer sending a
	 * signature produced by a key that is NOT in our provisioned cache
	 * (e.g. forged by an attacker, or belonging to a different AS).
	 * bgp_crypto_key_lookup() would return a cache entry whose pkey is
	 * unrelated to the signing key → EVP_DigestVerify must reject it
	 * and bgp_crypto_verify() must set sig_state = SIG_INVALID.
	 *
	 * Expected result: EVP_DigestVerify returns != 1 (INVALID).
	 * ───────────────────────────────────────────────────────────────── */
	printf("T-SV4  Correct signature verified with a different (wrong) public key must be rejected\n");
	printf("       (guards against forged key / key not in provisioned cache)\n");
	{
		int rc = do_verify(wrong_keypair, signed_data, signed_data_len,
				   sig, sig_len);
		check("T-SV4: EVP_DigestVerify returns !=1 — wrong public key rejected", rc != 1);
		clear_openssl_err();
	}
	printf("\n");

	/* ── cleanup + summary ───────────────────────────────────────────── */
	EVP_PKEY_free(wrong_keypair);
	EVP_PKEY_free(keypair);

	printf("============================================================\n");
	if (g_failed == 0)
		printf("  Result : ALL %d TESTS PASSED\n", g_total);
	else
		fprintf(stderr, "  Result : %d/%d TEST(S) FAILED\n", g_failed, g_total);
	printf("============================================================\n");

	return g_failed ? 1 : 0;
}
