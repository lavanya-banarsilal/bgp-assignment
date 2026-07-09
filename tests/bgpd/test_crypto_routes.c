// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * Unit tests for BGP crypto-routes SAFI (SAFI 241).
 *
 * Tests the wire-format encode/decode path introduced in
 * bgpd/bgp_crypto_routes.c without requiring a live network.
 *
 * Pattern follows tests/bgpd/test_mp_attr.c — a self-contained C program
 * that prints "[PASS]" / "[FAIL]" lines consumed by the Python runner.
 *
 * What is tested:
 *  T1  TLV encode: bgp_crypto_routes_encode_nlri_trailer writes the correct
 *      byte sequence for a known signature, key_id, algo, and seq_no.
 *  T2  TLV encode: returns 0 (writes nothing) when path->extra->crypto is NULL.
 *  T3  TLV encode: returns 0 when sig_len == 0 (unsigned route).
 *  T4  NLRI parse: bgp_nlri_parse_crypto_routes correctly decodes a
 *      hand-crafted NLRI buffer containing one IPv4 prefix + valid TLV.
 *  T5  NLRI parse: returns BGP_NLRI_PARSE_ERROR_PACKET_OVERFLOW when the
 *      TLV header is truncated.
 *  T6  NLRI parse: returns BGP_NLRI_PARSE_ERROR_PACKET_OVERFLOW when
 *      sig_len points beyond the buffer end.
 *  T7  NLRI parse: returns BGP_NLRI_PARSE_ERROR_PACKET_OVERFLOW when
 *      TLV type byte is wrong (not 0xCE).
 *  T8  SAFI constants: SAFI_CRYPTO_ROUTES == 10, IANA_SAFI_CRYPTO_ROUTES == 241.
 *  T9  TLV type constant: BGP_CRYPTO_SIG_TLV_TYPE == 0xCE.
 *  T10 afindex: AFI_IP and AFI_IP6 return distinct, in-range indices.
 *
 * Copyright (C) 2025 BGP_ASSIGNMENT Project
 */

#include <zebra.h>

#include "stream.h"
#include "memory.h"
#include "prefix.h"
#include "log.h"
#include "lib/iana_afi.h"

#include "bgpd/bgpd.h"
#include "bgpd/bgp_attr.h"
#include "bgpd/bgp_route.h"
#include "bgpd/bgp_packet.h"
#include "bgpd/bgp_debug.h"
#include "bgpd/bgp_crypto_routes.h"

/* ── Linker stubs (needed to satisfy libbgp references) ─────────────────── */
struct zebra_privs_t bgpd_privs = {};
struct event_loop *master = NULL;

/* ── Test helpers ────────────────────────────────────────────────────────── */
#define VT100_GREEN "\x1b[32m"
#define VT100_RED   "\x1b[31m"
#define VT100_RESET "\x1b[0m"

static int failed = 0;
static int total  = 0;
static int tty    = 0;

/*
 * test_result() — core PASS/FAIL printer.
 *
 * Output format (non-TTY):
 *   [PASS]  <name>
 *   [FAIL]  <name>
 *
 * TTY adds green/red colour.  Using "PASS"/"FAIL" rather than "OK"/"FAILED"
 * so the result is self-explanatory at a glance.
 */
static void test_result(const char *name, int ok)
{
	total++;
	if (ok) {
		if (tty)
			fprintf(stdout, "%s[PASS]%s  %s\n",
				VT100_GREEN, VT100_RESET, name);
		else
			fprintf(stdout, "[PASS]  %s\n", name);
	} else {
		if (tty)
			fprintf(stderr, "%s[FAIL]%s  %s\n",
				VT100_RED, VT100_RESET, name);
		else
			fprintf(stderr, "[FAIL]  %s\n", name);
		failed++;
	}
}

#define PASS(name) test_result(name, 1)
#define FAIL(name) test_result(name, 0)
#define CHECK(name, expr) test_result(name, (expr))

/* ── T1: TLV encode — correct bytes written ─────────────────────────────── */
/*
 * What it does:
 *   Builds a fake bgp_path_info with known values (key_id=0xDEADBEEF,
 *   algo=ECDSA_P256, sig={0xAA,0xBB,0xCC,0xDD}, seq=42) and calls
 *   bgp_crypto_routes_encode_nlri_trailer().  Verifies every byte at
 *   every offset in the output stream.
 *
 * What it guards:
 *   An off-by-one, wrong byte order, or missing field in the TLV encoder
 *   means every receiver will fail to parse the NLRI.  This test pins the
 *   exact wire format so any regression is caught immediately.
 *
 * Expected: 16 bytes written in order:
 *   CE | DEADBEEF | 01 | 0004 | AABBCCDD | 0000002A
 */
static void test_tlv_encode_basic(void)
{
	printf("\nT1  TLV encoder writes exact byte sequence for known input\n");
	printf("    (verifies correct wire format: type|key_id|algo|sig_len|sig|seq)\n");

	struct bgp_path_info_extra_crypto crypto = {
		.key_id     = 0xDEADBEEF,
		.sig_algo   = BGP_CRYPTO_ALGO_ECDSA_P256,
		.sig_len    = 4,
		.sig        = { 0xAA, 0xBB, 0xCC, 0xDD },
		.sequence_no = 42,
	};
	struct bgp_path_info_extra extra = { .crypto = &crypto };
	struct bgp_path_info path = { .extra = &extra };

	struct stream *s = stream_new(256);
	int written = bgp_crypto_routes_encode_nlri_trailer(s, &path);

	/*
	 * Expected layout (16 bytes total):
	 *   [0]       0xCE              (TLV type)
	 *   [1..4]    DE AD BE EF       (key_id, big-endian)
	 *   [5]       0x01              (algo = ECDSA_P256)
	 *   [6..7]    00 04             (sig_len = 4)
	 *   [8..11]   AA BB CC DD       (sig bytes)
	 *   [12..15]  00 00 00 2A       (seq_no = 42)
	 */
	int ok = 1;
	ok &= (written == 16);
	if (ok) {
		uint8_t *buf = STREAM_DATA(s);
		ok &= (buf[0] == 0xCE);
		ok &= (buf[1] == 0xDE && buf[2] == 0xAD &&
		       buf[3] == 0xBE && buf[4] == 0xEF);
		ok &= (buf[5] == 0x01);
		ok &= (buf[6] == 0x00 && buf[7] == 0x04);
		ok &= (buf[8]  == 0xAA && buf[9]  == 0xBB &&
		       buf[10] == 0xCC && buf[11] == 0xDD);
		ok &= (buf[12] == 0x00 && buf[13] == 0x00 &&
		       buf[14] == 0x00 && buf[15] == 0x2A);
	}
	stream_free(s);
	test_result("T1: encoder writes 16 bytes with correct type/key_id/algo/sig/seq", ok);
}

/* ── T2: TLV encode — NULL path writes nothing ──────────────────────────── */
/*
 * What it does:
 *   Calls bgp_crypto_routes_encode_nlri_trailer() with a NULL path pointer.
 *   Checks return value is 0 and the output stream remains empty.
 *
 * What it guards:
 *   Withdrawal paths and routes not yet signed pass NULL.  The encoder must
 *   not crash or write garbage bytes — unsigned routes must still be
 *   encodable so the caller does not assert.
 */
static void test_tlv_encode_null_path(void)
{
	printf("\nT2  TLV encoder writes nothing (returns 0) when path is NULL\n");
	printf("    (guards against crash on withdrawal paths or unsigned routes)\n");

	struct stream *s = stream_new(64);
	int written = bgp_crypto_routes_encode_nlri_trailer(s, NULL);
	CHECK("T2: encoder returns 0 for NULL path", written == 0);
	CHECK("T2: encoder writes 0 bytes to stream for NULL path",
	      stream_get_endp(s) == 0);
	stream_free(s);
}

/* ── T3: TLV encode — sig_len==0 writes nothing ─────────────────────────── */
/*
 * What it does:
 *   Creates a crypto struct with sig_len=0 (route not yet signed) and calls
 *   the encoder.  Confirms nothing is written to the output stream.
 *
 * What it guards:
 *   An originator that has not configured a private key yet sends a bare
 *   NLRI with no TLV.  The receiver classifies it as SIG_NONE and keeps
 *   it out of the FIB — the correct safe default.  The encoder must not
 *   write a partial TLV in this case.
 */
static void test_tlv_encode_unsigned(void)
{
	printf("\nT3  TLV encoder writes nothing when sig_len == 0 (unsigned route)\n");
	printf("    (guards against partial TLV when originator has no private key)\n");

	struct bgp_path_info_extra_crypto crypto = {
		.sig_len = 0,
	};
	struct bgp_path_info_extra extra = { .crypto = &crypto };
	struct bgp_path_info path = { .extra = &extra };

	struct stream *s = stream_new(64);
	int written = bgp_crypto_routes_encode_nlri_trailer(s, &path);
	CHECK("T3: encoder returns 0 for sig_len=0 (unsigned route)", written == 0);
	stream_free(s);
}

/* ── Build a raw NLRI buffer for parse tests ─────────────────────────────── */
/*
 * Layout of one complete crypto-routes NLRI entry for 10.0.0.0/8:
 *
 *   prefixlen   1B = 0x08
 *   prefix      1B = 0x0A  (10.x.x.x, only 1 byte for /8)
 *   TLV type    1B = 0xCE
 *   key_id      4B = 00 00 00 01
 *   algo        1B = 0x01
 *   sig_len     2B = 00 04
 *   sig         4B = AA BB CC DD
 *   seq_no      4B = 00 00 00 01
 */
static const uint8_t good_nlri[] = {
	/* prefix length */ 0x08,
	/* prefix bytes  */ 0x0A,
	/* TLV type      */ 0xCE,
	/* key_id        */ 0x00, 0x00, 0x00, 0x01,
	/* algo          */ 0x01,
	/* sig_len       */ 0x00, 0x04,
	/* sig           */ 0xAA, 0xBB, 0xCC, 0xDD,
	/* seq_no        */ 0x00, 0x00, 0x00, 0x01,
};

/* Bad: TLV header truncated (stops after algo byte — missing sig_len) */
static const uint8_t truncated_hdr_nlri[] = {
	0x08, 0x0A,
	0xCE, 0x00, 0x00, 0x00, 0x01, 0x01,
	/* missing sig_len+sig+seq_no */
};

/* Bad: sig_len says 64 bytes but buffer ends after 2 bytes of sig */
static const uint8_t truncated_sig_nlri[] = {
	0x08, 0x0A,
	0xCE, 0x00, 0x00, 0x00, 0x01, 0x01,
	0x00, 0x40, /* sig_len = 64 */
	0xAA, 0xBB, /* only 2 sig bytes — truncated */
};

/* Bad: wrong TLV type byte */
static const uint8_t wrong_type_nlri[] = {
	0x08, 0x0A,
	0xAB, /* wrong type — must be 0xCE */
	0x00, 0x00, 0x00, 0x01, 0x01,
	0x00, 0x04,
	0xAA, 0xBB, 0xCC, 0xDD,
	0x00, 0x00, 0x00, 0x01,
};

static struct bgp_nlri make_nlri(const uint8_t *data, size_t len)
{
	struct bgp_nlri nlri = {
		.afi    = AFI_IP,
		.safi   = SAFI_CRYPTO_ROUTES,
		.nlri   = (uint8_t *)data,
		.length = (uint16_t)len,
	};
	return nlri;
}

/* ── T4: NLRI parse — good buffer, no error ─────────────────────────────── */
/*
 * What it does:
 *   Feeds a hand-crafted 17-byte NLRI for 10.0.0.0/8 with a complete TLV
 *   (key_id=1, algo=0x01, sig_len=4, sig=AABBCCDD, seq=1) through the
 *   parser in withdraw mode (so bgp_update() is not called).
 *
 * What it guards:
 *   The happy-path parse.  Confirms the parser advances through the prefix
 *   bytes and TLV fields correctly without an off-by-one or buffer over-read.
 */
static void test_nlri_parse_good(void)
{
	printf("\nT4  NLRI parser accepts a well-formed buffer (10.0.0.0/8 + complete TLV)\n");
	printf("    (happy-path parse: verifies parser advances through fields correctly)\n");

	struct bgp_nlri nlri = make_nlri(good_nlri, sizeof(good_nlri));
	/*
	 * withdraw=true exercises the withdraw path without calling bgp_update —
	 * it must still return BGP_NLRI_PARSE_OK (no parse error).
	 */
	int rc = bgp_nlri_parse_crypto_routes(NULL, NULL, &nlri, true);
	CHECK("T4: parser returns BGP_NLRI_PARSE_OK for well-formed NLRI",
	      rc == BGP_NLRI_PARSE_OK);
}

/* ── T5: NLRI parse — truncated TLV header ──────────────────────────────── */
/*
 * What it does:
 *   Buffer has the 0xCE type byte + key_id (4B) + algo (1B) but is missing
 *   the mandatory sig_len (2B).  Parser runs in non-withdraw mode.
 *
 * What it guards:
 *   Per RFC 4760 §5, a malformed MP_REACH_NLRI must trigger a BGP NOTIFY
 *   and session reset.  A truncated TLV header must never be silently
 *   accepted — it could mask a security event or lead to mis-parsing.
 */
static void test_nlri_parse_truncated_hdr(void)
{
	printf("\nT5  NLRI parser rejects truncated TLV header (sig_len field missing)\n");
	printf("    (RFC 4760: malformed NLRI must trigger NOTIFY + session reset)\n");

	struct bgp_nlri nlri = make_nlri(truncated_hdr_nlri,
					 sizeof(truncated_hdr_nlri));
	int rc = bgp_nlri_parse_crypto_routes(NULL, NULL, &nlri, false);
	CHECK("T5: parser returns PACKET_OVERFLOW for truncated TLV header",
	      rc == BGP_NLRI_PARSE_ERROR_PACKET_OVERFLOW);
}

/* ── T6: NLRI parse — truncated signature body ──────────────────────────── */
/*
 * What it does:
 *   sig_len field claims 64 bytes but the buffer only contains 2 bytes of
 *   signature.  Parser must detect that reading sig_len bytes would go
 *   past the buffer boundary.
 *
 * What it guards:
 *   Classic buffer over-read attack: a malicious peer sets a large sig_len
 *   to make the router read past the NLRI buffer boundary.  The bounds
 *   check here prevents that.
 */
static void test_nlri_parse_truncated_sig(void)
{
	printf("\nT6  NLRI parser rejects sig_len claiming 64 bytes when only 2 bytes present\n");
	printf("    (guards against buffer over-read: attacker inflates sig_len)\n");

	struct bgp_nlri nlri = make_nlri(truncated_sig_nlri,
					 sizeof(truncated_sig_nlri));
	int rc = bgp_nlri_parse_crypto_routes(NULL, NULL, &nlri, false);
	CHECK("T6: parser returns PACKET_OVERFLOW for truncated signature body",
	      rc == BGP_NLRI_PARSE_ERROR_PACKET_OVERFLOW);
}

/* ── T7: NLRI parse — wrong TLV type byte ───────────────────────────────── */
/*
 * What it does:
 *   First byte after the prefix is 0xAB instead of the expected 0xCE.
 *   Parser must detect the wrong magic byte and reject the NLRI.
 *
 * What it guards:
 *   The TLV type byte (0xCE) is the magic delimiter between the prefix and
 *   the signature data.  A wrong type means the stream is misaligned —
 *   silently reading further would corrupt the parser state or mis-verify
 *   a completely different byte range as a signature.
 */
static void test_nlri_parse_wrong_type(void)
{
	printf("\nT7  NLRI parser rejects wrong TLV type byte (0xAB instead of 0xCE)\n");
	printf("    (guards against stream misalignment from wrong magic byte)\n");

	struct bgp_nlri nlri = make_nlri(wrong_type_nlri,
					 sizeof(wrong_type_nlri));
	int rc = bgp_nlri_parse_crypto_routes(NULL, NULL, &nlri, false);
	CHECK("T7: parser returns PACKET_OVERFLOW for wrong TLV type byte",
	      rc == BGP_NLRI_PARSE_ERROR_PACKET_OVERFLOW);
}

/* ── T8: SAFI and IANA SAFI constants ───────────────────────────────────── */
/*
 * What it does:
 *   Compile-time constant checks: SAFI_CRYPTO_ROUTES (internal FRR array
 *   index) == 10 and IANA_SAFI_CRYPTO_ROUTES (IANA wire value) == 241.
 *
 * What it guards:
 *   The two SAFI values serve different roles.  The internal index is used
 *   for array indexing into the RIB (bgp->rib[afi][safi]); the IANA value
 *   goes on the wire in MP_REACH_NLRI.  Confusing them causes routes to be
 *   installed into the wrong table or sent with the wrong SAFI on the wire.
 */
static void test_safi_constants(void)
{
	printf("\nT8  SAFI constants: internal index == 10, IANA wire value == 241\n");
	printf("    (guards against confusion between RIB array index and wire SAFI)\n");

	CHECK("T8: SAFI_CRYPTO_ROUTES (internal index) == 10",
	      SAFI_CRYPTO_ROUTES == 10);
	CHECK("T8: IANA_SAFI_CRYPTO_ROUTES (wire value) == 241",
	      IANA_SAFI_CRYPTO_ROUTES == 241);
}

/* ── T9: TLV type constant ──────────────────────────────────────────────── */
/*
 * What it does:
 *   Asserts BGP_CRYPTO_SIG_TLV_TYPE == 0xCE.
 *
 * What it guards:
 *   0xCE is in the private/experimental range (no IANA registration needed).
 *   This test pins the magic byte so a refactor or merge cannot silently
 *   change it and break the wire format.
 */
static void test_tlv_type_constant(void)
{
	printf("\nT9  TLV type magic byte must be 0xCE (private/experimental range)\n");
	printf("    (pins the wire magic byte so it cannot be accidentally changed)\n");

	CHECK("T9: BGP_CRYPTO_SIG_TLV_TYPE == 0xCE",
	      BGP_CRYPTO_SIG_TLV_TYPE == 0xCE);
}

/* ── T10: afindex returns distinct in-range values ──────────────────────── */
/*
 * What it does:
 *   Calls afindex(AFI_IP, SAFI_CRYPTO_ROUTES) and
 *   afindex(AFI_IP6, SAFI_CRYPTO_ROUTES).  Checks both are >= 0,
 *   < BGP_AF_MAX, and different from each other.
 *
 * What it guards:
 *   FRR uses afindex() to slot into the per-instance RIB array
 *   (bgp->rib[afi][safi]).  If the two AFIs return the same index, the
 *   IPv4 and IPv6 crypto-route tables collide and corrupt each other.
 *   Out-of-range values would cause an array out-of-bounds access.
 */
static void test_afindex(void)
{
	printf("\nT10 AFI_IP and AFI_IP6 afindex values are distinct and in range\n");
	printf("    (guards against IPv4/IPv6 RIB array collision or out-of-bounds)\n");

	int v4 = afindex(AFI_IP,  SAFI_CRYPTO_ROUTES);
	int v6 = afindex(AFI_IP6, SAFI_CRYPTO_ROUTES);
	CHECK("T10: AFI_IP  SAFI_CRYPTO_ROUTES afindex is in [0, BGP_AF_MAX)",
	      v4 >= 0 && v4 < BGP_AF_MAX);
	CHECK("T10: AFI_IP6 SAFI_CRYPTO_ROUTES afindex is in [0, BGP_AF_MAX)",
	      v6 >= 0 && v6 < BGP_AF_MAX);
	CHECK("T10: AFI_IP and AFI_IP6 afindex values are distinct (no table collision)",
	      v4 != v6);
}

/* ── main ────────────────────────────────────────────────────────────────── */
int main(int argc, char **argv)
{
	tty = isatty(fileno(stdout));

	printf("============================================================\n");
	printf("  BGP crypto-routes SAFI 241 — wire-format unit tests\n");
	printf("  Tests TLV encoder, NLRI parser, and compile-time constants\n");
	printf("  No live network required.\n");
	printf("============================================================\n");

	/* Minimal FRR init required by libbgp */
	bgp_master_init(NULL, BGP_SOCKET_SNDBUF_SIZE, list_new());
	bgp_option_set(BGP_OPT_NO_LISTEN);

	/* Initialise crypto-routes key cache (exercised by T4–T7) */
	bgp_crypto_routes_init();

	/* Run all tests */
	test_tlv_encode_basic();
	test_tlv_encode_null_path();
	test_tlv_encode_unsigned();
	test_nlri_parse_good();
	test_nlri_parse_truncated_hdr();
	test_nlri_parse_truncated_sig();
	test_nlri_parse_wrong_type();
	test_safi_constants();
	test_tlv_type_constant();
	test_afindex();

	bgp_crypto_routes_finish();

	printf("\n============================================================\n");
	if (failed)
		fprintf(stderr, "  Result : %d/%d TEST(S) FAILED\n", failed, total);
	else
		fprintf(stdout, "  Result : ALL %d TESTS PASSED\n", total);
	printf("============================================================\n");

	return failed ? 1 : 0;
}
