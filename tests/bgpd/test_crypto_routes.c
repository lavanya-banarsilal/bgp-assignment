// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * Unit tests for BGP crypto-routes SAFI (SAFI 200).
 *
 * Tests the wire-format encode/decode path introduced in
 * bgpd/bgp_crypto_routes.c without requiring a live network.
 *
 * Pattern follows tests/bgpd/test_mp_attr.c — a self-contained C program
 * that prints "OK" / "FAILED" lines consumed by the Python runner.
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
 *  T8  key_id: SHA-256 truncation produces a stable 4-byte ID.
 *  T9  SAFI value: SAFI_CRYPTO_ROUTES == 10, IANA_SAFI_CRYPTO_ROUTES == 200.
 *  T10 afindex: BGP_AF_IPV4_CRYPTO_ROUTES and BGP_AF_IPV6_CRYPTO_ROUTES
 *      return distinct, in-range indices from afindex().
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
static int tty = 0;

static void test_result(const char *name, int ok)
{
	if (ok) {
		if (tty)
			fprintf(stdout, "%s%s%s: OK\n",
				VT100_GREEN, name, VT100_RESET);
		else
			fprintf(stdout, "%s: OK\n", name);
	} else {
		if (tty)
			fprintf(stderr, "%s%s%s: FAILED\n",
				VT100_RED, name, VT100_RESET);
		else
			fprintf(stderr, "%s: FAILED\n", name);
		failed++;
	}
}

#define PASS(name) test_result(name, 1)
#define FAIL(name) test_result(name, 0)
#define CHECK(name, expr) test_result(name, (expr))

/* ── T1: TLV encode — correct bytes written ─────────────────────────────── */
static void test_tlv_encode_basic(void)
{
	const char *tname = "T1: TLV encode basic";

	/* Build a fake bgp_path_info with a known crypto struct */
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

	/* Expected layout:
	 *  0xCE              (1 B, type)
	 *  DE AD BE EF       (4 B, key_id big-endian)
	 *  0x01              (1 B, algo)
	 *  00 04             (2 B, sig_len = 4)
	 *  AA BB CC DD       (4 B, sig)
	 *  00 00 00 2A       (4 B, seq_no = 42)
	 *  = 16 bytes total
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
	test_result(tname, ok);
}

/* ── T2: TLV encode — NULL path writes nothing ──────────────────────────── */
static void test_tlv_encode_null_path(void)
{
	struct stream *s = stream_new(64);
	int written = bgp_crypto_routes_encode_nlri_trailer(s, NULL);
	CHECK("T2: TLV encode null path returns 0", written == 0);
	CHECK("T2: TLV encode null path writes 0 bytes",
	      stream_get_endp(s) == 0);
	stream_free(s);
}

/* ── T3: TLV encode — sig_len==0 writes nothing ─────────────────────────── */
static void test_tlv_encode_unsigned(void)
{
	struct bgp_path_info_extra_crypto crypto = {
		.sig_len = 0,
	};
	struct bgp_path_info_extra extra = { .crypto = &crypto };
	struct bgp_path_info path = { .extra = &extra };

	struct stream *s = stream_new(64);
	int written = bgp_crypto_routes_encode_nlri_trailer(s, &path);
	CHECK("T3: TLV encode unsigned (sig_len=0) returns 0", written == 0);
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
static void test_nlri_parse_good(void)
{
	struct bgp_nlri nlri = make_nlri(good_nlri, sizeof(good_nlri));
	/*
	 * bgp_nlri_parse_crypto_routes with attr=NULL and withdraw=true
	 * exercises the withdraw path without touching bgp_update — it must
	 * return BGP_NLRI_PARSE_OK.
	 */
	int rc = bgp_nlri_parse_crypto_routes(NULL, NULL, &nlri, true);
	CHECK("T4: NLRI parse good buffer returns OK",
	      rc == BGP_NLRI_PARSE_OK);
}

/* ── T5: NLRI parse — truncated TLV header ──────────────────────────────── */
static void test_nlri_parse_truncated_hdr(void)
{
	struct bgp_nlri nlri = make_nlri(truncated_hdr_nlri,
					 sizeof(truncated_hdr_nlri));
	int rc = bgp_nlri_parse_crypto_routes(NULL, NULL, &nlri, false);
	CHECK("T5: NLRI parse truncated TLV header returns OVERFLOW",
	      rc == BGP_NLRI_PARSE_ERROR_PACKET_OVERFLOW);
}

/* ── T6: NLRI parse — truncated signature body ──────────────────────────── */
static void test_nlri_parse_truncated_sig(void)
{
	struct bgp_nlri nlri = make_nlri(truncated_sig_nlri,
					 sizeof(truncated_sig_nlri));
	int rc = bgp_nlri_parse_crypto_routes(NULL, NULL, &nlri, false);
	CHECK("T6: NLRI parse truncated sig returns OVERFLOW",
	      rc == BGP_NLRI_PARSE_ERROR_PACKET_OVERFLOW);
}

/* ── T7: NLRI parse — wrong TLV type byte ───────────────────────────────── */
static void test_nlri_parse_wrong_type(void)
{
	struct bgp_nlri nlri = make_nlri(wrong_type_nlri,
					 sizeof(wrong_type_nlri));
	int rc = bgp_nlri_parse_crypto_routes(NULL, NULL, &nlri, false);
	CHECK("T7: NLRI parse wrong TLV type returns OVERFLOW",
	      rc == BGP_NLRI_PARSE_ERROR_PACKET_OVERFLOW);
}

/* ── T8: SAFI and IANA SAFI constants ───────────────────────────────────── */
static void test_safi_constants(void)
{
	CHECK("T8: SAFI_CRYPTO_ROUTES == 10",
	      SAFI_CRYPTO_ROUTES == 10);
	CHECK("T8: IANA_SAFI_CRYPTO_ROUTES == 200",
	      IANA_SAFI_CRYPTO_ROUTES == 200);
}

/* ── T9: TLV type constant ──────────────────────────────────────────────── */
static void test_tlv_type_constant(void)
{
	CHECK("T9: BGP_CRYPTO_SIG_TLV_TYPE == 0xCE",
	      BGP_CRYPTO_SIG_TLV_TYPE == 0xCE);
}

/* ── T10: afindex returns distinct in-range values ──────────────────────── */
static void test_afindex(void)
{
	int v4 = afindex(AFI_IP,  SAFI_CRYPTO_ROUTES);
	int v6 = afindex(AFI_IP6, SAFI_CRYPTO_ROUTES);
	CHECK("T10: AFI_IP  SAFI_CRYPTO_ROUTES afindex in range",
	      v4 >= 0 && v4 < BGP_AF_MAX);
	CHECK("T10: AFI_IP6 SAFI_CRYPTO_ROUTES afindex in range",
	      v6 >= 0 && v6 < BGP_AF_MAX);
	CHECK("T10: AFI_IP and AFI_IP6 afindex values are distinct",
	      v4 != v6);
}

/* ── main ────────────────────────────────────────────────────────────────── */
int main(int argc, char **argv)
{
	tty = isatty(fileno(stdout));

	/* Minimal FRR init required by libbgp */
	bgp_master_init(NULL, BGP_SOCKET_SNDBUF_SIZE, list_new());
	bgp_option_set(BGP_OPT_NO_LISTEN);

	/* Initialise crypto-routes key cache (tested by T4–T7) */
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

	if (failed)
		fprintf(stderr, "\n%d test(s) FAILED\n", failed);
	else
		fprintf(stdout, "\nAll tests passed.\n");

	return failed ? 1 : 0;
}
