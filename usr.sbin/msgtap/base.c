/*	$OpenBSD$ */

/*
 * Copyright (c) 2021 The University of Queensland
 *
 * Permission to use, copy, modify, and distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */

#include <sys/types.h>
#include <sys/socket.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <vis.h>
#include <time.h>

#include <arpa/inet.h>

#include <msgtap.h>

#include "msgtapc.h"

static void
msgtap_md_pad(const struct msgtap_metadata *md,
    const void *buf, size_t buflen)
{
	printf("%zu bytes", buflen);
}

void
msgtap_md_string(const struct msgtap_metadata *md,
    const void *buf, size_t buflen)
{
	const uint8_t *data = buf;
	size_t i;

	for (i = 0; i < buflen; i++) {
		char dst[8];
		vis(dst, data[i], VIS_TAB|VIS_NL, 0);
		printf("%s", dst);
	}
}

void
msgtap_md_default(const struct msgtap_metadata *md,
    const void *buf, size_t buflen)
{
	const uint8_t *data = buf;
	const char *sep;
	size_t i;

	msgtap_md_string(md, buf, buflen);

	sep = " |";
	for (i = 0; i < buflen; i++) {
		printf("%s%02x", sep, data[i]);
		sep = ":";
	}
	printf("|");
}

static void
msgtap_md_hex(const struct msgtap_metadata *md,
    const void *buf, size_t buflen)
{
	const uint8_t *data = buf;
	size_t i;

	for (i = 0; i < buflen; i++)
		printf("%02x", data[i]);
}

static void
msgtap_md_ts(const struct msgtap_metadata *md,
    const void *buf, size_t buflen)
{
	uint64_t nsec;
	struct timespec ts;
	struct tm *tm;
	char tmbuf[128];

	memcpy(&nsec, buf, sizeof(nsec));
	nsec = betoh64(nsec);

	ts.tv_sec = nsec / 1000000000ULL;
	ts.tv_nsec = nsec % 1000000000ULL;

	tm = gmtime(&ts.tv_sec);

	strftime(tmbuf, sizeof(tmbuf), "%Y-%m-%dT%H:%M:%S", tm);

	printf("%s.%09luZ", tmbuf, ts.tv_nsec);
}

static void
msgtap_md_nsec(const struct msgtap_metadata *md,
    const void *buf, size_t buflen)
{
	uint64_t nsec;
	memcpy(&nsec, buf, sizeof(nsec));
	nsec = betoh64(nsec);
	printf("%llu nsec", nsec);
}

static void
msgtap_md_u8(const struct msgtap_metadata *md,
    const void *buf, size_t buflen)
{
	const uint8_t *u8p = buf;
	printf("%u", *u8p);
}

static void
msgtap_md_u16(const struct msgtap_metadata *md,
    const void *buf, size_t buflen)
{
	uint16_t u16;
	memcpy(&u16, buf, sizeof(u16));
	printf("%u", ntohs(u16));
}

static void
msgtap_md_u32(const struct msgtap_metadata *md,
    const void *buf, size_t buflen)
{
	uint32_t u32;
	memcpy(&u32, buf, sizeof(u32));
	printf("%u", ntohl(u32));
}

static void
msgtap_md_u64(const struct msgtap_metadata *md,
    const void *buf, size_t buflen)
{
	uint64_t u64;
	memcpy(&u64, buf, sizeof(u64));
	printf("%llu", betoh64(u64));
}

static void
msgtap_md_ipv4_addr(const struct msgtap_metadata *md,
    const void *buf, size_t buflen)
{
	char name[INET_ADDRSTRLEN];

	inet_ntop(AF_INET, buf, name, sizeof(name));

	printf("%s", name);
}

static void
msgtap_md_ipv6_addr(const struct msgtap_metadata *md,
    const void *buf, size_t buflen)
{
	char name[INET6_ADDRSTRLEN];

	inet_ntop(AF_INET6, buf, name, sizeof(name));

	printf("%s", name);
}

static void
msgtap_md_ip_proto(const struct msgtap_metadata *md,
    const void *buf, size_t buflen)
{
	uint8_t proto = *(uint8_t *)buf;

	switch (proto) {
	case MSGTAP_T_IPPROTO_TCP:
		printf("tcp");
		break;
	case MSGTAP_T_IPPROTO_UDP:
		printf("udp");
		break;
	default:
		printf("(%u)", proto);
		break;
	}
}

static void
msgtap_md_net_dir(const struct msgtap_metadata *md,
    const void *buf, size_t buflen)
{
	uint8_t dir = *(uint8_t *)buf;

	switch (dir) {
	case MSGTAP_T_NET_DIR_UNKNOWN:
		printf("unknown");
		break;
	case MSGTAP_T_NET_DIR_IN:
		printf("in");
		break;
	case MSGTAP_T_NET_DIR_OUT:
		printf("out");
		break;
	case MSGTAP_T_NET_DIR_BOTH:
		printf("both");
		break;
	default:
		printf("(%u)", dir);
		break;
	}
}

#define msgtap_md_port msgtap_md_u16

static const struct msgtap_md_type msgtap_md_types_base[] = {
	{ MSGTAP_T_PAD,		-1,	"pad",		msgtap_md_pad },
	{ MSGTAP_T_ORG,		-1,	"organisation",	msgtap_md_string },
	{ MSGTAP_T_SERVICE,	-1,	"service",	msgtap_md_string },
	{ MSGTAP_T_SITE,	-1,	"site",		msgtap_md_string },
	{ MSGTAP_T_HOSTNAME,	-1,	"hostname",	msgtap_md_string },
	{ MSGTAP_T_NAME,	-1,	"name",		msgtap_md_string },
	{ MSGTAP_T_COMPONENT,	-1,	"component",	msgtap_md_string },
	{ MSGTAP_T_EXTRA,	-1,	"extra",	msgtap_md_string },
	{ MSGTAP_T_FILE,	-1,	"file",		msgtap_md_string },
	{ MSGTAP_T_FUNC,	-1,	"function",	msgtap_md_string },
	{ MSGTAP_T_LINE,	MSGTAP_T_LINE_LEN,
					"line",		msgtap_md_u32 },
	{ MSGTAP_T_PID,		MSGTAP_T_PID_LEN,
					"pid",		msgtap_md_u32 },
	{ MSGTAP_T_TID,		MSGTAP_T_TID_LEN,
					"tid",		msgtap_md_u32 },
	{ MSGTAP_T_SEQ32,	MSGTAP_T_SEQ32_LEN,
					"seq",		msgtap_md_u32 },
	{ MSGTAP_T_SEQ64,	MSGTAP_T_SEQ64_LEN,
					"seq",		msgtap_md_u64 },
	{ MSGTAP_T_TS,		MSGTAP_T_TS_LEN,
					"timestamp",	msgtap_md_ts },
	{ MSGTAP_T_TS_PRECISION,
				MSGTAP_T_TS_PRECISION_LEN,
					"timestamp-precision",
							msgtap_md_nsec },
	{ MSGTAP_T_TM,		MSGTAP_T_TM_LEN,
					"duration",	msgtap_md_nsec },

	{ MSGTAP_T_NET_PRIO,	MSGTAP_T_NET_PRIO_LEN,
					"net-prio",	msgtap_md_u8 },
	{ MSGTAP_T_NET_DIR,	MSGTAP_T_NET_DIR_LEN,
					"net-dir",	msgtap_md_net_dir },
	{ MSGTAP_T_NET_FLOWID,	-1,	"net-flowid",	msgtap_md_hex },

	{ MSGTAP_T_IP,		0,	"IP",		NULL },
	{ MSGTAP_T_IPV4,	0,	"IPv4",		NULL },
	{ MSGTAP_T_IPV6,	0,	"IPv6",		NULL },

	{ MSGTAP_T_IPSRCADDR,	4,	"src-addr",	msgtap_md_ipv4_addr },
	{ MSGTAP_T_IPSRCADDR,	16,	"src-addr",	msgtap_md_ipv6_addr },
	{ MSGTAP_T_IPDSTADDR,	4,	"dst-addr",	msgtap_md_ipv4_addr },
	{ MSGTAP_T_IPDSTADDR,	16,	"dst-addr",	msgtap_md_ipv6_addr },

	{ MSGTAP_T_IPSRCPORT,	MSGTAP_T_IPSRCPORT_LEN,
					"src-port",	msgtap_md_port },
	{ MSGTAP_T_IPDSTPORT,	MSGTAP_T_IPDSTPORT_LEN,
					"dst-port",	msgtap_md_port },

	{ MSGTAP_T_IPPROTO,	MSGTAP_T_IPPROTO_LEN,
					"ip-proto",	msgtap_md_ip_proto },
};

const struct msgtap_md_class msgtap_md_class_base = {
	.mdc_id =			MSGTAP_CLASS_BASE,
	.mdc_name =			NULL,
	.mdc_types =			msgtap_md_types_base,
	.mdc_ntypes =			nitems(msgtap_md_types_base),
};
