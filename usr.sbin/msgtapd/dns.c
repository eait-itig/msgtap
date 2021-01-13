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

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <vis.h>
#include <err.h>

#include <netdb.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <sys/socketvar.h>

#include <sys/queue.h>

#include <event.h>

#include <msgtap.h>
#include <msgtap/dns.h>

#include "msgtapd.h"
#include "util.h"

static void	dns_dump(const void *, size_t, size_t);

static void
dns_md_proto(const struct msgtap_metadata *md,
    const void *buf, size_t len)
{
	uint8_t proto = *(uint8_t *)buf;

	switch (proto) {
	case DNSMSGTAP_PROTOCOL_UDP:
		printf("udp");
		break;
	case DNSMSGTAP_PROTOCOL_TCP:
		printf("tcp");
		break;
	case DNSMSGTAP_PROTOCOL_DOT:
		printf("dns-over-tls");
		break;
	case DNSMSGTAP_PROTOCOL_DOH:
		printf("dns-over-http");
		break;
	default:
		printf("%u", proto);
		break;
	}
}

static void
dns_md_query_zone(const struct msgtap_metadata *md,
    const void *buf, size_t buflen)
{
	const uint8_t *data = buf;
	size_t i;

	printf("\"");
	for (i = 0; i < buflen; i++) {
		char dst[8];

		if (data[i] == '\0')
			break;

		vis(dst, data[i], VIS_TAB|VIS_NL, 0);
		printf("%s", dst);
	}
	printf("\"");
}

static void
dns_md_msgtype(const struct msgtap_metadata *md,
    const void *buf, size_t len)
{
	uint8_t msgtype = *(uint8_t *)buf;

	switch (msgtype) {
	case DNSMSGTAP_MSGTYPE_AQ:
		printf("auth-query");
		break;
	case DNSMSGTAP_MSGTYPE_AR:
		printf("auth-response");
		break;
	case DNSMSGTAP_MSGTYPE_RQ:
		printf("resolver-query");
		break;
	case DNSMSGTAP_MSGTYPE_RR:
		printf("resolver-response");
		break;
	case DNSMSGTAP_MSGTYPE_CQ:
		printf("client-query");
		break;
	case DNSMSGTAP_MSGTYPE_CR:
		printf("client-response");
		break;
	case DNSMSGTAP_MSGTYPE_FQ:
		printf("forwarder-query");
		break;
	case DNSMSGTAP_MSGTYPE_FR:
		printf("forwarder-response");
		break;
	case DNSMSGTAP_MSGTYPE_SQ:
		printf("stub-query");
		break;
	case DNSMSGTAP_MSGTYPE_SR:
		printf("stub-response");
		break;
	case DNSMSGTAP_MSGTYPE_TQ:
		printf("tool-query");
		break;
	case DNSMSGTAP_MSGTYPE_TR:
		printf("tool-response");
		break;
	default:
		printf("%u", msgtype);
		break;
	}
}

static const struct msgtap_md_type msgtap_md_types_dns[] = {
	{ DNSMSGTAP_PROTOCOL,	DNSMSGTAP_PROTOCOL_LEN,
					"proto",	dns_md_proto },
	{ DNSMSGTAP_QUERY_ZONE,	-1,	"query-zone",	dns_md_query_zone },
	{ DNSMSGTAP_MSGTYPE,	DNSMSGTAP_MSGTYPE_LEN,
					"msg-type",	dns_md_msgtype },
};

const struct msgtap_md_class msgtap_md_class_dns = {
	.mdc_id =			MSGTAP_TYPE_DNS,
	.mdc_name =			"dns",
	.mdc_types =			msgtap_md_types_dns,
	.mdc_ntypes =			nitems(msgtap_md_types_dns),
	.mdc_dump = 			dns_dump,
};

static void
dns_dump(const void *buf, size_t buflen, size_t msglen)
{
	hexdump(buf, buflen);
}
