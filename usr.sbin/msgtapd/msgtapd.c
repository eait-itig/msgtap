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

#include "msgtapd.h"
#include "util.h"

#ifndef nitems
#define nitems(_a)	(sizeof((_a)) / sizeof((_a)[0]))
#endif

struct msgtapd;

struct msgtap_listener {
	struct msgtapd	*mtl_daemon;
	TAILQ_ENTRY(msgtap_listener)
			 mtl_entry;
	const char	*mtl_path;
	struct event	 mtl_ev;
};

TAILQ_HEAD(msgtap_listeners, msgtap_listener);

struct msgtapd {
	void		*mtd_buf;
	size_t		 mtd_buflen;

	struct msgtap_listeners
			 mtd_listeners;
};

static void	msgtap_recv(int, short, void *);

static size_t	kern_sb_max(void);

__dead static void
usage(void)
{
	extern char *__progname;

	fprintf(stderr, "usage: %s -U /listener\n", __progname);

	exit(1);
}

int
main(int argc, char *argv[])
{
	struct msgtapd _mtd = {
		.mtd_buf	= NULL,
		.mtd_buflen	= 0,
		.mtd_listeners	= TAILQ_HEAD_INITIALIZER(_mtd.mtd_listeners),
	};
	struct msgtapd * const mtd = &_mtd; /* stupid c */
	struct msgtap_listener *mtl;
	int ch;

	while ((ch = getopt(argc, argv, "U:")) != -1) {
		switch (ch) {
		case 'U':
			if (sun_check(optarg) == -1)
				err(1, "listener %s", optarg);

			mtl = malloc(sizeof(*mtl));
			if (mtl == NULL)
				err(1, NULL);
			mtl->mtl_path = optarg;

			TAILQ_INSERT_TAIL(&mtd->mtd_listeners, mtl, mtl_entry);
			break;

		default:
			usage();
		}
	}

	argc -= optind;
	argv += optind;

	if (argc != 0)
		usage();

	if (TAILQ_EMPTY(&mtd->mtd_listeners))
		usage();

	mtd->mtd_buflen = kern_sb_max();
	mtd->mtd_buf = malloc(mtd->mtd_buflen);
	if (mtd->mtd_buf == NULL)
		err(1, "%zu buffer allocation", mtd->mtd_buflen);

	TAILQ_FOREACH(mtl, &mtd->mtd_listeners, mtl_entry) {
		int fd;

		/*
                 * narrow the toctou window, and try to avoid binding
                 * to the same name twice.
		 */
		if (sun_check(mtl->mtl_path) == -1)
			err(1, "listener %s", mtl->mtl_path);

		fd = sun_bind(mtl->mtl_path);
		if (fd == -1) {
			/* clean up? */
			err(1, "bind %s", mtl->mtl_path);
		}

		mtl->mtl_daemon = mtd;
		event_set(&mtl->mtl_ev, fd, 0, NULL, NULL);
	}

	event_init();

	TAILQ_FOREACH(mtl, &mtd->mtd_listeners, mtl_entry) {
		event_set(&mtl->mtl_ev, EVENT_FD(&mtl->mtl_ev),
		    EV_READ|EV_PERSIST, msgtap_recv, mtl);
		event_add(&mtl->mtl_ev, NULL);
	}

	event_dispatch();

	return (0);
}

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

static void
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
msgtap_md_tm(const struct msgtap_metadata *md,
    const void *buf, size_t buflen)
{
	uint64_t nsec;
	memcpy(&nsec, buf, sizeof(nsec));
	nsec = betoh64(nsec);
	printf("%llu nsec", nsec);
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
#define msgtap_md_net_prio msgtap_md_default
#define msgtap_md_net_flowid msgtap_md_default

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
	{ MSGTAP_T_TM,		MSGTAP_T_TM_LEN,
					"duration",	msgtap_md_tm },

	{ MSGTAP_T_NET_PRIO,	MSGTAP_T_NET_PRIO_LEN,
					"net-prio",	msgtap_md_net_prio },
	{ MSGTAP_T_NET_DIR,	MSGTAP_T_NET_DIR_LEN,
					"net-dir",	msgtap_md_net_dir },
	{ MSGTAP_T_NET_FLOWID,	-1,	"net-flowid",	msgtap_md_net_flowid },

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

static const struct msgtap_md_class msgtap_md_class_base = {
	.mdc_id =			MSGTAP_CLASS_BASE,
	.mdc_name =			NULL,
	.mdc_types =			msgtap_md_types_base,
	.mdc_ntypes =			nitems(msgtap_md_types_base),
};

static const struct msgtap_md_type *
msgtap_md_type_lookup(const struct msgtap_md_class *mdc,
    const struct msgtap_metadata *md)
{
	unsigned int i;

	for (i = 0; i < mdc->mdc_ntypes; i++) {
		const struct msgtap_md_type *mdt;

		mdt = &mdc->mdc_types[i];
		if (mdt->mdt_id != md->md_type)
			continue;
		if (mdt->mdt_len != -1 &&
		    mdt->mdt_len != md->md_len)
			continue;

		return (mdt);
	}

	return (NULL);
}

static int
msgtap_dump_md(const void *buf, size_t len,
    const struct msgtap_md_class *mdc_t)
{
	struct msgtap_metadata md;
	const struct msgtap_md_class *mdc;
	const struct msgtap_md_type *mdt;
	void (*md_print)(const struct msgtap_metadata *, const void *, size_t);

	while (len > 0) {
		if (len < sizeof(md)) {
			warnx("size of metadata header %zu < "
			    "remaining data %zu", sizeof(md), len);
			return (-1);
		}
		memcpy(&md, buf, sizeof(md));

		buf = (uint8_t *)buf + sizeof(md);
		len -= sizeof(md);

		md.md_len = ntohs(md.md_len);
		if (len < md.md_len) {
			warnx("size of metadata %u < "
			    "remaining data %zu", md.md_len, len);
			return (-1);
		}

		switch (md.md_class) {
		case MSGTAP_CLASS_BASE:
			mdc = &msgtap_md_class_base;
			break;
		case MSGTAP_CLASS_TYPED:
			mdc = mdc_t;
			break;
		default:
			mdc = NULL;
			break;
		}

		if (mdc == NULL) {
			printf("class-%u.", md.md_class);
			mdt = NULL;
		} else {
			if (mdc->mdc_name != NULL)
				printf("%s.", mdc->mdc_name);
			mdt = msgtap_md_type_lookup(mdc, &md);
		}

		if (mdt == NULL) {
			printf("type-%u", md.md_type);
			md_print = msgtap_md_default;
		} else {
			printf("%s", mdt->mdt_name);
			md_print = mdt->mdt_handler;
		}

		if (md_print != NULL) {
			printf(": ");
			(*md_print)(&md, buf, md.md_len);
		}

		printf("\n");

		buf = (uint8_t *)buf + md.md_len;
		len -= md.md_len;
	} 

	return (0);
}

static int
msgtap_dump(const void *buf, size_t len)
{
	const struct msgtap_header *mh;
	uint32_t mdlen, msglen, caplen;
	const struct msgtap_md_class *mdc;

	if (len < sizeof(*mh))
		return (-1);

	mh = buf;
	if ((mh->mh_flags & htons(MSGTAP_F_VERSION)) !=
	    htons(MSGTAP_F_VERSION_0)) {
		warnx("unexpected version");
		return (-1);
	}

	mdlen = ntohl(mh->mh_metalen);
	msglen = ntohl(mh->mh_msglen);
	caplen = ntohl(mh->mh_caplen);

	buf = mh + 1;
	len -= sizeof(*mh);

	if (len < mdlen) {
		warnx("metadata length %u > buffer len %zu", mdlen, len);
		return (-1);
	}

	switch (ntohs(mh->mh_type)) {
	case MSGTAP_TYPE_DNS:
		mdc = &msgtap_md_class_dns;
		break;
	default:
		mdc = NULL;
		break;
	}

	msgtap_dump_md(buf, mdlen, mdc);

	buf = (uint8_t *)buf + mdlen;
	len -= mdlen;

	if (len < caplen) {
		warnx("data length %u > buffer len %zu", caplen, len);
		return (-1);
	}

	if (mdc == NULL)
		hexdump(buf, caplen);
	else
		(*mdc->mdc_dump)(buf, caplen, msglen);

	return (0);
}

static void
msgtap_recv(int fd, short events, void *arg)
{
	struct msgtap_listener *mtl = arg;
	struct msgtapd *mtd = mtl->mtl_daemon;
	ssize_t rv;

	rv = recv(fd, mtd->mtd_buf, mtd->mtd_buflen, 0);
	if (rv == -1)
		err(1, "recv %s", mtl->mtl_path);

	printf("%s:\n", mtl->mtl_path);
	//hexdump(mtd->mtd_buf, rv);

	msgtap_dump(mtd->mtd_buf, rv);

	fflush(stdout);
}

static size_t
kern_sb_max(void)
{
	return (SB_MAX);
}
