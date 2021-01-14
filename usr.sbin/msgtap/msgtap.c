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
#include <ctype.h>
#include <unistd.h>
#include <errno.h>
#include <err.h>

#include <sys/types.h>
#include <sys/stat.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <sys/socketvar.h>

#include <msgtap.h>
#include "msgtapc.h"

#define MSGTAPD_DEFAULT_SOCKET "/var/run/msgtap.sock"

static int	msgtap_connect(const char *);
static void	msgtap_recv(int);

static int	msgtap_dump(const void *, size_t);

void		hexdump(const void *, size_t);

__dead static void
usage(void)
{
	extern char *__progname;

	fprintf(stderr, "usage: %s [-s /path/to/msgtap.sock]\n", __progname);

	exit(1);
}

int
main(int argc, char *argv[])
{
	const char *sockname = MSGTAPD_DEFAULT_SOCKET;
	int ch;
	int s;

	while ((ch = getopt(argc, argv, "s:")) != -1) {
		switch (ch) {
		case 's':
			sockname = optarg;
			break;
		default:
			usage();
			/* NOTREACHED */
		}
	}

	s = msgtap_connect(sockname);
	if (s == -1)
		err(1, "%s", sockname);

	for (;;) {
		msgtap_recv(s);
	}

	return (0);
}

static int
msgtap_connect(const char *sockname)
{
	struct sockaddr_un sun = {
		.sun_family = AF_UNIX,
	};
	int s;

	if (strlcpy(sun.sun_path, sockname,
	    sizeof(sun.sun_path)) >= sizeof(sun.sun_path)) {
		errno = ENAMETOOLONG;
		return (-1);
	}

	s = socket(AF_UNIX, SOCK_SEQPACKET, 0);
	if (s == -1)
		return (-1);

	if (connect(s, (struct sockaddr *)&sun, sizeof(sun)) == -1) {
		close(s);
		return (-1);
	}

	return (s);
}

static void
msgtap_recv(int s)
{
	static char buffer[SB_MAX];
	ssize_t rv;

	rv = recv(s, buffer, sizeof(buffer), 0);
	if (rv == -1)
		err(1, "recv");
	if (rv == 0)
		exit(0);

	msgtap_dump(buffer, rv);
}

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

static int
printable(int ch)
{
	if (ch == '\0')
		return ('_');
	if (!isprint(ch))
		return ('~');

	return (ch);
}

void
hexdump(const void *d, size_t datalen)
{
	const uint8_t *data = d;
	size_t i, j = 0;

	for (i = 0; i < datalen; i += j) {
		printf("%4zu: ", i);
		for (j = 0; j < 16 && i+j < datalen; j++)
			printf("%02x ", data[i + j]);
		while (j++ < 16)
			printf("   ");
		printf("|");
		for (j = 0; j < 16 && i+j < datalen; j++)
			putchar(printable(data[i + j]));
		printf("|\n");
	}
}
