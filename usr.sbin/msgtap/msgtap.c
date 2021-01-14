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

#define MSGTAPD_DEFAULT_SOCKET "/var/run/msgtap.sock"

static int	msgtap_connect(const char *);
static void	msgtap_recv(int);

static void	hexdump(const void *, size_t);

__dead static void
usage(void)
{
	extern char *__progname;

	fprintf(stderr, "usage: %s [-s /path/to/msgtap.sock\n", __progname);

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

	hexdump(buffer, rv);
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

static void
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
