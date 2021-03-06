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

struct msgtap_server {
	struct msgtapd		*mts_daemon;
	struct event		 mts_ev;
};

static void	msgtapd_bind(struct msgtapd *, struct msgtap_listener *, int);
static void	msgtap_accept(int, short, void *);
static void	msgtap_recv(int, short, void *);
static void	msgtap_client_closed(int, short, void *);
static void	msgtap_client_flush(int, short, void *);
static void	msgtap_client_close(struct msgtap_client *);

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
	struct msgtapd *mtd;
	struct msgtap_listener *mtl;

	char *conffile = "/etc/msgtapd.conf";
	int nflag = 0;
	int ch;

	while ((ch = getopt(argc, argv, "D:f:n")) != -1) {
		switch (ch) {
		case 'D':
			if (cmdline_symset(optarg) < 0) {
				errx(1, "cannot parse macro definition %s",
				    optarg);
			}
			break;
		case 'f':
			conffile = optarg;
			break;

		case 'n':
			nflag = 1;
			break;

		default:
			usage();
		}
	}

	argc -= optind;
	argv += optind;

	if (argc != 0)
		usage();

	mtd = parse_config(conffile);
	if (mtd == NULL)
		exit(1);

	if (TAILQ_EMPTY(&mtd->mtd_server_listeners))
		errx(1, "no server listeners configured");
	if (TAILQ_EMPTY(&mtd->mtd_client_listeners))
		errx(1, "no client listeners configured");

	mtd->mtd_buflen = kern_sb_max();
	mtd->mtd_buf = malloc(mtd->mtd_buflen);
	if (mtd->mtd_buf == NULL)
		err(1, "%zu buffer allocation", mtd->mtd_buflen);

	TAILQ_FOREACH(mtl, &mtd->mtd_server_listeners, mtl_entry)
		msgtapd_bind(mtd, mtl, SOCK_SEQPACKET);
	TAILQ_FOREACH(mtl, &mtd->mtd_client_listeners, mtl_entry)
		msgtapd_bind(mtd, mtl, SOCK_STREAM);

	event_init();

	TAILQ_FOREACH(mtl, &mtd->mtd_server_listeners, mtl_entry) {
		event_set(&mtl->mtl_ev, EVENT_FD(&mtl->mtl_ev),
		    EV_READ|EV_PERSIST, msgtap_accept, mtl);
		event_add(&mtl->mtl_ev, NULL);
	}
	TAILQ_FOREACH(mtl, &mtd->mtd_client_listeners, mtl_entry) {
		event_set(&mtl->mtl_ev, EVENT_FD(&mtl->mtl_ev),
		    EV_READ|EV_PERSIST, msgtap_accept, mtl);
		event_add(&mtl->mtl_ev, NULL);
	}

	event_dispatch();

	return (0);
}

static void
msgtapd_bind(struct msgtapd *mtd, struct msgtap_listener *mtl, int type)
{
	int lfd;

	if (sun_check(mtl->mtl_path, type) == -1)
		err(1, "listener %s", mtl->mtl_path);

	lfd = sun_bind(mtl->mtl_path, type);
	if (lfd == -1) {
		/* clean up? */
		err(1, "bind %s", mtl->mtl_path);
	}

	if (listen(lfd, 5) == -1)
		err(1, "listen %s", mtl->mtl_path);

	event_set(&mtl->mtl_ev, lfd, 0, NULL, NULL);
}

static void
msgtap_accept(int lfd, short events, void *arg)
{
	struct msgtap_listener *mtl = arg;
	struct msgtapd *mtd = mtl->mtl_daemon;
	int fd;

	fd = accept4(lfd, NULL, 0, SOCK_NONBLOCK);
	if (fd == -1) {
		warn("%s accept", mtl->mtl_path);
		return;
	}

	mtl->mtl_accept(mtd, fd);
}

void
msgtapd_server_accept(struct msgtapd *mtd, int fd)
{
	struct msgtap_server *mts;

	mts = malloc(sizeof(*mts));
	if (mts == NULL) {
		warn("server connection alloc");
		close(fd);
		return;
	}

	mts->mts_daemon = mtd;

	event_set(&mts->mts_ev, fd, EV_READ|EV_PERSIST, msgtap_recv, mts);
	event_add(&mts->mts_ev, NULL);
}

static void
msgtap_recv(int fd, short events, void *arg)
{
	struct msgtap_server *mts = arg;
	struct msgtapd *mtd = mts->mts_daemon;
	struct msgtap_client *mtc, *nmtc;
	ssize_t rv;
	size_t rlen, wlen;

	rv = recv(fd, mtd->mtd_buf, mtd->mtd_buflen, 0);
	if (rv == -1)
		err(1, "server recv");
	if (rv == 0) {
		warnx("server disconnected");
		event_del(&mts->mts_ev);
		close(EVENT_FD(&mts->mts_ev));
		free(mts);
		return;
	}

	rlen = rv;

	TAILQ_FOREACH_SAFE(mtc, &mtd->mtd_clients, mtc_entry, nmtc) {
		if (mtc->mtc_buf != NULL) {
			warnx("drop");
			/* this client is already busy, drop this message */
			continue;
		}

		rv = write(EVENT_FD(&mtc->mtc_wrev), mtd->mtd_buf, rlen);
		if (rv == -1)
			err(1, "client send");

		wlen = rv;
		if (wlen < rlen) {
			size_t len;
			/*
                         * the client is busy, buffer the remainder
                         * of this message.
			 */

			len = rlen - wlen;
			mtc->mtc_buf = malloc(len);
			if (mtc->mtc_buf == NULL) {
                                /* oh noes! we've run out of memory.
                                 * we could die, or we could kill this
                                 * client to try and recover.
				 */
				msgtap_client_close(mtc);
				continue;
			}

			memcpy(mtc->mtc_buf, mtd->mtd_buf + wlen, len);
			mtc->mtc_buflen = len;
			mtc->mtc_bufoff = 0;

			event_add(&mtc->mtc_wrev, NULL);
		}
	}
}

void
msgtapd_client_accept(struct msgtapd *mtd, int fd)
{
	struct msgtap_client *mtc;

	mtc = malloc(sizeof(*mtc));
	if (mtc == NULL) {
		warn("client connection alloc");
		close(fd);
		return;
	}

	mtc->mtc_daemon = mtd;
	TAILQ_INSERT_TAIL(&mtd->mtd_clients, mtc, mtc_entry);

	event_set(&mtc->mtc_rdev, fd, EV_READ|EV_PERSIST,
	    msgtap_client_closed, mtc);
	event_add(&mtc->mtc_rdev, NULL);

	event_set(&mtc->mtc_wrev, fd, EV_WRITE, msgtap_client_flush, mtc);
	mtc->mtc_buf = NULL;
}

static void
msgtap_client_closed(int fd, short events, void *arg)
{
	struct msgtap_client *mtc = arg;
	struct msgtapd *mtd = mtc->mtc_daemon;
	ssize_t rv;

	rv = read(fd, mtd->mtd_buf, mtd->mtd_buflen);
	if (rv == -1)
		err(1, "client recv");
	if (rv == 0) {
		msgtap_client_close(mtc);
		return;
	}
}

static void
msgtap_client_flush(int fd, short events, void *arg)
{
	struct msgtap_client *mtc = arg;
	ssize_t rv;

	rv = write(fd, mtc->mtc_buf + mtc->mtc_bufoff,
	    mtc->mtc_buflen - mtc->mtc_bufoff);
	if (rv == -1) {
		switch (errno) {
		case EINTR:
		case EAGAIN:
			/* try again */
			event_add(&mtc->mtc_wrev, NULL);
			break;
		default:
			warn("client write");
			msgtap_client_close(mtc);
			break;
		}

		return;
	}

	mtc->mtc_bufoff += rv;
	if (mtc->mtc_bufoff < mtc->mtc_buflen) {
		/* some more work to do */
		event_add(&mtc->mtc_wrev, NULL);
		return;
	}

	/* done */
	free(mtc->mtc_buf);
	mtc->mtc_buf = NULL;
}

static void
msgtap_client_close(struct msgtap_client *mtc)
{
	struct msgtapd *mtd = mtc->mtc_daemon;

	event_del(&mtc->mtc_rdev);
	event_del(&mtc->mtc_wrev);
	free(mtc->mtc_buf);
	close(EVENT_FD(&mtc->mtc_rdev));
	TAILQ_REMOVE(&mtd->mtd_clients, mtc, mtc_entry);
	free(mtc);
}

static size_t
kern_sb_max(void)
{
	return (SB_MAX);
}
