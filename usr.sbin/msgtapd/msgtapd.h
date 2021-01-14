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

#ifndef nitems
#define nitems(_a)	(sizeof((_a)) / sizeof((_a)[0]))
#endif

struct msgtapd;

struct msgtap_listener {
	char			*mtl_path;

	struct msgtapd		*mtl_daemon;
	TAILQ_ENTRY(msgtap_listener)
				 mtl_entry;
	struct event		 mtl_ev;

	void (*mtl_accept)(struct msgtapd *, int);
};

TAILQ_HEAD(msgtap_listeners, msgtap_listener);

struct msgtap_client {
	struct msgtapd		*mtc_daemon;
	TAILQ_ENTRY(msgtap_client)
				 mtc_entry;
	struct event		 mtc_ev;
};

TAILQ_HEAD(msgtap_clients, msgtap_client);

struct msgtapd {
	void			*mtd_buf;
	size_t			 mtd_buflen;

	struct msgtap_listeners	 mtd_server_listeners;
	struct msgtap_listeners	 mtd_client_listeners;
	struct msgtap_clients	 mtd_clients;
};

int			 cmdline_symset(char *);
struct msgtapd		*parse_config(char *);

void			 msgtapd_accept_server(struct msgtapd *, int);
void			 msgtapd_accept_client(struct msgtapd *, int);
