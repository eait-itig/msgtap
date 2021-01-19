/*	$OpenBSD$ */

/*
 * Copyright (c) 2021 David Gwynne <dlg@openbsd.org>
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
#include <fcntl.h>
#include <unistd.h>
#include <pwd.h>
#include <signal.h>
#include <errno.h>
#include <err.h>

#include <sys/queue.h>
#include <sys/socket.h>
#include <sys/param.h> /* for gethostname */

#include <sys/ioctl.h>
#include <net/if.h>
#include <net/bpf.h>

#include <pcap.h>
#include <event.h>

#include <msgtap.h>
#include "libmsgtap.h"

#ifndef ISSET
#define ISSET(_v, _m)	((_v) & (_m))
#endif

#ifndef nitems
#define nitems(_a)	(sizeof((_a)) / sizeof((_a)[0]))
#endif

#define BPF_DEV "/dev/bpf"
#define NETTAP_USER "_tcpdump"

struct nettap;

struct bpf_interface {
	struct nettap	*bif_nt;
	const char	*bif_name;
	size_t		 bif_namelen;
	unsigned int	 bif_dlt;
	unsigned int	 bif_blen;
	struct event	 bif_ev;

	TAILQ_ENTRY(bpf_interface)
			 bif_entry;
};

TAILQ_HEAD(bpf_interfaces, bpf_interface);

struct nettap {
	const char	*nt_hostname;
	size_t		 nt_hostnamelen;
	struct bpf_interfaces
			 nt_bifs;
	unsigned int	 nt_snaplen;
	unsigned int	 nt_buflen;
	void *		 nt_buf;

	struct event	 nt_sigalarm;

	struct event	 nt_msgtap;
};

static void	msgtap_open(int, const struct passwd *);

static void	nettap_itimer(struct nettap *, unsigned long long);
static void	nettap_tick(int, short, void *);
static void	nettap_hostname(struct nettap *);

static void	bpf_interface_open(struct nettap *, const char *);
static void	bpf_interface_read(int, short, void *);

static void	nettap_msg(struct nettap *, struct bpf_interface *,
		    const struct bpf_hdr *, size_t, const void *, size_t);
static void	msgtap_pipe(int, short, void *);

static int	setnbio(int, int);
void		hexdump(const void *, size_t);

__dead static void
usage(void)
{
	extern char *__progname;

	fprintf(stderr, "usage: %s -i ifname[:dlt]\n", __progname);

	exit(1);
}

int
main(int argc, char *argv[])
{
	struct nettap _nt = {
		.nt_bifs = TAILQ_HEAD_INITIALIZER(_nt.nt_bifs),
		.nt_snaplen = 256,
		.nt_buflen = 0,
	};
	struct nettap * const nt = &_nt;
	struct bpf_interface *bif;
	int promisc = 0;

	int ch;
	int pipefds[2];

	struct passwd *pw;

	if (geteuid() != 0)
		errx(1, "need root privileges");

	pw = getpwnam(NETTAP_USER);
	if (pw == NULL)
		errx(1, "no %s user", NETTAP_USER);

	while ((ch = getopt(argc, argv, "i:Pp")) != -1) {
		switch (ch) {
		case 'i':
			bpf_interface_open(nt, optarg);
			break;

		case 'P':
			promisc = 0;
			break;
		case 'p':
			promisc = 1;
			break;

		default:
			usage();
			/* NOTREACHED */
		}
	}

	argc -= optind;
	argv += optind;

	if (argc > 0)
		usage();

	if (TAILQ_EMPTY(&nt->nt_bifs))
		usage();

	if (pipe(pipefds) == -1)
		err(1, "socketpair");

	/* wire up msgtap */
	msgtap_open(pipefds[0], pw);

	if (setnbio(pipefds[1], 1) == -1)
		err(1, "set pipe non-blocking");

	if (chroot(pw->pw_dir) == -1)
		err(1, "chroot %s", pw->pw_dir);
	if (chdir("/") == -1)
		err(1, "chdir %s", pw->pw_dir);

	if (setgroups(1, &pw->pw_gid) ||
	    setresgid(pw->pw_gid, pw->pw_gid, pw->pw_gid) ||
	    setresuid(pw->pw_uid, pw->pw_uid, pw->pw_uid))
		errx(1, "can't drop privileges");

	endpwent();

	nettap_hostname(nt);

	event_init();

	TAILQ_FOREACH(bif, &nt->nt_bifs, bif_entry) {
		if (bif->bif_blen > nt->nt_buflen)
			nt->nt_buflen = bif->bif_blen;

		if (promisc && ioctl(EVENT_FD(&bif->bif_ev),
		    BIOCPROMISC, NULL) == -1) {
			warn("failed to configure promisc on %s",
			    bif->bif_name);
		}

		event_set(&bif->bif_ev, EVENT_FD(&bif->bif_ev),
		    EV_READ | EV_PERSIST, bpf_interface_read, bif);
		event_add(&bif->bif_ev, NULL);
	}

	nt->nt_buf = malloc(nt->nt_buflen);
	if (nt->nt_buf == NULL)
		err(1, "BPF buffer alloc (%u bytes)", nt->nt_buflen);

	nettap_itimer(nt, 1000);

	event_set(&nt->nt_msgtap, pipefds[1], EV_READ | EV_PERSIST,
	    msgtap_pipe, nt);
	event_add(&nt->nt_msgtap, NULL);

	event_dispatch();

	return (0);
}

static void
msgtap_open(int fd, const struct passwd *pw)
{
	char *argv[] = { "msgtap", "-f", "-", NULL };
	switch (fork()) {
	case -1:
		err(1, "msgtap fork");
		/* NOTREACHED */
	case 0:
		/* child */
		break;
	default:
		/* parent */
		close(fd);
		return;
	}

	if (setgroups(1, &pw->pw_gid) ||
	    setresgid(pw->pw_gid, pw->pw_gid, pw->pw_gid) ||
	    setresuid(pw->pw_uid, pw->pw_uid, pw->pw_uid))
		errx(1, "can't drop privileges");

	endpwent();

	if (dup2(fd, STDIN_FILENO) == -1)
		err(1, "msgtap dup stdin");
	close(fd);

	if (execv("/opt/local/sbin/msgtap", argv) == -1)
		err(1, "exec msgtap");
}

static void
msgtap_pipe(int pfd, short events, void *arg)
{
	/* we should only get here if the pipe closes */
	exit(1);
}

static void
msgtap_write(int fd, const struct mt_msg *mt,
    size_t msglen, const void *buf, size_t caplen)
{
	struct msgtap_header mh;
	struct iovec iov[3];
	ssize_t rv;

	mh.mh_flags = htobe16(MSGTAP_F_VERSION_0);
	mh.mh_type = htobe16(0); /* XXX */
	mh.mh_metalen = htobe32(mt->msglen);
	mh.mh_msglen = htobe32(msglen);
	mh.mh_caplen = htobe32(caplen);

	iov[0].iov_base = &mh;
	iov[0].iov_len = sizeof(mh);
	iov[1].iov_base = mt->msg;
	iov[1].iov_len = mt->msglen;
	iov[2].iov_base = (void *)buf;
	iov[2].iov_len = caplen;

	rv = writev(fd, iov, nitems(iov));
	if (rv == -1)
		err(1, "msgtap write");
}

static void
nettap_itimer(struct nettap *nt, unsigned long long msec)
{
	struct itimerval it;

	signal_set(&nt->nt_sigalarm, SIGALRM, nettap_tick, nt);
	signal_add(&nt->nt_sigalarm, NULL);

	memset(&it, 0, sizeof(it));
	it.it_value.tv_sec = msec / 1000;
	it.it_value.tv_usec = (msec % 1000) * 1000;
	it.it_interval = it.it_value;

	if (setitimer(ITIMER_REAL, &it, NULL) == -1)
		err(1, "setitimer %llu msec", msec);
}

static void
nettap_tick(int sig, short events, void *arg)
{
	struct nettap *nt = arg;
	struct bpf_interface *bif;

	TAILQ_FOREACH(bif, &nt->nt_bifs, bif_entry)
		bpf_interface_read(EVENT_FD(&bif->bif_ev), 0, bif);
}

static void
nettap_hostname(struct nettap *nt)
{
	char hostname[MAXHOSTNAMELEN];

	if (gethostname(hostname, sizeof(hostname)) == -1)
		err(1, "get hostname");

	nt->nt_hostname = strdup(hostname);
	if (nt->nt_hostname == NULL)
		err(1, "hostname alloc");

	nt->nt_hostnamelen = strlen(nt->nt_hostname);
}

static void
bpf_interface_open(struct nettap *nt, const char *arg)
{
	struct ifreq ifr;
	struct bpf_version bv;
	struct bpf_interface *bif;
	char *dltname;
	int bpf, dlt;

	bif = malloc(sizeof(*bif));
	if (bif == NULL)
		err(1, NULL);

	dltname = strchr(arg, ':');
	if (dltname == NULL) {
		bif->bif_name = arg;
		bif->bif_namelen = strlen(arg);
	} else {
		size_t namelen = dltname - arg;
		char *name;

		name = malloc(namelen + 1);
		if (name == NULL)
			err(1, NULL);
		memcpy(name, arg, namelen);
		name[namelen] = '\0';

		dltname++; /* move past the ':' */
		dlt = pcap_datalink_name_to_val(dltname);
		if (dlt == -1)
			errx(1, "%s: unknown datalink type %s", name, dltname);

		bif->bif_name = name;
		bif->bif_namelen = namelen;
		bif->bif_dlt = dlt;
	}

	bpf = open(BPF_DEV, O_RDONLY|O_NONBLOCK|O_CLOEXEC);
	if (bpf == -1)
		err(1, "%s", BPF_DEV);

	if (ioctl(bpf, BIOCVERSION, &bv) == -1)
		err(1, "%s: get BPF version", BPF_DEV);

	if (bv.bv_major != BPF_MAJOR_VERSION ||
	    bv.bv_minor < BPF_MINOR_VERSION) {
		errx(1, "unsupported BPF version %u.%u (expected %u.%u)",
		    bv.bv_major, bv.bv_minor,
		    BPF_MAJOR_VERSION, BPF_MINOR_VERSION);
	}

	memset(&ifr, 0, sizeof(ifr));
	if (strlcpy(ifr.ifr_name, bif->bif_name, sizeof(ifr.ifr_name)) >=
	    sizeof(ifr.ifr_name))
		errx(1, "%s: interface name is too long", bif->bif_name);

	if (ioctl(bpf, BIOCSETIF, &ifr) == -1)
		err(1, "failed to set BPF interface %s", bif->bif_name);

	if (dltname == NULL) {
		if (ioctl(bpf, BIOCGDLT, &bif->bif_dlt) == -1) {
			err(1, "%s: failed to get datalink type",
			    bif->bif_name);
		}
	} else {
		if (ioctl(bpf, BIOCSDLT, &bif->bif_dlt) == -1) {
			err(1, "%s: failed to set datalink type %s",
			    bif->bif_name, dltname);
		}
	}

	if (ioctl(bpf, BIOCGBLEN, &bif->bif_blen) == -1)
		err(1, "%s: failed to get buffer length", bif->bif_name);

	event_set(&bif->bif_ev, bpf, 0, NULL, NULL);

	bif->bif_nt = nt;
	TAILQ_INSERT_TAIL(&nt->nt_bifs, bif, bif_entry);
}

static void
bpf_interface_read(int bpf, short events, void *arg)
{
	const struct bpf_hdr *bh;
	struct bpf_interface *bif = arg;
	struct nettap *nt = bif->bif_nt;
	ssize_t rv;
	const uint8_t *buf;
	size_t len, bpflen, caplen;

	rv = read(bpf, nt->nt_buf, bif->bif_blen);
	if (rv == -1)
		err(1, "%s read", bif->bif_name);
	if (rv == 0)
		return;

	buf = nt->nt_buf;
	len = rv;

	for (;;) {
		if (len < sizeof(*bh)) {
			warnx("buffer length < bpf header length");
			break;
		}

		bh = (const struct bpf_hdr *)buf;
		bpflen = bh->bh_hdrlen + bh->bh_caplen;
		if (len < bpflen) {
			warnx("buffer length < bpf length");
			break;
		}

		caplen = bh->bh_caplen;
		if (caplen > nt->nt_snaplen)
			caplen = nt->nt_snaplen;

		nettap_msg(nt, bif, bh, bh->bh_datalen,
		    buf + bh->bh_hdrlen, caplen);

#if 0
		printf("%s %u.%06u: caplen %u, pktlen %u", bif->bif_name,
		    bh->bh_tstamp.tv_sec, bh->bh_tstamp.tv_usec,
		    bh->bh_caplen, bh->bh_datalen);
		printf(", pri %u", bh->bh_flags & BPF_F_PRI_MASK);
		if (bh->bh_ifidx != 0)
			printf(", rcvif %u", bh->bh_ifidx);
		if (ISSET(bh->bh_flags, BPF_F_FLOWID))
			printf(", flowid 0x%04x", bh->bh_flowid);
		switch (bh->bh_flags & BPF_F_DIR_MASK) {
		case BPF_F_DIR_IN:
			printf(", in");
			break;
		case BPF_F_DIR_OUT:
			printf(", out");
			break;
		case BPF_F_DIR_IN|BPF_F_DIR_OUT:
			printf(", bidir");
			break;
		}

		printf("\n");
#endif
		bpflen = BPF_WORDALIGN(bpflen);
		if (len <= bpflen)
			break;

		buf += bpflen;
		len -= bpflen;
	}
}

static void
nettap_msg(struct nettap *nt, struct bpf_interface *bif,
    const struct bpf_hdr *bh, size_t msglen, const void *buf, size_t buflen)
{
	struct mt_msg *mt;
	uint64_t nsec;
	uint8_t dir;

	mt = mt_msg_alloc();
	if (mt == NULL) {
		warn("%s packet dropped", bif->bif_name);
		return;
	}

	nsec = (uint64_t)bh->bh_tstamp.tv_sec * 1000000000LLU;
	nsec += (uint64_t)bh->bh_tstamp.tv_usec * 1000U;

	if (mt_msg_add_u64(mt, MSGTAP_CLASS_BASE, MSGTAP_T_TS, nsec) == -1)
		goto drop;

	if (mt_msg_add_u64(mt, MSGTAP_CLASS_BASE, MSGTAP_T_TS_PRECISION,
	    1000) == -1)
		goto drop;

	if (mt_msg_add_bytes(mt, MSGTAP_CLASS_BASE, MSGTAP_T_HOSTNAME,
	    nt->nt_hostname, nt->nt_hostnamelen) == -1)
		goto drop;

	if (mt_msg_add_bytes(mt, MSGTAP_CLASS_BASE, MSGTAP_T_COMPONENT,
	    bif->bif_name, bif->bif_namelen) == -1)
		goto drop;

	switch (bh->bh_flags & BPF_F_DIR_MASK) {
	case 0:
		dir = MSGTAP_T_NET_DIR_UNKNOWN;
		break;
	case BPF_F_DIR_IN:
		dir = MSGTAP_T_NET_DIR_IN;
		break;
	case BPF_F_DIR_OUT:
		dir = MSGTAP_T_NET_DIR_OUT;
		break;
	case BPF_F_DIR_IN|BPF_F_DIR_OUT:
		dir = MSGTAP_T_NET_DIR_BOTH; /* wat */
		break;
	}

	if (mt_msg_add_u8(mt, MSGTAP_CLASS_BASE, MSGTAP_T_NET_DIR, dir) == -1)
		goto drop;

	if (mt_msg_add_u8(mt, MSGTAP_CLASS_BASE, MSGTAP_T_NET_PRIO,
	    bh->bh_flags & BPF_F_PRI_MASK) == -1)
		goto drop;

	if (ISSET(bh->bh_flags, BPF_F_FLOWID)) {
		if (mt_msg_add_u16(mt, MSGTAP_CLASS_BASE, MSGTAP_T_NET_FLOWID,
		    bh->bh_flowid) == -1)
			goto drop;
	}


	msgtap_write(EVENT_FD(&nt->nt_msgtap), mt, msglen, buf, buflen);

drop:
	mt_msg_free(mt);
}

static int
setnbio(int fd, int opt)
{
	return (ioctl(fd, FIONBIO, &opt));
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
