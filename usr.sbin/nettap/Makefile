# $OpenBSD$

PROG=	nettap
SRCS=	nettap.c
SRCS+=	libmsgtap.c
MAN=

BINOWN=	root
BINGRP=	network
BINMODE=4550

LDADD=	-lpcap -levent
DPADD=	${LIBPCAP} ${LIBEVENT}

WARNINGS=Yes
DEBUG=-g

.include <bsd.prog.mk>
