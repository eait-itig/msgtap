# $OpenBSD$

PROG=	nettap
SRCS=	nettap.c
SRCS+=	libmsgtap.c
MAN=

LDADD=	-lpcap -levent
DPADD=	${LIBPCAP} ${LIBEVENT}

WARNINGS=Yes
DEBUG=-g

.include <bsd.prog.mk>
