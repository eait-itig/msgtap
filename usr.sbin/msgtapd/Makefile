# $OpenBSD$

PROG=	msgtapd
SRCS=	msgtapd.c dns.c
SRCS+=	util.c
MAN=

LDADD+=	-levent
DPADD+=	${LIBEVENT}

WARNINGS=Yes
DEBUG=-g

.include <bsd.prog.mk>
