# $OpenBSD$

PROG=	msgtapd
SRCS=	msgtapd.c dns.c parse.y
SRCS+=	util.c
MAN=

LDADD+=	-levent
DPADD+=	${LIBEVENT}

CFLAGS+=-I${.CURDIR}
YFLAGS=	

WARNINGS=Yes
DEBUG=-g

.include <bsd.prog.mk>
