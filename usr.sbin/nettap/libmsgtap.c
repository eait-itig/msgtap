/*	$OpenBSD$ */

/*
 * Copyright (c) 2019, 2020 David Gwynne <dlg@openbsd.org>
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

#include <stdint.h>
#include <string.h>
#include <stdlib.h>
#include <errno.h>

#include <msgtap.h>

#include "libmsgtap.h"

void *
msgtap_md(struct msgtap_metadata *md, uint8_t class, uint8_t type,
    uint16_t len)
{
	uint8_t *md_len = (uint8_t *)&md->md_len;

	md->md_class = class;
	md->md_type = type;

	md_len[0] = len >> 8;
	md_len[1] = len;

	return (md + 1);
}

void
msgtap_md_u8(struct msgtap_metadata *md, uint8_t class, uint8_t type,
    uint8_t u8)
{
	uint8_t *u8p;

	u8p = msgtap_md(md, class, type, sizeof(u8));
	u8p[0] = u8;
}

void
msgtap_md_u16(struct msgtap_metadata *md, uint8_t class, uint8_t type,
    uint16_t u16)
{
	uint8_t *u16p;

	u16p = msgtap_md(md, class, type, sizeof(u16));
	u16p[0] = u16 >> 8;
	u16p[1] = u16;
}

void
msgtap_md_u32(struct msgtap_metadata *md, uint8_t class, uint8_t type,
    uint32_t u32)
{
	uint8_t *u32p;

	u32p = msgtap_md(md, class, type, sizeof(u32));
	u32p[0] = u32 >> 24;
	u32p[1] = u32 >> 16;
	u32p[2] = u32 >> 8;
	u32p[3] = u32;
}

void
msgtap_md_u64(struct msgtap_metadata *md, uint8_t class, uint8_t type,
    uint64_t u64)
{
	uint8_t *u64p;

	u64p = msgtap_md(md, class, type, sizeof(u64));
	u64p[0] = u64 >> 56;
	u64p[1] = u64 >> 48;
	u64p[2] = u64 >> 40;
	u64p[3] = u64 >> 32;
	u64p[4] = u64 >> 24;
	u64p[5] = u64 >> 16;
	u64p[6] = u64 >> 8;
	u64p[7] = u64;
}

void
msgtap_md_mem(struct msgtap_metadata *md, uint8_t class, uint8_t type,
    const void *src, uint16_t len)
{
	void *dst;

	dst = msgtap_md(md, class, type, len);
	memcpy(dst, src, len);
}

/*
 *
 */

struct mt_msg *
mt_msg_alloc(void)
{
	struct mt_msg *mt;

	mt = malloc(sizeof(*mt));
	if (mt == NULL)
		return (NULL);

	mt->msg = NULL;
	mt->msglen = 0;

	return (mt);
}

void
mt_msg_free(struct mt_msg *mt)
{
	free(mt->msg);
	free(mt);
}

static void *
mt_msg_md_realloc(struct mt_msg *mt_msg, size_t len)
{
	uint8_t *msg;
	size_t olen, nlen;

	if (len > 0xffff) {
		errno = EMSGSIZE;
		return (NULL);
	}

	olen = mt_msg->msglen;
	nlen = olen + sizeof(struct msgtap_metadata) + len;
	msg = realloc(mt_msg->msg, nlen);
	if (msg == NULL)
		return (NULL);

	mt_msg->msg = msg;
	mt_msg->msglen = nlen;

	return (msg + olen);
}

int
mt_msg_add_flag(struct mt_msg *mt_msg, uint8_t class, uint8_t type)
{
	struct msgtap_metadata *md;

	md = mt_msg_md_realloc(mt_msg, 0);
	if (md == NULL)
		return (-1);

	msgtap_md(md, class, type, 0);

	return (0);
}

int
mt_msg_add_bytes(struct mt_msg *mt_msg, uint8_t class, uint8_t type,
    const void *buf, size_t buflen)
{
	struct msgtap_metadata *md;

	md = mt_msg_md_realloc(mt_msg, buflen);
	if (md == NULL)
		return (-1);

	msgtap_md_mem(md, class, type, buf, buflen);

	return (0);
}

int
mt_msg_add_u8(struct mt_msg *mt_msg, uint8_t class, uint8_t type, uint8_t u8)
{
	struct msgtap_metadata *md;

	md = mt_msg_md_realloc(mt_msg, sizeof(u8));
	if (md == NULL)
		return (-1);

	msgtap_md_u8(md, class, type, u8);

	return (0);
}

int
mt_msg_add_u16(struct mt_msg *mt_msg, uint8_t class, uint8_t type, uint16_t u16)
{
	struct msgtap_metadata *md;

	md = mt_msg_md_realloc(mt_msg, sizeof(u16));
	if (md == NULL)
		return (-1);

	msgtap_md_u16(md, class, type, u16);

	return (0);
}

int
mt_msg_add_u32(struct mt_msg *mt_msg, uint8_t class, uint8_t type, uint32_t u32)
{
	struct msgtap_metadata *md;

	md = mt_msg_md_realloc(mt_msg, sizeof(u32));
	if (md == NULL)
		return (-1);

	msgtap_md_u32(md, class, type, u32);

	return (0);
}

int
mt_msg_add_u64(struct mt_msg *mt_msg, uint8_t class, uint8_t type, uint64_t u64)
{
	struct msgtap_metadata *md;

	md = mt_msg_md_realloc(mt_msg, sizeof(u64));
	if (md == NULL)
		return (-1);

	msgtap_md_u64(md, class, type, u64);

	return (0);
}
