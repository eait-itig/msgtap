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

#ifndef _LIBMSGTAP_H_
#define _LIBMSGTAP_H_

struct msgtap_metadata;

void	*msgtap_md(struct msgtap_metadata *, uint8_t, uint8_t, uint16_t);

void	 msgtap_md_u8(struct msgtap_metadata *, uint8_t, uint8_t, uint8_t);
void	 msgtap_md_u16(struct msgtap_metadata *, uint8_t, uint8_t, uint16_t);
void	 msgtap_md_u32(struct msgtap_metadata *, uint8_t, uint8_t, uint32_t);
void	 msgtap_md_u64(struct msgtap_metadata *, uint8_t, uint8_t, uint64_t);

void	 msgtap_md_mem(struct msgtap_metadata *, uint8_t, uint8_t,
	     const void *, uint16_t);

struct mt_msg {
	void		*msg;
	size_t		 msglen;
};

struct mt_msg *
	mt_msg_alloc(void);
void	mt_msg_free(struct mt_msg *);

int	mt_msg_add_flag(struct mt_msg *, uint8_t, uint8_t);
int	mt_msg_add_bytes(struct mt_msg *, uint8_t, uint8_t,
	    const void *, size_t);
int	mt_msg_add_u8(struct mt_msg *, uint8_t, uint8_t, uint8_t);
int	mt_msg_add_u16(struct mt_msg *, uint8_t, uint8_t, uint16_t);
int	mt_msg_add_u32(struct mt_msg *, uint8_t, uint8_t, uint32_t);
int	mt_msg_add_u64(struct mt_msg *, uint8_t, uint8_t, uint64_t);

#endif /* _LIBMSGTAP_H_ */
