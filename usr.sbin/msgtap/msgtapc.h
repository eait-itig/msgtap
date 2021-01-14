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

struct msgtap_md_type {
	uint8_t		  mdt_id;
	int		  mdt_len;

	const char	 *mdt_name;
	void		(*mdt_handler)(const struct msgtap_metadata *,
			      const void *, size_t);
};

struct msgtap_md_class {
	uint8_t		  mdc_id;
	const char	 *mdc_name;

	const struct msgtap_md_type
			 *mdc_types;
	unsigned int	  mdc_ntypes;
	void		(*mdc_dump)(const void *, size_t, size_t);
};

void	msgtap_md_default(const struct msgtap_metadata *,
	    const void *, size_t);
void	msgtap_md_string(const struct msgtap_metadata *,
	    const void *, size_t);

extern const struct msgtap_md_class msgtap_md_class_base;
extern const struct msgtap_md_class msgtap_md_class_dns;

void	hexdump(const void *, size_t);
