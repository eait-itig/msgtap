/*	$OpenBSD */

/*
 * Copyright (c) 2019 David Gwynne <dlg@openbsd.org>
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

#ifndef _DNSMSGTAP_H_
#define _DNSMSGTAP_H_

#define DNSMSGTAP_PROTOCOL	0x03
#define DNSMSGTAP_PROTOCOL_LEN	1
#define DNSMSGTAP_PROTOCOL_UDP		1
#define DNSMSGTAP_PROTOCOL_TCP		2
#define DNSMSGTAP_PROTOCOL_DOT		3
#define DNSMSGTAP_PROTOCOL_DOH		4

/*
 * The "zone" or "bailiwick" pertaining to the DNS query message.
 * This is a wire-format DNS domain name.
 */
#define DNSMSGTAP_QUERY_ZONE	0x0b

#define DNSMSGTAP_MSGTYPE	0x0f
#define DNSMSGTAP_MSGTYPE_LEN	1
#define DNSMSGTAP_MSGTYPE_AQ		1	/* AUTH_QUERY */
#define DNSMSGTAP_MSGTYPE_AR		2	/* AUTH_RESPONSE */
#define DNSMSGTAP_MSGTYPE_RQ		3	/* RESOLVER_QUERY */
#define DNSMSGTAP_MSGTYPE_RR		4	/* RESOLVER_RESPONSE */
#define DNSMSGTAP_MSGTYPE_CQ		5	/* CLIENT_QUERY */
#define DNSMSGTAP_MSGTYPE_CR		6	/* CLIENT_RESPONSE */
#define DNSMSGTAP_MSGTYPE_FQ		7	/* FORWARDER_QUERY */
#define DNSMSGTAP_MSGTYPE_FR		8	/* FORWARDER_RESPONSE */
#define DNSMSGTAP_MSGTYPE_SQ		9	/* STUB_QUERY */
#define DNSMSGTAP_MSGTYPE_SR		10	/* STUB_RESPONSE */
#define DNSMSGTAP_MSGTYPE_TQ		11	/* TOOL_QUERY */
#define DNSMSGTAP_MSGTYPE_TR		12	/* TOOL_RESPONSE */
#define DNSMSGTAP_MSGTYPE_UQ		13	/* UPDATE_QUERY */
#define DNSMSGTAP_MSGTYPE_UR		14	/* UPDATE_RESPONSE */

#endif /* _DNSMSGTAP_H_ */
