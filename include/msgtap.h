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

#ifndef _MSGTAP_H_
#define _MSGTAP_H_

/*
 *    0                   1                   2                   3
 *    0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
 *   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *   |Version| Reserved              | Type of Message               |
 *   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *   | Metadata Length                                               |
 *   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *   | Length                                                        |
 *   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *   | Captured                                                      |
 *   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *
 * Version (4 bits): The current version number is 0.
 *
 * Reserved (12 bits): These bits MUST be zero when messages are
 * generated, and MUST be ignored when processed.
 *
 * Type of Message (16 bits): Identifies the type of data in the message.
 *
 * Metadata Length (32 bits): The amount of metadata attached to the
 * message, in bytes.
 *
 * Length (32 bits): The original length of the data attached to this
 * message.
 *
 * Captured (32 bits): The amount of data attached to this message.
 * The amount of data that is captured may be less than the original
 * length of the message.
 */

struct msgtap_header {
	uint16_t	mh_flags;
#define MSGTAP_F_VERSION	0xf000
#define MSGTAP_F_VERSION_0		0x0000
	uint16_t	mh_type;
#define MSGTAP_TYPE_DNS		53
	uint32_t	mh_metalen;	/* length of all metadata in bytes */
	uint32_t	mh_msglen;	/* original message length in bytes */
	uint32_t	mh_caplen;	/* captured message bytes */
};

/*
 *    0                   1                   2                   3
 *    0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
 *   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *   | Class         | Type          | Length                        |
 *   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 */

struct msgtap_metadata {
	uint8_t		md_class;
	uint8_t		md_type;
	uint16_t	md_len;		/* length in bytes */
};

#define MSGTAP_CLASS_BASE	0x00
#define MSGTAP_CLASS_TYPED	0xff	/* MD class depends on message type */

/*
 * Base class types
 */
#define MSGTAP_T_PAD		0x00	/* no metadata, just padding */

#define MSGTAP_T_ORG		0x01
#define MSGTAP_T_SERVICE	0x02
#define MSGTAP_T_SITE		0x03
#define MSGTAP_T_HOSTNAME	0x04
#define MSGTAP_T_NAME		0x05
#define MSGTAP_T_COMPONENT	0x06
#define MSGTAP_T_EXTRA		0x07
#define MSGTAP_T_FILE		0x08
#define MSGTAP_T_FUNC		0x09
#define MSGTAP_T_LINE		0x0a	/* uint32 */
#define MSGTAP_T_LINE_LEN		4

#define MSGTAP_T_PID		0x0b	/* uint32 */
#define MSGTAP_T_PID_LEN		4
#define MSGTAP_T_TID		0x0c	/* uint32 */
#define MSGTAP_T_TID_LEN		4

#define MSGTAP_T_SEQ32		0x10	/* counter32 */
#define MSGTAP_T_SEQ32_LEN	4
#define MSGTAP_T_SEQ64		0x10	/* counter64 */
#define MSGTAP_T_SEQ64_LEN	8

/* The time at which the message was generated */
#define MSGTAP_T_TS		0x11	/* uint64 nsec after the unix epoch */
#define MSGTAP_T_TS_LEN			8
#define MSGTAP_T_TS_PRECISION	0x12	/* uint64 nsec */
#define MSGTAP_T_TS_PRECISION_LEN	8
/* How long the event took */
#define MSGTAP_T_TM		0x13	/* uint64 nsec interval */
#define MSGTAP_T_TM_LEN			8
#define MSGTAP_T_TM_PRECISION	0x14	/* uint64 nsec */
#define MSGTAP_T_TM_PRECISION_LEN	8

#define MSGTAP_T_NET_PRIO	0x20	/* actually 3 bits */
#define MSGTAP_T_NET_PRIO_LEN		1
#define MSGTAP_T_NET_DIR	0x21
#define MSGTAP_T_NET_DIR_LEN		1
#define MSGTAP_T_NET_DIR_UNKNOWN	0
#define MSGTAP_T_NET_DIR_IN		1
#define MSGTAP_T_NET_DIR_OUT		2
#define MSGTAP_T_NET_DIR_BOTH		3
#define MSGTAP_T_NET_FLOWID	0x22	/* uint? */

#define MSGTAP_T_IP		0x30	/* flag */
#define MSGTAP_T_IPV4		0x31	/* flag */
#define MSGTAP_T_IPV6		0x32	/* flag */
#define MSGTAP_T_IPSRCADDR	0x33
#define MSGTAP_T_IPDSTADDR	0x34

#define MSGTAP_T_IPPROTO	0x35
#define MSGTAP_T_IPPROTO_LEN		1
#define MSGTAP_T_IPPROTO_TCP		6
#define MSGTAP_T_IPPROTO_UDP		17

#define MSGTAP_T_IPSRCPORT	0x36
#define MSGTAP_T_IPSRCPORT_LEN		2
#define MSGTAP_T_IPDSTPORT	0x37
#define MSGTAP_T_IPDSTPORT_LEN		2

#define MSGTAP_T_IPECN		0x38
#define MSGTAP_T_IPECN_LEN		1

#endif /* _MSGTAP_H_ */
