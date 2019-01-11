#ifndef MPLS_H
#define MPLS_H

#define MPLS_HLEN 4

/**
 * Have our own version of mpls.h since OracleLinux  does not include newer functionality
 * like encode & decode.
 * sources: https://elixir.bootlin.com/linux/latest/source/include/uapi/linux/mpls.h &
 * https://github.com/torvalds/linux/blob/6f0d349d922ba44e4348a17a78ea51b7135965b1/net/mpls/internal.h
 */

#include "bpf_endian.h"
#include <stdbool.h> 

#define IPPROTO_MPLS 137

#define MPLS_LS_LABEL_MASK      0xFFFFF000
#define MPLS_LS_LABEL_SHIFT     12
#define MPLS_LS_TC_MASK         0x00000E00
#define MPLS_LS_TC_SHIFT        9
#define MPLS_LS_S_MASK          0x00000100
#define MPLS_LS_S_SHIFT         8
#define MPLS_LS_TTL_MASK        0x000000FF
#define MPLS_LS_TTL_SHIFT       0

/* Reserved labels */
#define MPLS_LABEL_IPV4NULL		0 /* RFC3032 */
#define MPLS_LABEL_RTALERT		1 /* RFC3032 */
#define MPLS_LABEL_IPV6NULL		2 /* RFC3032 */
#define MPLS_LABEL_IMPLNULL		3 /* RFC3032 */
#define MPLS_LABEL_ENTROPY		7 /* RFC6790 */
#define MPLS_LABEL_GAL			13 /* RFC5586 */
#define MPLS_LABEL_OAMALERT		14 /* RFC3429 */
#define MPLS_LABEL_EXTENSION		15 /* RFC7274 */

#define MPLS_LABEL_FIRST_UNRESERVED	16 /* RFC3032 */

/* Reference: RFC 5462, RFC 3032
 *
 *  0                   1                   2                   3
 *  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * |                Label                  | TC  |S|       TTL     |
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *
 *	Label:  Label Value, 20 bits
 *	TC:     Traffic Class field, 3 bits
 *	S:      Bottom of Stack, 1 bit
 *	TTL:    Time to Live, 8 bits
 */
struct mpls_hdr {
	unsigned int entry;
};

struct mpls_entry_decoded {
	unsigned int label;
	unsigned char ttl;
	unsigned char tc;
	unsigned char bos;
	//inserted to make -Wpadded happy
	unsigned char align_padding;
};

/*
 * check if the protocol type is either MPLS unicast or MPLS multicast
 */
static inline bool is_eth_p_mpls(unsigned short eth_type)
{
	return eth_type == bpf_htons(ETH_P_MPLS_UC) || eth_type == bpf_htons(ETH_P_MPLS_MC);
}

/*
 * check if the protocol type is either MPLS
 */
static inline bool is_ip_p_mpls(unsigned short ip_type)
{
	return ip_type == bpf_htons(IPPROTO_MPLS);
}

/*
 * test whether mpl header is the bottom of the stack.
 * @param hdr the mpls header to test
 */
static inline bool is_mpls_entry_bos(struct mpls_hdr * hdr)
{
	return hdr->entry & bpf_htonl(MPLS_LS_S_MASK);
}


/*
 * encode the values into the network header.
 * @label the 20bits of MPLS label
 * @ttl time to live
 * @tc traffic class
 * @bos true/false if label is the bottom of the stack
 */
static inline struct mpls_hdr mpls_encode(unsigned int label, unsigned int ttl,
													 unsigned int tc, int bos)
{
	struct mpls_hdr result;
	result.entry =
		//we need to convert from CPU endian to network endian
		bpf_htonl((label << MPLS_LS_LABEL_SHIFT) |
			    (tc << MPLS_LS_TC_SHIFT) |
			    (bos ? (1 << MPLS_LS_S_SHIFT) : 0) |
			    (ttl << MPLS_LS_TTL_SHIFT));
	return result;
}

/*
 * decode the header into a friendlier struct for easy access.
 * @hdr the mpls header
 */
static inline struct mpls_entry_decoded mpls_entry_decode(struct mpls_hdr *hdr)
{
	struct mpls_entry_decoded result;
	//we need to convert from network endian to host endian
	unsigned int entry = bpf_ntohl(hdr->entry);

	result.label = (entry & MPLS_LS_LABEL_MASK) >> MPLS_LS_LABEL_SHIFT;
	result.ttl = (entry & MPLS_LS_TTL_MASK) >> MPLS_LS_TTL_SHIFT;
	result.tc =  (entry & MPLS_LS_TC_MASK) >> MPLS_LS_TC_SHIFT;
	result.bos = (entry & MPLS_LS_S_MASK) >> MPLS_LS_S_SHIFT;

	return result;
}


#endif //MPLS_H