/**
 * Helpful BPF commands to work with endianess.
 * https://github.com/torvalds/linux/blob/6f0d349d922ba44e4348a17a78ea51b7135965b1/tools/testing/selftests/bpf/bpf_endian.h
 */

#ifndef BPF_ENDIAN_H
#define BPF_ENDIAN_H

#include <linux/swab.h>

//briefly turn off clang's -Wno-reserved-id-macro
//since this file uses __ for the macros
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wreserved-id-macro"
/* LLVM's BPF target selects the endianness of the CPU
 * it compiles on, or the user specifies (bpfel/bpfeb),
 * respectively. The used __BYTE_ORDER__ is defined by
 * the compiler, we cannot rely on __BYTE_ORDER from
 * libc headers, since it doesn't reflect the actual
 * requested byte order.
 *
 * Note, LLVM's BPF target has different __builtin_bswapX()
 * semantics. It does map to BPF_ALU | BPF_END | BPF_TO_BE
 * in bpfel and bpfeb case, which means below, that we map
 * to cpu_to_be16(). We could use it unconditionally in BPF
 * case, but better not rely on it, so that this header here
 * can be used from application and BPF program side, which
 * use different targets.
 */
#if __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__
# define __bpf_ntohs(x)			__builtin_bswap16(x)
# define __bpf_htons(x)			__builtin_bswap16(x)
# define __bpf_constant_ntohs(x)	___constant_swab16(x)
# define __bpf_constant_htons(x)	___constant_swab16(x)
# define __bpf_ntohl(x)			__builtin_bswap32(x)
# define __bpf_htonl(x)			__builtin_bswap32(x)
# define __bpf_constant_ntohl(x)	___constant_swab32(x)
# define __bpf_constant_htonl(x)	___constant_swab32(x)
#elif __BYTE_ORDER__ == __ORDER_BIG_ENDIAN__
# define __bpf_ntohs(x)			(x)
# define __bpf_htons(x)			(x)
# define __bpf_constant_ntohs(x)	(x)
# define __bpf_constant_htons(x)	(x)
# define __bpf_ntohl(x)			(x)
# define __bpf_htonl(x)			(x)
# define __bpf_constant_ntohl(x)	(x)
# define __bpf_constant_htonl(x)	(x)
#else
# error "Fix your compiler's __BYTE_ORDER__?!"
#endif
#pragma clang diagnostic pop

#define bpf_htons(x)				\
	(__builtin_constant_p(x) ?		\
	 __bpf_constant_htons(x) : __bpf_htons(x))
#define bpf_ntohs(x)				\
	(__builtin_constant_p(x) ?		\
	 __bpf_constant_ntohs(x) : __bpf_ntohs(x))
#define bpf_htonl(x)				\
	(__builtin_constant_p(x) ?		\
	 __bpf_constant_htonl(x) : __bpf_htonl(x))
#define bpf_ntohl(x)				\
	(__builtin_constant_p(x) ?		\
	 __bpf_constant_ntohl(x) : __bpf_ntohl(x))

#endif /* BPF_ENDIAN_H */