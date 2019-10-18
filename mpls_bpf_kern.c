/*******************************************************************************************
 *                              MPLSinIP eBPF
 * This file contains a BPF (Berkeley Packet Filter) for use within tc
 * (traffic-control).
 *
 * BPF is a virtual-machine within the Linux kernel that supports a limited
 * instruction set (not Turing complete). It allows user supplied code to be
 * executed during key points within the kernel. The kernel verifies all BPF
 * programs so that they don't address invalid memory & that the time spent in
 * the BPF program is limited by dis-allowing loops & setting a maximum number
 * of instructions.
 *
 *
 * ----------------------------------------------------------------------------------------
 *  eBPF Guide & Checklist
 *
 * 1. eBPF does not support method calls so any function called from the
 *    entry-point needs to be inlined.
 * 2. The kernel can JIT the eBPF however prior to 4.15, it was off by default
 *    (value 0). echo 1 > /proc/sys/net/core/bpf_jit_enable
 *
 * @author Farid Zakaria <farid.m.zakaria\@gmail.com>
 *******************************************************************************************/

#include <assert.h>
#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/pkt_cls.h>
#include "bpf_endian.h"
#include "bpf_helpers.h"
#include "helpers.h"
#include "mpls.h"

/*
 * For learning purposes let's just use a fixed MPLS label
 */
#define MPLS_STATIC_LABEL 69

/**
 * Adjust room at the network layer
 * (room space is added or removed below the layer 3 header).
 * https://elixir.bootlin.com/linux/v5.3.6/source/include/uapi/linux/bpf.h#L1536
 */
#define BPF_ADJ_ROOM_NET 0

/**
 * A really simple BPF map that controls a switch
 * whether the debug printk messages are emitted.
 */
struct bpf_elf_map SEC("maps") DEBUGS_MAP = {
    .type = BPF_MAP_TYPE_ARRAY,
    .size_key = sizeof(unsigned int),
    .size_value = sizeof(bool),
    .pinning = PIN_GLOBAL_NS,
    .max_elem = 1,
};

/*
 * Check whether the debug flag is set via user space.
 */
bool is_debug(void);

forced_inline bool is_debug() {
  int index = 0;  // the map has size of 1 so index is always 0
  bool *value = (bool *)bpf_map_lookup_elem(&DEBUGS_MAP, &index);
  if (!value) {
    return false;
  }
  return *value;
}

#define bpf_debug_printk(fmt, ...)                               \
  ({                                                             \
    if (unlikely(is_debug())) {                                  \
      char ____fmt[] = fmt;                                      \
      bpf_trace_printk(____fmt, sizeof(____fmt), ##__VA_ARGS__); \
    }                                                            \
  })

/*
 * The Internet Protocol (IP) is defined in RFC 791.
 * The RFC specifies the format of the IP header.
 * In the header there is the IHL (Internet Header Length) field which is 4bit
 * long
 * and specifies the header length in 32bit words.
 * The IHL field can hold values from 0 (Binary 0000) to 15 (Binary 1111).
 * 15 * 32bits = 480bits = 60 bytes
 */
#define MAX_IP_HDR_LEN 60

static_assert(sizeof(struct ethhdr) == ETH_HLEN,
              "ethernet header size does not match.");

/*
 * Since packet handling and printk can be interleaved, this will
 * add a unique identifier for an individual invocation so you can grep the
 * request identifier and see the log messags in isolation.
 *
 * This is a macro because in a real-example you might want to make this
 * a no-op for non-debug builds to avoid the cost of the call.
 */
#define REQUEST_ID() bpf_get_prandom_u32()

#define DEBUG(x, ...) bpf_debug_printk(x, ##__VA_ARGS__)

#define DEBUG_DECAP(id, x, ...) DEBUG("[decap][%u]" x, id, ##__VA_ARGS__)
#define DEBUG_ENCAP(id, x, ...) DEBUG("[encap][%u]" x, id, ##__VA_ARGS__)

/*
 * Entry point for the encapsulation & decapsulation eBPF
 * __sk_buff is a "shadow" struct of the internal sk_buff.
 * You can read more about how sk_buff works at:
 * http://vger.kernel.org/~davem/skb_data.html
 * @skb the socket buffer struct
 */
int mpls_decap_filter(struct __sk_buff *skb);
int mpls_encap_filter(struct __sk_buff *skb);

SEC("mpls_decap") int mpls_decap_filter(struct __sk_buff *skb) {
  // Generate a unique request id so we can identify each flow in
  // the trace logs
  unsigned long long request_id = REQUEST_ID();

  DEBUG_DECAP(request_id, "starting mpls decap.\n");

  /*
   * the redundant casts are needed according to the documentation.
   * possibly for the BPF verifier.
   * https://www.spinics.net/lists/xdp-newbies/msg00181.html
   */
  void *data_end = (void *)(long)skb->data_end;
  void *data = (void *)(long)skb->data;

  // The packet starts with the ethernet header, so let's get that going:
  struct ethhdr *eth = (struct ethhdr *)(data);

  /*
   * Now, we can't just go "eth->h_proto", that's illegal.  We have to
   * explicitly test that such an access is in range and doesn't go
   * beyond "data_end" -- again for the verifier.
   * The eBPF verifier will see that "eth" holds a packet pointer,
   * and also that you have made sure that from "eth" to "eth + 1"
   * is inside the valid access range for the packet.
   */
  if ((void *)(eth + 1) > data_end) {
    DEBUG_DECAP(request_id, "socket buffer struct was malformed.\n");
    return TC_ACT_SHOT;
  }

  /*
   * We only care about IP packet frames. Don't do anything to other ethernet
   * packets like ARP.
   * hton -> host to network order. Network order is always big-endian.
   * pedantic: the protocol is also directly accessible from __sk_buf
   */
  if (eth->h_proto != bpf_htons(ETH_P_IP)) {
    DEBUG_DECAP(request_id, " ethernet is not wrapping IP packet: 0x%x\n",
                bpf_ntohs(eth->h_proto));
    return TC_ACT_OK;
  }

  struct iphdr *iph = (struct iphdr *)(void *)(eth + 1);

  if ((void *)(iph + 1) > data_end) {
    DEBUG_DECAP(request_id, "socket buffer struct was malformed.\n");
    return TC_ACT_SHOT;
  }

  // multiply ip header by 4 (bytes) to get the number of bytes of the header.
  int iph_len = iph->ihl << 2;
  if (iph_len > MAX_IP_HDR_LEN) {
    DEBUG_DECAP(request_id, "ip header is too long: %d.\n", iph_len);
    return TC_ACT_SHOT;
  }

  // https://tools.ietf.org/html/rfc4023
  //==[ETH HDR][IP HDR][MPLS HDR][Data]==
  struct mpls_hdr *mpls = (struct mpls_hdr *)((void *)(iph) + iph_len);

  if ((void *)(mpls + 1) > data_end) {
    DEBUG_DECAP(request_id, "socket buffer struct was malformed.\n");
    return TC_ACT_SHOT;
  }

  struct mpls_entry_decoded mpls_decoded = mpls_entry_decode(mpls);

  DEBUG_DECAP(request_id, "decoded MPLS label: 0x%x\n", mpls_decoded.label);

  if (!is_mpls_entry_bos(mpls)) {
    DEBUG_DECAP(request_id, "mpls label not bottom of stack.\n");
    return TC_ACT_SHOT;
  }

  /*
   * This is the amount of padding we need to remove to be just left
   * with eth * iphdr.
   */
  int padlen = sizeof(struct mpls_hdr);

  /*
   * Grow or shrink the room for data in the packet associated to
   * skb by length and according to the selected mode.
   * BPF_ADJ_ROOM_NET: Adjust room at the network layer
   *  (room space is added or removed below the layer 3 header).
   */
  int ret = bpf_skb_adjust_room(skb, -padlen, BPF_ADJ_ROOM_NET, 0);
  if (ret) {
    DEBUG_DECAP(request_id, "error calling skb adjust room.\n");
    return TC_ACT_SHOT;
  }

  DEBUG_DECAP(request_id, "finished mpls decap.\n");
  return TC_ACT_OK;
}

SEC("mpls_encap") int mpls_encap_filter(struct __sk_buff *skb) {
  // Generate a unique request id so we can identify each flow in
  // the trace logs
  unsigned long long request_id = REQUEST_ID();
  DEBUG_ENCAP(request_id, "starting mpls encap.\n");

  /*
   * the redundant casts are needed according to the documentation.
   * possibly for the BPF verifier.
   * https://www.spinics.net/lists/xdp-newbies/msg00181.html
   */
  void *data_end = (void *)(long)skb->data_end;
  void *data = (void *)(long)skb->data;

  // The packet starts with the ethernet header, so let's get that going:
  struct ethhdr *eth = (struct ethhdr *)(data);

  /*
   * Now, we can't just go "eth->h_proto", that's illegal.  We have to
   * explicitly test that such an access is in range and doesn't go
   * beyond "data_end" -- again for the verifier.
   * The eBPF verifier will see that "eth" holds a packet pointer,
   * and also that you have made sure that from "eth" to "eth + 1"
   * is inside the valid access range for the packet.
   */
  if ((void *)(eth + 1) > data_end) {
    DEBUG_ENCAP(request_id, "socket buffer struct was malformed.\n");
    return TC_ACT_SHOT;
  }

  DEBUG_ENCAP(request_id, "casted to eth header.\n");

  /*
   * We only care about IP packet frames. Don't do anything to other ethernet
   * packets like ARP.
   * hton -> host to network order. Network order is always big-endian.
   * pedantic: the protocol is also directly accessible from __sk_buf
   */
  if (eth->h_proto != bpf_htons(ETH_P_IP)) {
    DEBUG_ENCAP(request_id, "ethernet is not wrapping IP packet: 0x%x\n",
                bpf_ntohs(eth->h_proto));
    return TC_ACT_OK;
  }

  struct iphdr *iph = (struct iphdr *)(void *)(eth + 1);

  if ((void *)(iph + 1) > data_end) {
    DEBUG_ENCAP(request_id, "socket buffer struct was malformed.\n");
    return TC_ACT_SHOT;
  }

  DEBUG_ENCAP(request_id, "casted to ip header.\n");

  // multiply ip header by 4 (bytes) to get the number of bytes of the header.
  int iph_len = iph->ihl << 2;
  if (iph_len > MAX_IP_HDR_LEN) {
    DEBUG_ENCAP(request_id, "ip header is too long: %d\n", iph_len);
    return TC_ACT_SHOT;
  }

  DEBUG_ENCAP(request_id, "calculated ip header length.\n");

  /*
   * This is the amount of padding we need to remove to be just left
   * with eth * iphdr.
   */
  int padlen = sizeof(struct mpls_hdr);

  /*
   * Grow or shrink the room for data in the packet associated to
   * skb by length and according to the selected mode.
   * BPF_ADJ_ROOM_NET: Adjust room at the network layer
   *  (room space is added or removed below the layer 3 header).
   */
  int ret = bpf_skb_adjust_room(skb, padlen, BPF_ADJ_ROOM_NET, 0);
  if (ret) {
    DEBUG_ENCAP(request_id, "error calling skb adjust room.\n");
    return TC_ACT_SHOT;
  }

  DEBUG_ENCAP(request_id, "about to store bytes of MPLS label: 0x%x\n",
              MPLS_STATIC_LABEL);

  // construct our deterministic mpls header
  struct mpls_hdr mpls = mpls_encode(MPLS_STATIC_LABEL, 123, 0, true);

  unsigned long offset = sizeof(struct ethhdr) + (unsigned long)iph_len;
  ret = bpf_skb_store_bytes(skb, (int)offset, &mpls, sizeof(struct mpls_hdr),
                            BPF_F_RECOMPUTE_CSUM);

  DEBUG_ENCAP(request_id, "finished mpls encap.\n");
  return TC_ACT_OK;
}

static char _license[] SEC("license") = "GPL";
