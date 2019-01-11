/*******************************************************************************************
 *                              MPLS eBPF
 * This file contains an BPF (Berkely Packet Filter) for use within lwtunnel.
 *
 * BPF is a virtual-machine within the Linux kernel that supports a limited
 * instruction set (not turning complete). It allows user supplied code to be
 * executed during key points within the kernel. The kernel verifies all BPF
 * programs such that they don't address invalid memory & that the time spent in
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
#include "bpf_endian.h"
#include "bpf_helpers.h"
#include "helpers.h"
#include "mpls.h"

#define BPF_DROP 2
#define BPF_OK 0
#define BPF_ADJ_ROOM_NET 0

/*
 * The Internet Protocol (IP) is defined in RFC 791.
 * The RFC specifies the format of the IP header.
 * In the header there is the IHL (Internet Header Length) field which is 4bits
 * long
 * and specifies the header length in 32bit words.
 * The IHL field can hold values from 0 (Binary 0000) to 15 (Binary 1111).
 * 15 * 32bits = 480bits = 60 bytes
 */
#define MAX_IP_HDR_LEN 60

static_assert(sizeof(struct ethhdr) == ETH_HLEN,
              "ethernet header size does not match.");

/*
 * Entry point for the decapsulation eBPF
 * __sk_buff is a "shadow" struct of the internal sk_buff.
 * You can read more how sk_buff works
 * http://vger.kernel.org/~davem/skb_data.html
 * @skb the socket buffer struct
 */
int mpls_decap(struct __sk_buff *skb);

SEC("mpls_decap") int mpls_decap(struct __sk_buff *skb) {
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
    bpf_printk("socket buffer struct was malformed.\n");
    return BPF_DROP;
  }

  /*
   * We only care about IP packet frames. Don't do anything to other ethernet
   * packets like ARP.
   * hton -> host to network order. Network order is always big-endian.
   * pedantic: the protocol is also directly accessible from __sk_buf
   */
  if (eth->h_proto != bpf_htons(ETH_P_IP)) {
    bpf_printk("ethernet is not wrapping IP packet.\n");
    return BPF_OK;
  }

  struct iphdr *iph = (struct iphdr *)(void *)(eth + 1);

  if ((void *)(iph + 1) > data_end) {
    bpf_printk("socket buffer struct was malformed.\n");
    return BPF_DROP;
  }

  // multiply ip header by 4 (bytes) to get the number of bytes of the header.
  int iph_len = iph->ihl << 2;
  if (iph_len > MAX_IP_HDR_LEN) {
    bpf_printk("ip header is too long.\n");
    return BPF_DROP;
  }

  // https://tools.ietf.org/html/rfc4023
  //==[ETH HDR][IP HDR][MPLS HDR][Data]==
  struct mpls_hdr *mpls = (struct mpls_hdr *)((void *)(iph) + iph_len);

  if ((void *)(mpls + 1) > data_end) {
    bpf_printk("socket buffer struct was malformed.\n");
    return BPF_DROP;
  }

  struct mpls_entry_decoded mpls_decoded = mpls_entry_decode(mpls);

  bpf_printk("decoded MPLS label: %#x\n", mpls_decoded.label);

  if (!is_mpls_entry_bos(mpls)) {
    bpf_printk("mpls label not bottom of stack.\n");
    return BPF_DROP;
  }

  /*
   * We are going to shrink the skb which will overwrite the
   */
  struct ethhdr eth_copy;
  int ret = bpf_skb_load_bytes(skb, 0, &eth_copy, sizeof(struct ethhdr));
  if (ret) {
    bpf_printk("error calling skb load bytes.\n");
    return BPF_DROP;
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
  ret = bpf_skb_adjust_room(skb, -padlen, BPF_ADJ_ROOM_NET, 0);
  if (ret) {
    bpf_printk("error calling skb adjust room.\n");
    return BPF_DROP;
  }

  return 0;
}

static char _license[] SEC("license") = "GPL";
