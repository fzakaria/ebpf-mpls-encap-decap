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
#include <linux/mpls.h>
#include "bpf_endian.h"
#include "bpf_helpers.h"
#include "helpers.h"

#define BPF_DROP 2
#define BPF_OK 0

static_assert(sizeof(struct ethhdr) == ETH_HLEN,
              "ethernet header size does not match.");

/*
 * Entry point for the encapsulation eBPF
 * __sk_buff is a "shadow" struct of the internal sk_buff.
 * You can read more how sk_buff works
 * http://vger.kernel.org/~davem/skb_data.html
 * @skb the socket buffer struct
 */
int mpls_encap(struct __sk_buff *skb);

SEC("mpls_encap") int mpls_encap(struct __sk_buff *skb) {
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

  // Why does
  struct iphdr *iph = (struct iphdr *)(void *)(eth + 1);

  if ((void *)(iph + 1) > data_end) {
    bpf_printk("socket buffer struct was malformed.\n");
    return BPF_DROP;
  }

  return 0;
}

static char _license[] SEC("license") = "GPL";
