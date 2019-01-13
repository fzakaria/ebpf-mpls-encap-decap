#ifndef BPF_HELPERS_H
#define BPF_HELPERS_H

/* BPF_FUNC_skb_store_bytes flags. */
#define BPF_F_RECOMPUTE_CSUM		(1ULL << 0)

#define PIN_NONE		    0
#define PIN_OBJECT_NS		1
#define PIN_GLOBAL_NS		2

/* 
 * ELF map definition used by iproute2.
 * Cannot figure out how to get bpf_elf.h installed on system, so we've copied it here.
 * iproute2 claims this struct will remain backwards compatible
 * https://github.com/kinvolk/iproute2/blob/be55416addf76e76836af6a4dd94b19c4186e1b2/include/bpf_elf.h
 */
struct bpf_elf_map {
	/*
	 * The various BPF MAP types supported (see enum bpf_map_type)
	 * https://elixir.bootlin.com/linux/latest/source/include/uapi/linux/bpf.h
	 */
	__u32 type;
	__u32 size_key;
	__u32 size_value;
	__u32 max_elem;
	/*
	 * Various flags you can place such as `BPF_F_NO_COMMON_LRU`
	 */
	__u32 flags;
	__u32 id;
	/*
	 * Pinning is how the map are shared across process boundary.
	 * Cillium has a good explanation of them: http://docs.cilium.io/en/v1.3/bpf/#llvm
	 * PIN_GLOBAL_NS - will get pinned to `/sys/fs/bpf/tc/globals/${variable-name}`
	 * PIN_OBJECT_NS - will get pinned to a directory that is unique to this object
	 * PIN_NONE - the map is not placed into the BPF file system as a node,
	 			  and as a result will not be accessible from user space
	 */
	__u32 pinning;
};

/* helper functions called from eBPF programs written in C */
static void *(*bpf_map_lookup_elem)(void *map, void *key) =
	(void *) BPF_FUNC_map_lookup_elem;
static int (*bpf_map_update_elem)(void *map, void *key, void *value,
				  unsigned long long flags) =
	(void *) BPF_FUNC_map_update_elem;
static int (*bpf_map_delete_elem)(void *map, void *key) =
	(void *) BPF_FUNC_map_delete_elem;
static int (*bpf_probe_read)(void *dst, int size, void *unsafe_ptr) =
	(void *) BPF_FUNC_probe_read;
static unsigned long long (*bpf_ktime_get_ns)(void) =
	(void *) BPF_FUNC_ktime_get_ns;
static int (*bpf_trace_printk)(const char *fmt, int fmt_size, ...) =
	(void *) BPF_FUNC_trace_printk;
static void (*bpf_tail_call)(void *ctx, void *map, int index) =
	(void *) BPF_FUNC_tail_call;
static unsigned long long (*bpf_get_smp_processor_id)(void) =
	(void *) BPF_FUNC_get_smp_processor_id;
static unsigned long long (*bpf_get_current_pid_tgid)(void) =
	(void *) BPF_FUNC_get_current_pid_tgid;
static unsigned long long (*bpf_get_current_uid_gid)(void) =
	(void *) BPF_FUNC_get_current_uid_gid;
static int (*bpf_get_current_comm)(void *buf, int buf_size) =
	(void *) BPF_FUNC_get_current_comm;
static unsigned long long (*bpf_perf_event_read)(void *map,
						 unsigned long long flags) =
	(void *) BPF_FUNC_perf_event_read;
static int (*bpf_clone_redirect)(void *ctx, int ifindex, int flags) =
	(void *) BPF_FUNC_clone_redirect;
static int (*bpf_redirect)(int ifindex, int flags) =
	(void *) BPF_FUNC_redirect;
static int (*bpf_redirect_map)(void *map, int key, int flags) =
	(void *) BPF_FUNC_redirect_map;
static int (*bpf_perf_event_output)(void *ctx, void *map,
				    unsigned long long flags, void *data,
				    int size) =
	(void *) BPF_FUNC_perf_event_output;
static int (*bpf_get_stackid)(void *ctx, void *map, int flags) =
	(void *) BPF_FUNC_get_stackid;
static int (*bpf_probe_write_user)(void *dst, void *src, int size) =
	(void *) BPF_FUNC_probe_write_user;
static int (*bpf_current_task_under_cgroup)(void *map, int index) =
	(void *) BPF_FUNC_current_task_under_cgroup;
static int (*bpf_skb_adjust_room)(void *ctx, __s32 len_diff, __u32 mode,
				  __u64 flags) =
	(void *) BPF_FUNC_skb_adjust_room;
static int (*bpf_skb_get_tunnel_key)(void *ctx, void *key, int size, int flags) =
	(void *) BPF_FUNC_skb_get_tunnel_key;
static int (*bpf_skb_set_tunnel_key)(void *ctx, void *key, int size, int flags) =
	(void *) BPF_FUNC_skb_set_tunnel_key;
static int (*bpf_skb_get_tunnel_opt)(void *ctx, void *md, int size) =
	(void *) BPF_FUNC_skb_get_tunnel_opt;
static int (*bpf_skb_set_tunnel_opt)(void *ctx, void *md, int size) =
	(void *) BPF_FUNC_skb_set_tunnel_opt;
static unsigned long long (*bpf_get_prandom_u32)(void) =
	(void *) BPF_FUNC_get_prandom_u32;
static int (*bpf_xdp_adjust_head)(void *ctx, int offset) =
	(void *) BPF_FUNC_xdp_adjust_head;
static int (*bpf_setsockopt)(void *ctx, int level, int optname, void *optval,
			     int optlen) =
	(void *) BPF_FUNC_setsockopt;
static int (*bpf_sk_redirect_map)(void *ctx, void *map, int key, int flags) =
	(void *) BPF_FUNC_sk_redirect_map;
static int (*bpf_sock_map_update)(void *map, void *key, void *value,
				  unsigned long long flags) =
	(void *) BPF_FUNC_sock_map_update;


/* llvm builtin functions that eBPF C program may use to
 * emit BPF_LD_ABS and BPF_LD_IND instructions
 */
unsigned long long load_byte(void *skb,
			     unsigned long long off) asm("llvm.bpf.load.byte");
unsigned long long load_half(void *skb,
			     unsigned long long off) asm("llvm.bpf.load.half");
unsigned long long load_word(void *skb,
			     unsigned long long off) asm("llvm.bpf.load.word");

static int (*bpf_skb_load_bytes)(void *ctx, int off, void *to, int len) =
	(void *) BPF_FUNC_skb_load_bytes;
static int (*bpf_skb_store_bytes)(void *ctx, int off, void *from, int len, int flags) =
	(void *) BPF_FUNC_skb_store_bytes;
static int (*bpf_l3_csum_replace)(void *ctx, int off, int from, int to, int flags) =
	(void *) BPF_FUNC_l3_csum_replace;
static int (*bpf_l4_csum_replace)(void *ctx, int off, int from, int to, int flags) =
	(void *) BPF_FUNC_l4_csum_replace;
static int (*bpf_skb_under_cgroup)(void *ctx, void *map, int index) =
	(void *) BPF_FUNC_skb_under_cgroup;
static int (*bpf_skb_change_head)(void *, int len, int flags) =
	(void *) BPF_FUNC_skb_change_head;

#endif
