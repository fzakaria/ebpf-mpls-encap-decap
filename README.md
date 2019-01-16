# MPLS Encapsulation & Decapsulation via eBPF

> This is a small tiny BPF filter that demonstrates how to encap/decap an IPv4 packet with MPLS.

The goal of this project is to be a good learning resource & skeleton project of how to setup
a project for writing & building an eBPF filter. Documentation on the subject is scattered largely for eBPF across man-pages, e-mail lists & blog-posts. What's worse is that the date of publication of many of them are quite old now, and don't reflect the best practices as of today.

The eBPF filter is found in [mpls_bpf_kern.c](https://github.com/fzakaria/eBPF-mpls-encap-decap/blob/master/mpls_bpf_kern.c), with the source __heavily__ commented to help new readers understand what is going on.

## MPLSinIP

This example performs MPLSinIP encapsulation/decapsulation as defined in [RFC4023](https://tools.ietf.org/html/rfc4023).

MPLS-in-IP messages have the following format:

```
             +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
             |                                     |
             |             IP Header               |
             |                                     |
             +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
             |                                     |
             |          MPLS Label Stack           |
             |                                     |
             +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
             |                                     |
             |            Message Body             |
             |                                     |
             +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
```

MPLS label is defined in [RFC3032](https://tools.ietf.org/html/rfc3032):

```
   0                   1                   2                   3
   0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
  |                Label                  | TC  |S|       TTL     |
  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

 	Label:  Label Value, 20 bits
 	TC:     Traffic Class field, 3 bits
 	S:      Bottom of Stack, 1 bit
 	TTL:    Time to Live, 8 bits
 ```

For the purpose of this _demo_, the MPLS label is always **0x45**, however more advanced label switching would
perform different actions based on the label value.

## Testing

### Setup Virtual Network Interfaces

We will first create a pair of virtual network interfaces that will serve as the encap/decap pair for testing
purposes. In order to use Linux `tc` with a virtual interface, one of them __must be__ placed within a network namespace.

```bash
ip link add veth0 type veth peer name veth1
ip netns add test
ip link set veth0 netns test
ip link set veth1 up
ip netns exec test ip link set veth0 up
ip addr add 10.1.0.2/24 dev veth1
ip netns exec test ip addr add 10.1.0.1/24 dev veth0

# Add a qdisc to both devices in order to attach bpf filters
tc qdisc add dev veth1 clsact
ip netns exec test tc qdisc add dev veth0 clsact

# Verify you can ping!
ping -I 10.1.0.2 10.1.0.1
PING 10.1.0.1 (10.1.0.1) from 10.1.0.2 : 56(84) bytes of data.
64 bytes from 10.1.0.1: icmp_seq=1 ttl=64 time=0.077 ms
64 bytes from 10.1.0.1: icmp_seq=2 ttl=64 time=0.074 ms
64 bytes from 10.1.0.1: icmp_seq=3 ttl=64 time=0.073 ms
```

### Adding eBPF Filters

We've set verbose flag, so you will see the output of the eBPF verifier. The command below uses `ip netns exec` to run `tc` for the device in the network namespace.

```bash
ip netns exec test tc filter add dev veth0 ingress bpf da obj mpls.bpf sec mpls_decap verbose
tc filter add dev veth1 egress bpf da obj mpls.bpf sec mpls_encap verbose

# Verify you can see them !
ip netns exec test tc filter show dev veth0 ingress
tc filter show dev veth1 egress

# Verify you can ping!
ping -I 10.1.0.2 10.1.0.1
PING 10.1.0.1 (10.1.0.1) from 10.1.0.2 : 56(84) bytes of data.
64 bytes from 10.1.0.1: icmp_seq=1 ttl=64 time=0.077 ms
64 bytes from 10.1.0.1: icmp_seq=2 ttl=64 time=0.074 ms
64 bytes from 10.1.0.1: icmp_seq=3 ttl=64 time=0.073 ms
```

### Verifying & Debugging

In order to verify all is working let's check the debug trace logs!

```bash
# Turn on tracing logs
echo 1 > /sys/kernel/debug/tracing/tracing_on

# You can cat the pipe
cat /sys/kernel/debug/tracing/trace_pipe

# tc also provides a simple way to view it
tc exec bpf dbg

ping-3964  [001] .... 174556.399525: 0x00000001: [encap] about to store bytes of MPLS label: 0x45
ping-3964  [001] .... 174556.399526: 0x00000001: [encap] finished mpls encap.
ping-3964  [001] ..s1 174556.399534: 0x00000001: [decap] starting mpls decap.
ping-3964  [001] ..s1 174556.399536: 0x00000001: [decap] decoded MPLS label: 45
ping-3964  [001] ..s1 174556.399537: 0x00000001: [decap] finished mpls decap.
<idle>-0   [001] ..s. 174559.791288: 0x00000001: [encap] starting mpls encap.
```

You can list all BPF programs loaded:

```bash
bpftool prog

42: sched_cls  tag c2678af39418836e
	xlated 1640B  jited 963B  memlock 4096B
43: sched_cls  tag aa3fa6025585b31a
	xlated 1888B  jited 1100B  memlock 4096B
```

You can also view the output of the JIT if you run the following.

```bash
bpftool prog dump jited id 42

...
 3b4:	mov    $0x1e,%esi
 3b9:	callq  0xffffffffc7ed7c16
 3be:	jmpq   0x0000000000000197
...

# On older linux kernels, you have to explicitly turn on JIT
# echo 1 > /proc/sys/net/core/bpf_jit_enable
```

You can use `llvm-objdump` to also see the contents of the eBPF

```bash
# -g prints the line numbers
# -S prints the instructions with associated C code
llvm-objdump -S -g mpls.bpf
```

### Userland command

A `mpls.bin` command is provided, that allows interacting with the eBPF program loaded.
You can _enable_ or _disable_ the debug output.

This will change the visibility of the debug print messages in `/sys/kernel/debug/tracing/trace_pipe` 

```bash
./mpls.bin show
debug flag: false

 ./mpls.bin enable
Successfully enabled.
```

> Note: enable & disable only affects the veth in the current namespace which has its own BPF map in `/sys/fs/bpf/ip/globals/DEBUGS_MAP`. Using `ip netns exec test` also did not work, as the _bpf filesystem_ was no longer mounted.

### Cleanup

You can cleanup the tc filters:

```bash
ip netns exec test tc filter del dev veth0 ingress
tc filter del dev veth1 egress
```

## Building

You can build on an _OracleLinux 7.6_ machine or there is limited support for OSX via _docker_.

### OracleLinux

Simply use the provided `Makefile`.

```bash
make
```

### Mac / OSX

Simply use the provided `Makefile` but be sure to run the `docker` target.

```bash
# Install llvm latest if you don't have it!
brew install --with-toolchain llvm
# Builds the BPF filter in an OracleLinux docker image
make docker
```
