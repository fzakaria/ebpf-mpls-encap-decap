# MPLS Encapsulation & Decapsulation via eBPF

> This is a small tiny BPF filter that demonstrates how to encap/decap an IPv4 packet with MPLS.

The goal of this project is to be a good learning resource & skeleton project of how to setup
a project for writing & building an eBPF filter. Documentation on the subject is scattered largely for eBPF across man-pages, e-mail lists & blog-posts. What's worse is that the date of publication of many of them are quite old now, and don't reflect the best practices as of today.

The eBPF filter is found in [mpls_bpf_kern.c](https://github.com/fzakaria/epbpf-mpls-encap-decap/blob/master/mpls_bpf_kern.c), with the source __heavily__ commented to help new readers understand what is going on.

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

A simple file [test.sh](https://github.com/fzakaria/epbpf-mpls-encap-decap/blob/master/test.sh) is included that will:

1. Create two network namespaces: machine-1 & machine-2
2. Create a virtual network interface pair; one in each network namespace
3. Setup the network interfaces to be able to ping each other
4. Add a qdisc to the network interfaces
5. Add the compiled bpf filter via tc 

After running the script you should see the output of ping:

```bash
Pinging from machine-1 to machine-2
PING 10.132.204.33 (10.132.204.33) from 10.132.204.25 : 56(84) bytes of data.
64 bytes from 10.132.204.33: icmp_seq=1 ttl=64 time=0.039 ms
64 bytes from 10.132.204.33: icmp_seq=2 ttl=64 time=0.089 ms
64 bytes from 10.132.204.33: icmp_seq=3 ttl=64 time=0.133 ms
64 bytes from 10.132.204.33: icmp_seq=4 ttl=64 time=0.035 ms
64 bytes from 10.132.204.33: icmp_seq=5 ttl=64 time=0.089 ms
```

### Verifying & Debugging

In order to verify all is working let's check the debug trace logs!
(do the following in the host namespace)

```bash
# Turn on tracing logs
echo 1 > /sys/kernel/debug/tracing/tracing_on

# Let's turn on the debug
sudo ./mpls.bin enable                                          
Successfully enabled.

# Confirm it's enabled
sudo ./mpls.bin show  
debug flag: true

# You can cat the pipe
cat /sys/kernel/debug/tracing/trace_pipe


ping-11635 [000] ..s1 136779.910443: 0: [decap][815794764]finished mpls decap.
ping-11635 [000] .... 136780.935386: 0: [encap][2508757858]starting mpls encap.
ping-11635 [000] .... 136780.935404: 0: [encap][2508757858]casted to eth header.
ping-11635 [000] .... 136780.935406: 0: [encap][2508757858]casted to ip header.
ping-11635 [000] .... 136780.935408: 0: [encap][2508757858]calculated ip header length.
ping-11635 [000] .... 136780.935412: 0: [encap][2508757858]about to store bytes of MPLS label: 0x45
ping-11635 [000] .... 136780.935414: 0: [encap][2508757858]finished mpls encap.
ping-11635 [000] ..s1 136780.935426: 0: [decap][1560953898]starting mpls decap.
ping-11635 [000] ..s1 136780.935428: 0: [decap][1560953898]decoded MPLS label: 0x45
ping-11635 [000] ..s1 136780.935430: 0: [decap][1560953898]finished mpls decap.
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

You should be able to view the BPF_MAP also pinned onto the filesystem:

```bash
sudo tree /sys/fs/bpf/tc        

/sys/fs/bpf/tc
└── globals
    └── DEBUGS_MAP

1 directory, 1 file


sudo bpftool map show id 53 -f
53: array  flags 0x0
	key 4B  value 1B  max_entries 1  memlock 4096B
	pinned /sys/fs/bpf/tc/globals/DEBUGS_MAP

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

### Cleanup

Running the [test.sh](https://github.com/fzakaria/epbpf-mpls-encap-decap/blob/master/test.sh) script deletes at the start any network namespace prior and starts off fresh.

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
