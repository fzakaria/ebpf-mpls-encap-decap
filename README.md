# MPLS Encapsulation & Decapsulation via eBPF 

> This is a small tiny BPF filter that demonstrates how to encap/decap an IPv4 packet with MPLS.

This goals of this project is to be a good learning resource & skeleton project of how best to setup
a project for writing & building an eBPF filter. Documentation on the subject is scattered largely for eBPF across man-pages, e-mail lists & blog-posts. What's worse, is that the date of publication of many of them are quite old now, and don't reflect the best practices as of today.

## Building 

You can build on an _OracleLinux 7.6_ machine or there is limited support for OSX via _docker_.

## OracleLinux

Simply use the provided `Makefile`.

```bash
make
```

## Mac / OSX

Simply use the provided `Makefile` but be sure to run the `docker` target.

```bash
# install llvm latest if you don't have it!
brew install --with-toolchain llvm
# builds the BPF filter in an OracleLinux docker image
make docker
```