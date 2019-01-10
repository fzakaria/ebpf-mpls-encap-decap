/**
 * A collection of useful definitions when writing eBPF.
 * Some of these were taken from https://github.com/iovisor/bcc/blob/master/src/cc/export/helpers.h
 */

#ifndef HELPERS_H
#define HELPERS_H

#include "bpf_helpers.h"

/* 
 * helper macro to place programs, maps, license in
 * different sections in elf_bpf file. Section names
 * are interpreted by elf_bpf loader
 */
#define SEC(NAME) __attribute__((section(NAME), used))

/*
 * helper macro to make it simpler to print trace messages to
 * bpf_trace_printk.
 * ex. bpf_printk("BPF command: %d\n", op);
 * you can find the output in /sys/kernel/debug/tracing/trace_pipe
 * however it will collide with any othe rrunning process.
 */
#define bpf_printk(fmt, ...)							\
({														\
	       char ____fmt[] = fmt;						\
	       bpf_trace_printk(____fmt, sizeof(____fmt),	\
				##__VA_ARGS__);							\
})

/*
 * The __builtin_expect macros are GCC specific macros that use the branch prediction;
 * they tell the processor whether a condition is likely to be true,
 * so that the processor can prefetch instructions on the correct "side" of the branch.
 */
#define likely(x) __builtin_expect(!!(x), 1)
#define unlikely(x) __builtin_expect(!!(x), 0)

#endif