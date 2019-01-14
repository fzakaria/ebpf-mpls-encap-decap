#include <linux/bpf.h>
#include <stdio.h>
#include <unistd.h>

/*********************************************************************************
 * Copied only relevant needed libbpf helpers from mini library
 * found: https://elixir.bootlin.com/linux/v4.4/source/samples/bpf/libbpf.h#L19
 *********************************************************************************/

/*
 * When building perf, unistd.h is override. Define NR_bpf is
 * required to be defined.
 */
#ifndef NR_bpf
#if defined(__i386__)
#define NR_bpf 357
#elif defined(__x86_64__)
#define NR_bpf 321
#elif defined(__aarch64__)
#define NR_bpf 280
#else
#error NR_bpf not defined. libbpf does not support your arch.
#endif
#endif

static unsigned long ptr_to_u64(const void *ptr) { return (unsigned long)ptr; }

long bpf_obj_get(const char *pathname);
long bpf_map_update_elem(unsigned int fd, void *key, void *value,
                         unsigned long long flags);
long bpf_map_lookup_elem(unsigned int fd, void *key, void *value);

long bpf_obj_get(const char *pathname) {
  union bpf_attr attr = {
      .pathname = ptr_to_u64((const void *)pathname),
  };

  return syscall(NR_bpf, BPF_OBJ_GET, &attr, sizeof(attr));
}

long bpf_map_update_elem(unsigned int fd, void *key, void *value,
                         unsigned long long flags) {
  union bpf_attr attr = {
      .map_fd = fd,
      .key = ptr_to_u64(key),
      .value = ptr_to_u64(value),
      .flags = flags,
  };

  return syscall(NR_bpf, BPF_MAP_UPDATE_ELEM, &attr, sizeof(attr));
}

long bpf_map_lookup_elem(unsigned int fd, void *key, void *value) {
  union bpf_attr attr = {
      .map_fd = fd, .key = ptr_to_u64(key), .value = ptr_to_u64(value),
  };

  return syscall(NR_bpf, BPF_MAP_LOOKUP_ELEM, &attr, sizeof(attr));
}

/*********************************************************************************/

int main(int argc, char **argv) {
  int i;

  printf("argc = %d\n", argc);
  for (i = 0; i < argc; i++) printf("arg[%d] = \"%s\"\n", i, argv[i]);
}