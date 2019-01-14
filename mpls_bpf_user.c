#include <argp.h>
#include <errno.h>
#include <linux/bpf.h>
#include <stdbool.h>
#include <stdio.h>
#include <string.h>
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

/* flags for BPF_MAP_UPDATE_ELEM command */
#define BPF_ANY 0     /* create new element or update existing */
#define BPF_NOEXIST 1 /* create new element only if it didn't exist */
#define BPF_EXIST 2   /* only update existing element */

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

/**
 * When PIN_GLOBAL_NS is used, this is deafult global namespace that is loaded.
 */
static const char *TC_GLOBAL_NS = "/sys/fs/bpf/tc/globals";

/**
 * The name of the BPF MAP variable in mpls_bpf_berk.c
 */
static const char *BPF_MAP_NAME = "DEBUGS_MAP";

const char *argp_program_version = "mpls_bpf_user 1.0";
const char *argp_program_bug_address = "<farid.m.zakaria@gmail.com>";

/* Program documentation. */
static char doc[] = "MPLSoIP User-- a program to interfact with the eBPF code.";

/* A description of the arguments we accept. */
static char args_doc[] = "[show] [disable|enable]";

/*
   OPTIONS.  Field 1 in ARGP.
   Order of fields: {NAME, KEY, ARG, FLAGS, DOC}.
*/
static struct argp_option options[] = {
    {0, 0, 0, 0, 0, 0},
};

/* This structure is used by main to communicate with parse_opt. */
struct arguments {
  void (*cmd)(void);
};

void show(void);
void disable(void);
void enable(void);
long get_map_fd(void);

long get_map_fd(void) {
  char pinned_file[256];
  snprintf(pinned_file, sizeof(pinned_file), "%s/%s", TC_GLOBAL_NS,
           BPF_MAP_NAME);
  return bpf_obj_get(pinned_file);
}

void show(void) {
  long fd = get_map_fd();
  if (fd < 0) {
    fprintf(stderr, "could not find map %s [%s]. Default is false.\n",
            BPF_MAP_NAME, strerror(errno));
    return;
  }

  bool value = false;
  int index = 0;
  bpf_map_lookup_elem((unsigned int)fd, &index, &value);
  printf("%s", value ? "true" : "false");
}

void disable(void) {
  long fd = get_map_fd();
  if (fd < 0) {
    fprintf(stderr, "could not find map %s [%s]. Cannot disable.\n",
            BPF_MAP_NAME, strerror(errno));
    return;
  }
  int index = 0;
  bool value = false;
  long ret = bpf_map_update_elem((unsigned int)fd, &index, &value, BPF_ANY);
  if (!ret) {
    fprintf(stderr, "Could not update element [%s].\n", strerror(errno));
  }
}

void enable(void) {
  long fd = get_map_fd();
  if (fd < 0) {
    fprintf(stderr, "could not find map %s [%s]. Cannot enable.\n",
            BPF_MAP_NAME, strerror(errno));
    return;
  }
  bool value = false;
  int index = 0;
  long ret = bpf_map_update_elem((unsigned int)fd, &index, &value, BPF_ANY);
  if (!ret) {
    fprintf(stderr, "Could not update element [%s].\n", strerror(errno));
  }
}

static error_t parse_opt(int key, char *arg, struct argp_state *state) {
  /* Get the input argument from argp_parse, which we
   know is a pointer to our arguments structure. */
  struct arguments *arguments = state->input;
  switch (key) {
    case ARGP_KEY_NO_ARGS:
      argp_usage(state);
      break;
    case ARGP_KEY_ARG:
      if (strcmp(arg, "show") == 0) {
        arguments->cmd = &show;
      } else if (strcmp(arg, "disable") == 0) {
        arguments->cmd = &disable;
      } else if (strcmp(arg, "enable") == 0) {
        arguments->cmd = &enable;
      } else {
        argp_error(state, "%s is not a valid command", arg);
      }
      break;
    default:
      return ARGP_ERR_UNKNOWN;
  }
  return 0;
}

/* Our argp parser. */
static struct argp argp = {options, parse_opt, args_doc, doc, 0, 0, 0};

int main(int argc, char **argv) {
  struct arguments arguments;
  arguments.cmd = NULL;
  /* Where the magic happens */
  argp_parse(&argp, argc, argv, 0, 0, &arguments);
  if (arguments.cmd != NULL) {
    void (*cmd)(void) = arguments.cmd;
    (*cmd)();
  }
}