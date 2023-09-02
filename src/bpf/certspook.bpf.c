// SPDX-License-Identifier: AGPL-3.0-or-later
//
// This module connects to the connect() system call and copies sockaddr
// structs to a ringbuffer to be read by a companion userspace program.

#include <linux/bpf.h>
#include <linux/ptrace.h>
#include <linux/socket.h>
#include <linux/net.h>
#include <linux/tcp.h>
#include <linux/types.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netdb.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_helpers.h>

char LICENSE[] SEC("license") = "GPL";

#ifdef CERTSPOOK_DEBUG
#define debug_msgf(fmt, ...) bpf_printk(fmt, ...)
#else
#define debug_msgf(fmt, ...) if(0){}
#endif


struct sock_common {
  __be32 skc_daddr;
  __be32 skc_rcv_saddr;
  unsigned int skc_hash;
  __be16 skc_dport;
  __u16 skc_num;
	unsigned short		skc_family;
};

struct sock {
  struct sock_common __sk_common;
};

struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 4 * 1024);
} connaddrs SEC(".maps");


SEC("kprobe/__sys_connect")
int BPF_KPROBE(probe_sys_connect, int fd, struct sockaddr *addr, int addrlen) {
  __u16 sk_family;
  struct sockaddr_in addr_in;
  struct sockaddr_in6 addr_in6;

  if (bpf_probe_read_user(&sk_family, sizeof(sk_family), &addr->sa_family) == 0) {
    if (sk_family == AF_INET) {
      if (bpf_probe_read_user(&addr_in, sizeof(addr_in), addr) == 0) {
        bpf_ringbuf_output(&connaddrs, &addr_in, sizeof(addr_in), 0);
      }
    } else if (sk_family == AF_INET6) {
      if (bpf_probe_read_user(&addr_in6, sizeof(addr_in6), addr) == 0) {
        bpf_ringbuf_output(&connaddrs, &addr_in6, sizeof(addr_in6), 0);
      }
    }
  }

  return 0;
}

// SEC("kprobe/tcp_connect")
int BPF_KPROBE(probe_tcp_connect, struct sock *sk) {
  struct sock s1;
  bpf_probe_read_kernel(&s1, sizeof(s1), sk);
  if (s1.__sk_common.skc_family == AF_INET) {
    bpf_ringbuf_output(&connaddrs, &s1.__sk_common.skc_daddr, sizeof(__be32), 0);
  }

  return 0;
}

// The original DNS specification limited names to 255 byte limit:
//     https://www.rfc-editor.org/rfc/rfc1035
// The 2008 internationalization effort retains the 255 byte limit:
//     https://www.rfc-editor.org/rfc/rfc5890#section-4.2
// This is padded by 1 byte because it is unclear to me whether the 255 limit
// accounts for the trailing dot.
#define MAX_HOSTNAME_LEN 256
#define HOSTNAME_BUF_LEN MAX_HOSTNAME_LEN + 1

struct composite_result {
	struct addrinfo **gai_first_result;
	char hostname[HOSTNAME_BUF_LEN];
};

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, __u64);
    __type(value, struct composite_result);
    __uint(max_entries, 256);
} gai_callers SEC(".maps");

// This union exists because sockaddr is possibly the worst API ever created.
union sockaddr_u {
	struct sockaddr_in saddr4;
	struct sockaddr_in6 saddr6;
};

struct exported_gai_result {
	sa_family_t sa_family;
	union sockaddr_u saddr;
	char hostname[HOSTNAME_BUF_LEN];
};

struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 4 * 1024);
} exported_gai_results SEC(".maps");

SEC("uprobe//lib/x86_64-linux-gnu/libc.so.6:getaddrinfo")
int BPF_KPROBE(probe_getaddrinfo, const char *restrict node, const char *restrict service, const struct addrinfo *restrict hints, struct addrinfo **restrict res) {
	__u64 caller = bpf_get_current_pid_tgid();

	struct composite_result comp_res;

	if (bpf_probe_read_user_str(&comp_res.hostname, HOSTNAME_BUF_LEN, node) <= 0) {
		debug_msgf("Hostname could not be copied from getaddrinfo() invocation.");
		goto bail;
	}

	comp_res.gai_first_result = res;

	long update_result = bpf_map_update_elem(&gai_callers, &caller, &comp_res, BPF_ANY);
	if (update_result < 0) {
		debug_msgf("Could not update element in gai_callers map.");
	}

bail:
	return 0;
}

// TODO: Can libbpf be made to load this same function for multiple potential libc locations?
SEC("uretprobe//lib/x86_64-linux-gnu/libc.so.6:getaddrinfo")
int uretprobe_getaddrinfo(struct pt_regs *ctx) {
	debug_msgf("In uretprobe for getaddrinfo()");

	__u64 caller = bpf_get_current_pid_tgid();

	struct composite_result *comp_res;

	if (PT_REGS_RC(ctx) != 0) {
		debug_msgf("getaddrinfo() returned failure code %d -- ignoring", PT_REGS_RC(ctx));
		goto bail;
	}

	comp_res = (struct composite_result *)bpf_map_lookup_elem(&gai_callers, &caller);
	if (comp_res == NULL) {
		debug_msgf("Could not find caller of getaddrinfo().");
		goto bail;
	}

	struct addrinfo *gai_res_ptr;
	struct addrinfo gai_res;
	struct exported_gai_result ex_res;

	if (bpf_probe_read_kernel(&ex_res.hostname, HOSTNAME_BUF_LEN, comp_res->hostname) < 0) {
		debug_msgf("Failed to read hostname from gai_callers value.");
		goto bail;
	}

	if (bpf_probe_read_user(&gai_res_ptr, sizeof(struct addrinfo *), comp_res->gai_first_result) < 0) {
		debug_msgf("Failed to read first getaddrinfo() result.");
		goto bail;
	}

	// Without a fixed address limit the BPF verifier will consider the linked
	// list traversal an infitnite loop.
	__u64 address_cnt = 100;
	while ((address_cnt > 0) && (gai_res_ptr != NULL)) {
		address_cnt--;

		if (bpf_probe_read_user(&gai_res, sizeof(struct addrinfo), gai_res_ptr) < 0) {
			debug_msgf("Could not read getaddrinfo() result %d", &n, sizeof(__u64));
			break;
		}

		long ret;
		struct sockaddr saddr;
		if ((ret = bpf_probe_read_user(&saddr, sizeof(struct sockaddr), gai_res.ai_addr)) < 0) {
			debug_msgf("Failed to copy gai_result: %d", (__u64 *)&ret, sizeof(long));
			goto bail;
		}

		ex_res.sa_family = saddr.sa_family;
		if (saddr.sa_family == AF_INET) {
			if ((ret = bpf_probe_read_user(&ex_res.saddr.saddr4, sizeof(struct sockaddr_in), gai_res.ai_addr)) < 0) {
				debug_msgf("Failed to copy sockaddr_in to exported_gai_result: %d", (__u64 *)&ret, sizeof(long));
				goto bail;
			}
		} else if (saddr.sa_family == AF_INET6) {
			if ((ret = bpf_probe_read_user(&ex_res.saddr.saddr6, sizeof(struct sockaddr_in6), gai_res.ai_addr)) < 0) {
				debug_msgf("Failed to copy sockaddr_in6 to exported_gai_result: %d", (__u64 *)&ret, sizeof(long));
				goto bail;
				// TODO: Should some of these goto bail statements be continue statements?
			}
		} else {
			continue;
		}

		bpf_ringbuf_output(&exported_gai_results, &ex_res, sizeof(struct exported_gai_result), 0);

		if (gai_res.ai_next == NULL) {
			debug_msgf("Found final getaddrinfo() result because ai_next is NULL");
			goto bail;
		}

		gai_res_ptr = gai_res.ai_next;
	}

bail:
	// ignores any error because there isn't any way to recover.
	bpf_map_delete_elem(&gai_callers, &caller);
	return 0;
}
