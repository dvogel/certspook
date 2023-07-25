// This module connects to the connect() system call and copies sockaddr
// structs to a ringbuffer to be read by a companion userspace program.

#include <linux/bpf.h>
#include <linux/ptrace.h>
#include <linux/socket.h>
#include <linux/net.h>
#include <linux/tcp.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_helpers.h>

char LICENSE[] SEC("license") = "GPL";

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

