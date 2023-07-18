//go:build ignore

//##include "common.h"
//#include "bpf_tracing.h"
#define __TARGET_ARCH_x86

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_tracing.h>

char __license[] SEC("license") = "Dual MIT/GPL";

struct event {
	u32 pid;
	u8 buf[80];
	u32 buf_size;
	int ret;
};

struct {
	__uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
} events SEC(".maps");

// Force emitting struct event into the ELF.
const struct event *unused __attribute__((unused));

SEC("uretprobe/SSL_read")
int uretprobe_SSL_read(struct pt_regs *ctx) {
	struct event event;

	event.pid = bpf_get_current_pid_tgid();
	bpf_probe_read(&event.buf, sizeof(event.buf), (void *)PT_REGS_PARM2(ctx));
	bpf_probe_read(&event.buf_size, sizeof(event.buf_size), (void *)PT_REGS_PARM3(ctx));
	bpf_probe_read(&event.ret, sizeof(event.ret), (void *)PT_REGS_RC(ctx));

	bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU, &event, sizeof(event));

	return 0;
}