package link

import (
	"errors"
	"fmt"
	"github.com/cilium/ebpf"
	"github.com/isu-kim/dyn-uprobe/internal/sys"
	"github.com/isu-kim/dyn-uprobe/internal/unix"
)

type tracing struct {
	RawLink
}

func (f *tracing) Update(new *ebpf.Program) error {
	return fmt.Errorf("tracing update: %w", ErrNotSupported)
}

type TracingOptions struct {
	// Program must be of type Tracing with attach type
	// AttachTraceFEntry/AttachTraceFExit/AttachModifyReturn or
	// AttachTraceRawTp.
	Program *ebpf.Program
	// Program attach type. Can be one of:
	// 	- AttachTraceFEntry
	// 	- AttachTraceFExit
	// 	- AttachModifyReturn
	// 	- AttachTraceRawTp
	// This field is optional.
	AttachType ebpf.AttachType
	// Arbitrary value that can be fetched from an eBPF program
	// via `bpf_get_attach_cookie()`.
	Cookie uint64
}

type LSMOptions struct {
	// Program must be of type LSM with attach type
	// AttachLSMMac.
	Program *ebpf.Program
	// Arbitrary value that can be fetched from an eBPF program
	// via `bpf_get_attach_cookie()`.
	Cookie uint64
}

// attachBTFID links all BPF program types (Tracing/LSM) that they attach to a btf_id.
func attachBTFID(program *ebpf.Program, at ebpf.AttachType, cookie uint64) (Link, error) {
	if program.FD() < 0 {
		return nil, fmt.Errorf("invalid program %w", sys.ErrClosedFd)
	}

	var (
		fd  *sys.FD
		err error
	)
	switch at {
	case ebpf.AttachTraceFEntry, ebpf.AttachTraceFExit, ebpf.AttachTraceRawTp,
		ebpf.AttachModifyReturn, ebpf.AttachLSMMac:
		// Attach via BPF link
		fd, err = sys.LinkCreateTracing(&sys.LinkCreateTracingAttr{
			ProgFd:     uint32(program.FD()),
			AttachType: sys.AttachType(at),
			Cookie:     cookie,
		})
		if err == nil {
			break
		}
		if !errors.Is(err, unix.EINVAL) && !errors.Is(err, sys.ENOTSUPP) {
			return nil, fmt.Errorf("create tracing link: %w", err)
		}
		fallthrough
	case ebpf.AttachNone:
		// Attach via RawTracepointOpen
		if cookie > 0 {
			return nil, fmt.Errorf("create raw tracepoint with cookie: %w", ErrNotSupported)
		}

		fd, err = sys.RawTracepointOpen(&sys.RawTracepointOpenAttr{
			ProgFd: uint32(program.FD()),
		})
		if errors.Is(err, sys.ENOTSUPP) {
			// This may be returned by bpf_tracing_prog_attach via bpf_arch_text_poke.
			return nil, fmt.Errorf("create raw tracepoint: %w", ErrNotSupported)
		}
		if err != nil {
			return nil, fmt.Errorf("create raw tracepoint: %w", err)
		}
	default:
		return nil, fmt.Errorf("invalid attach type: %s", at.String())
	}

	raw := RawLink{fd: fd}
	info, err := raw.Info()
	if err != nil {
		raw.Close()
		return nil, err
	}

	if info.Type == RawTracepointType {
		// Sadness upon sadness: a Tracing program with AttachRawTp returns
		// a raw_tracepoint link. Other types return a tracing link.
		return &rawTracepoint{raw}, nil
	}
	return &tracing{raw}, nil
}

// AttachTracing links a tracing (fentry/fexit/fmod_ret) BPF program or
// a BTF-powered raw tracepoint (tp_btf) BPF Program to a BPF hook defined
// in kernel modules.
func AttachTracing(opts TracingOptions) (Link, error) {
	if t := opts.Program.Type(); t != ebpf.Tracing {
		return nil, fmt.Errorf("invalid program type %s, expected Tracing", t)
	}

	switch opts.AttachType {
	case ebpf.AttachTraceFEntry, ebpf.AttachTraceFExit, ebpf.AttachModifyReturn,
		ebpf.AttachTraceRawTp, ebpf.AttachNone:
	default:
		return nil, fmt.Errorf("invalid attach type: %s", opts.AttachType.String())
	}

	return attachBTFID(opts.Program, opts.AttachType, opts.Cookie)
}

// AttachLSM links a Linux security module (LSM) BPF Program to a BPF
// hook defined in kernel modules.
func AttachLSM(opts LSMOptions) (Link, error) {
	if t := opts.Program.Type(); t != ebpf.LSM {
		return nil, fmt.Errorf("invalid program type %s, expected LSM", t)
	}

	return attachBTFID(opts.Program, ebpf.AttachLSMMac, opts.Cookie)
}
