// Package sys contains bindings for the BPF syscall.
package sys

// Regenerate types.go by invoking go generate in the current directory.

//go:generate go run github.com/isu-kim/dyn-uprobe/internal/cmd/gentypes ../../btf/testdata/vmlinux.btf.gz
