package testutils

import (
	"fmt"
	"github.com/cilium/ebpf/rlimit"
	"os"
)

func init() {
	// Increase the memlock for all tests unconditionally. It's a great source of
	// weird bugs, since different distros have different default limits.
	if err := rlimit.RemoveMemlock(); err != nil {
		fmt.Fprintln(os.Stderr, "WARNING: Failed to adjust rlimit, tests may fail")
	}
}
