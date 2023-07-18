package link

import (
	"debug/elf"
	"errors"
	"fmt"
	"github.com/cilium/ebpf"
	"log"
	"os"
	"os/exec"
	"regexp"
	"strings"
	"sync"

	"github.com/isu-kim/dyn-uprobe/internal"
	"github.com/isu-kim/dyn-uprobe/internal/tracefs"
)

var (
	uprobeRefCtrOffsetPMUPath = "/sys/bus/event_source/devices/uprobe/format/ref_ctr_offset"
	// elixir.bootlin.com/linux/v5.15-rc7/source/kernel/events/core.c#L9799
	uprobeRefCtrOffsetShift = 32
	haveRefCtrOffsetPMU     = internal.NewFeatureTest("RefCtrOffsetPMU", "4.20", func() error {
		_, err := os.Stat(uprobeRefCtrOffsetPMUPath)
		if errors.Is(err, os.ErrNotExist) {
			return internal.ErrNotSupported
		}
		if err != nil {
			return err
		}
		return nil
	})

	// ErrNoSymbol indicates that the given symbol was not found
	// in the ELF symbols table.
	ErrNoSymbol = errors.New("not found")
)

// Executable defines an executable program on the filesystem.
type Executable struct {
	// Path of the executable on the filesystem.
	path string
	// Parsed ELF and dynamic symbols' addresses.
	addresses map[string]uint64
	// Keep track of symbol table lazy load.
	addressesOnce sync.Once
}

// binSymbol will store a binary symbol's name and its address.
type binSymbol struct {
	symbol  string
	address uint64
}

// UprobeOptions defines additional parameters that will be used
// when loading Uprobes.
type UprobeOptions struct {
	// Symbol address. Must be provided in case of external symbols (shared libs).
	// If set, overrides the address eventually parsed from the executable.
	Address uint64
	// The offset relative to given symbol. Useful when tracing an arbitrary point
	// inside the frame of given symbol.
	//
	// Note: this field changed from being an absolute offset to being relative
	// to Address.
	Offset uint64
	// Only set the uprobe on the given process ID. Useful when tracing
	// shared library calls or programs that have many running instances.
	PID int
	// Automatically manage SDT reference counts (semaphores).
	//
	// If this field is set, the Kernel will increment/decrement the
	// semaphore located in the process memory at the provided address on
	// probe attach/detach.
	//
	// See also:
	// sourceware.org/systemtap/wiki/UserSpaceProbeImplementation (Semaphore Handling)
	// github.com/torvalds/linux/commit/1cc33161a83d
	// github.com/torvalds/linux/commit/a6ca88b241d5
	RefCtrOffset uint64
	// Arbitrary value that can be fetched from an eBPF program
	// via `bpf_get_attach_cookie()`.
	//
	// Needs kernel 5.15+.
	Cookie uint64
	// Prefix used for the event name if the uprobe must be attached using tracefs.
	// The group name will be formatted as `<prefix>_<randomstr>`.
	// The default empty string is equivalent to "ebpf" as the prefix.
	TraceFSPrefix string
}

func (uo *UprobeOptions) cookie() uint64 {
	if uo == nil {
		return 0
	}
	return uo.Cookie
}

func load(f *internal.SafeELFFile) (map[string]uint64, error) {
	ret := make(map[string]uint64)

	syms, err := f.Symbols()
	if err != nil && !errors.Is(err, elf.ErrNoSymbols) {
		return ret, err
	}

	dynsyms, err := f.DynamicSymbols()
	if err != nil && !errors.Is(err, elf.ErrNoSymbols) {
		return ret, err
	}

	syms = append(syms, dynsyms...)

	for _, s := range syms {
		if elf.ST_TYPE(s.Info) != elf.STT_FUNC {
			// Symbol not associated with a function or other executable code.
			continue
		}

		address := s.Value

		// Loop over ELF segments.
		for _, prog := range f.Progs {
			// Skip uninteresting segments.
			if prog.Type != elf.PT_LOAD || (prog.Flags&elf.PF_X) == 0 {
				continue
			}

			if prog.Vaddr <= s.Value && s.Value < (prog.Vaddr+prog.Memsz) {
				// If the symbol value is contained in the segment, calculate
				// the symbol offset.
				//
				// fn symbol offset = fn symbol VA - .text VA + .text offset
				//
				// stackoverflow.com/a/40249502
				address = s.Value - prog.Vaddr + prog.Off
				break
			}
		}
		ret[s.Name] = address
	}

	return ret, nil
}

// matchELFSymbol will find function from binary file and retrieve the address of the symbol
func matchELFSymbol(binPath string, functionName string) (binSymbol, error) {
	// OpenSafeELFFile, the function originated from eBPF's code.
	sf, err := internal.OpenSafeELFFile(binPath)
	if err != nil {
		log.Fatalf("failed to open file: %v\n", err)
		return binSymbol{}, err
	}

	// Load addresses and symbols of symbols.
	addresses, err := load(sf)
	if err != nil {
		log.Fatal("Could not load SafeELFFile: ", err)
		return binSymbol{}, err
	}

	// List all symbols found.
	symContained := make([]binSymbol, 0)

	// Look for the symbol containing or 100% matching the function Name we want.
	for sym, addr := range addresses {
		// Meh... case, we found symbols containing function's name.
		if strings.Contains(sym, functionName) {
			newEntry := binSymbol{symbol: sym, address: addr}
			symContained = append(symContained, newEntry)
		}
		// The best case, we found a 100% matching symbol.
		if sym == functionName {
			log.Printf("Found matching symbol: %s at 0x%x (%s)\n", sym, addr, binPath)
			return binSymbol{symbol: functionName, address: addr}, nil
		}
	}

	// Check for the symbols containing the function name that we are looking for.
	if len(symContained) == 0 {
		return binSymbol{}, errors.New("symbol does not exist")
	} else if len(symContained) == 1 {
		// Return the one that contains the function's name.
		return symContained[0], nil
	} else {
		// Make user choose.
		// @todo update this as auto selection by context.
		var selection int

		// Prompt user selection options.
		for i, val := range symContained {
			log.Printf("%d) %s\n", i, val.symbol)
		}

		_, err := fmt.Scanln(&selection)
		if err != nil {
			log.Fatal("Could not process input: ", err)
			return binSymbol{}, err
		}

		// Return user's selection.
		if selection >= 0 && selection < len(symContained) {
			return symContained[selection], nil
		} else {
			log.Fatal("Wrong input: ", selection)
			return binSymbol{}, err
		}
	}
}

// parseLdd returns all libraries' full paths.
func parseLdd(binaryPath string) ([]string, error) {
	// Execute the ldd command
	cmd := exec.Command("ldd", binaryPath)
	output, err := cmd.CombinedOutput()
	if err != nil {
		return nil, err
	}

	// Parse the ldd output
	libs := make([]string, 0)
	lines := strings.Split(string(output), "\n")
	regex := regexp.MustCompile(`^\s*(.*?)\s*=>\s*(.*?)\s*\(.*$`)
	for _, line := range lines {
		match := regex.FindStringSubmatch(line)
		if len(match) == 3 {
			libs = append(libs, match[2])
		}
	}

	return libs, nil
}

func checkBinarySymbol(binPath string, functionName string) (string, string, error) {
	// Match ELF symbol first to check the address of the symbol.
	sym, err := matchELFSymbol(binPath, functionName)
	if err != nil {
		log.Fatalf("could not match ELF symbol: %v\n", err)
		return "", "", err
	}

	// If symbol's address was 0, this means that this is a shared library.
	// Use ldd and find all libraries that this binary uses.
	if sym.address == 0 {
		log.Printf("%s had symbol addr 0, looking for shared libraries...\n", sym.symbol)
		libs, err := parseLdd(binPath)
		if err != nil {
			log.Fatalf("could not look for library dependencies: %v\n", err)
			return "", "", err
		}

		// For all libraries, look for the symbol that matches the required symbol.
		for _, lib := range libs {
			// The library contains binary path, no idea why :(
			if lib == binPath {
				continue
			}

			sym, err := matchELFSymbol(lib, sym.symbol)
			if err != nil {
				continue
			} else {
				// Yes we found a case.
				return lib, sym.symbol, nil
			}
		}
		// Something went on wrong.
		return "", "", errors.New("could not find symbol: " + sym.symbol)
	} else {
		// We got a perfect matching symbol.
		log.Printf("found %s from %s\n", sym.symbol, binPath)
		return binPath, sym.symbol, nil
	}
}

// To open a new Executable, use:
//
//	OpenExecutable("/bin/bash")
//
// The returned value can then be used to open Uprobe(s).
func OpenExecutable(path string) (*Executable, error) {
	if path == "" {
		return nil, fmt.Errorf("path cannot be empty")
	}

	f, err := internal.OpenSafeELFFile(path)
	if err != nil {
		return nil, fmt.Errorf("parse ELF file: %w", err)
	}
	defer f.Close()

	if f.Type != elf.ET_EXEC && f.Type != elf.ET_DYN {
		// ELF is not an executable or a shared object.
		return nil, errors.New("the given file is not an executable or a shared object")
	}

	return &Executable{
		path:      path,
		addresses: make(map[string]uint64),
	}, nil
}

func (ex *Executable) load(f *internal.SafeELFFile) error {
	syms, err := f.Symbols()
	if err != nil && !errors.Is(err, elf.ErrNoSymbols) {
		return err
	}

	dynsyms, err := f.DynamicSymbols()
	if err != nil && !errors.Is(err, elf.ErrNoSymbols) {
		return err
	}

	syms = append(syms, dynsyms...)

	for _, s := range syms {
		if elf.ST_TYPE(s.Info) != elf.STT_FUNC {
			// Symbol not associated with a function or other executable code.
			continue
		}

		address := s.Value

		// Loop over ELF segments.
		for _, prog := range f.Progs {
			// Skip uninteresting segments.
			if prog.Type != elf.PT_LOAD || (prog.Flags&elf.PF_X) == 0 {
				continue
			}

			if prog.Vaddr <= s.Value && s.Value < (prog.Vaddr+prog.Memsz) {
				// If the symbol value is contained in the segment, calculate
				// the symbol offset.
				//
				// fn symbol offset = fn symbol VA - .text VA + .text offset
				//
				// stackoverflow.com/a/40249502
				address = s.Value - prog.Vaddr + prog.Off
				break
			}
		}

		ex.addresses[s.Name] = address
	}

	return nil
}

// address calculates the address of a symbol in the executable.
//
// opts must not be nil.
func (ex *Executable) address(symbol string, opts *UprobeOptions) (uint64, error) {
	if opts.Address > 0 {
		return opts.Address + opts.Offset, nil
	}

	var err error
	ex.addressesOnce.Do(func() {
		var f *internal.SafeELFFile
		f, err = internal.OpenSafeELFFile(ex.path)
		if err != nil {
			err = fmt.Errorf("parse ELF file: %w", err)
			return
		}
		defer f.Close()

		err = ex.load(f)
	})
	if err != nil {
		return 0, fmt.Errorf("lazy load symbols: %w", err)
	}

	address, ok := ex.addresses[symbol]
	if !ok {
		return 0, fmt.Errorf("symbol %s: %w", symbol, ErrNoSymbol)
	}

	// Symbols with location 0 from section undef are shared library calls and
	// are relocated before the binary is executed. Dynamic linking is not
	// implemented by the library, so mark this as unsupported for now.
	//
	// Since only offset values are stored and not elf.Symbol, if the value is 0,
	// assume it's an external symbol.
	if address == 0 {
		return 0, fmt.Errorf("cannot resolve %s library call '%s': %w "+
			"(consider providing UprobeOptions.Address)", ex.path, symbol, ErrNotSupported)
	}

	return address + opts.Offset, nil
}

// NewUprobe is for attaching a symbol to executable file with dynamic symbols.
func (ex *Executable) NewUprobe(symbol string, prog *ebpf.Program, opts *UprobeOptions) (Link, error) {
	fmt.Println("Modified Uprobe!! Supports Dynamic Linking")

	// Check binPath file exists.
	if _, err := os.Stat(ex.path); os.IsNotExist(err) {
		log.Fatalf("file %s does not exist\n", ex.path)
	}

	// Check actual binary and actual symbol.
	actualBin, actualSym, err := checkBinarySymbol(ex.path, symbol)
	if err != nil {
		log.Fatalf("could not find actual ELF symbol: %v\n", err)
		return nil, nil
	}

	// Modify the actual binary file for the executable.
	ex.path = actualBin

	return ex.Uprobe(actualSym, prog, opts)
}

// Uprobe attaches the given eBPF program to a perf event that fires when the
// given symbol starts executing in the given Executable.
// For example, /bin/bash::main():
//
//	ex, _ = OpenExecutable("/bin/bash")
//	ex.Uprobe("main", prog, nil)
//
// When using symbols which belongs to shared libraries,
// an offset must be provided via options:
//
//	up, err := ex.Uprobe("main", prog, &UprobeOptions{Offset: 0x123})
//
// Note: Setting the Offset field in the options supersedes the symbol's offset.
//
// Losing the reference to the resulting Link (up) will close the Uprobe
// and prevent further execution of prog. The Link must be Closed during
// program shutdown to avoid leaking system resources.
//
// Functions provided by shared libraries can currently not be traced and
// will result in an ErrNotSupported.

func (ex *Executable) Uprobe(symbol string, prog *ebpf.Program, opts *UprobeOptions) (Link, error) {
	u, err := ex.uprobe(symbol, prog, opts, false)
	if err != nil {
		return nil, err
	}

	lnk, err := attachPerfEvent(u, prog, opts.cookie())
	if err != nil {
		u.Close()
		return nil, err
	}

	return lnk, nil
}

func (ex *Executable) NewUretprobe(symbol string, prog *ebpf.Program, opts *UprobeOptions) (Link, error) {
	fmt.Println("Modified NewUretprobe!! Supports Dynamic Linking")

	// Check binPath file exists.
	if _, err := os.Stat(ex.path); os.IsNotExist(err) {
		log.Fatalf("file %s does not exist\n", ex.path)
	}

	// Check actual binary and actual symbol.
	actualBin, actualSym, err := checkBinarySymbol(ex.path, symbol)
	if err != nil {
		log.Fatalf("could not find actual ELF symbol: %v\n", err)
		return nil, nil
	}

	// Modify the actual binary file for the executable.
	ex.path = actualBin

	return ex.Uretprobe(actualSym, prog, opts)
}

// Uretprobe attaches the given eBPF program to a perf event that fires right
// before the given symbol exits. For example, /bin/bash::main():
//
//	ex, _ = OpenExecutable("/bin/bash")
//	ex.Uretprobe("main", prog, nil)
//
// When using symbols which belongs to shared libraries,
// an offset must be provided via options:
//
//	up, err := ex.Uretprobe("main", prog, &UprobeOptions{Offset: 0x123})
//
// Note: Setting the Offset field in the options supersedes the symbol's offset.
//
// Losing the reference to the resulting Link (up) will close the Uprobe
// and prevent further execution of prog. The Link must be Closed during
// program shutdown to avoid leaking system resources.
//
// Functions provided by shared libraries can currently not be traced and
// will result in an ErrNotSupported.
func (ex *Executable) Uretprobe(symbol string, prog *ebpf.Program, opts *UprobeOptions) (Link, error) {
	u, err := ex.uprobe(symbol, prog, opts, true)
	if err != nil {
		return nil, err
	}

	lnk, err := attachPerfEvent(u, prog, opts.cookie())
	if err != nil {
		u.Close()
		return nil, err
	}

	return lnk, nil
}

// uprobe opens a perf event for the given binary/symbol and attaches prog to it.
// If ret is true, create a uretprobe.
func (ex *Executable) uprobe(symbol string, prog *ebpf.Program, opts *UprobeOptions, ret bool) (*perfEvent, error) {
	if prog == nil {
		return nil, fmt.Errorf("prog cannot be nil: %w", errInvalidInput)
	}
	if prog.Type() != ebpf.Kprobe {
		return nil, fmt.Errorf("eBPF program type %s is not Kprobe: %w", prog.Type(), errInvalidInput)
	}
	if opts == nil {
		opts = &UprobeOptions{}
	}

	offset, err := ex.address(symbol, opts)
	if err != nil {
		return nil, err
	}

	pid := opts.PID
	if pid == 0 {
		pid = perfAllThreads
	}

	if opts.RefCtrOffset != 0 {
		if err := haveRefCtrOffsetPMU(); err != nil {
			return nil, fmt.Errorf("uprobe ref_ctr_offset: %w", err)
		}
	}

	args := tracefs.ProbeArgs{
		Type:         tracefs.Uprobe,
		Symbol:       symbol,
		Path:         ex.path,
		Offset:       offset,
		Pid:          pid,
		RefCtrOffset: opts.RefCtrOffset,
		Ret:          ret,
		Cookie:       opts.Cookie,
		Group:        opts.TraceFSPrefix,
	}

	// Use uprobe PMU if the kernel has it available.
	tp, err := pmuProbe(args)
	if err == nil {
		return tp, nil
	}
	if err != nil && !errors.Is(err, ErrNotSupported) {
		return nil, fmt.Errorf("creating perf_uprobe PMU: %w", err)
	}

	// Use tracefs if uprobe PMU is missing.
	tp, err = tracefsProbe(args)
	if err != nil {
		return nil, fmt.Errorf("creating trace event '%s:%s' in tracefs: %w", ex.path, symbol, err)
	}

	return tp, nil
}
