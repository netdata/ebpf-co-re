package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
)

const (
	modeNone       = uint(0)
	modeProbe      = uint(1 << 0)
	modeTracepoint = uint(1 << 1)
	modeTrampoline = uint(1 << 2)

	pidMin  = 0
	pidMax  = 3
	pathMax = 4096
)

const (
	selectCachestat     = uint64(1 << 0)
	selectDC            = uint64(1 << 1)
	selectDisk          = uint64(1 << 2)
	selectDNS           = uint64(1 << 3)
	selectFD            = uint64(1 << 4)
	selectHardirq       = uint64(1 << 5)
	selectMdflush       = uint64(1 << 6)
	selectMount         = uint64(1 << 7)
	selectNetworkviewer = uint64(1 << 8)
	selectOOMKill       = uint64(1 << 9)
	selectProcess       = uint64(1 << 10)
	selectSHM           = uint64(1 << 11)
	selectSocket        = uint64(1 << 12)
	selectSoftirq       = uint64(1 << 13)
	selectSwap          = uint64(1 << 14)
	selectSync          = uint64(1 << 15)
	selectVFS           = uint64(1 << 16)
	selectNFS           = uint64(1 << 17)
	selectExt4          = uint64(1 << 18)
	selectBtrfs         = uint64(1 << 19)
	selectXFS           = uint64(1 << 20)
	selectZFS           = uint64(1 << 21)

	selectFilesystem       = selectNFS | selectExt4 | selectBtrfs | selectXFS
	selectAllNonFilesystem = selectCachestat | selectDC | selectDisk | selectDNS |
		selectFD | selectHardirq | selectMdflush | selectMount |
		selectNetworkviewer | selectOOMKill | selectProcess |
		selectSHM | selectSocket | selectSoftirq | selectSwap |
		selectSync | selectVFS
)

type aggregateTestCase struct {
	name              string
	binary            string
	skel              string
	extraArg          string
	unavailableReason string
	selectionBit      uint64
	modes             uint
	emitModeArg       bool
	pidSupported      bool
}

type aggregateResult struct {
	name     string
	binary   string
	mode     string
	pid      int
	status   string
	exitCode int
	command  string
	detail   string
}

type aggregateState struct {
	testsDir          string
	includesDir       string
	dnsPorts          string
	dnsIterations     string
	selectedPID       int
	selectionMask     uint64
	explicitSelection bool
}

var aggregateTests = []aggregateTestCase{
	{name: "cachestat", binary: "cachestat", skel: "cachestat.skel.h", selectionBit: selectCachestat, modes: modeProbe | modeTracepoint | modeTrampoline, emitModeArg: true, pidSupported: true},
	{name: "dc", binary: "dc", skel: "dc.skel.h", selectionBit: selectDC, modes: modeProbe | modeTracepoint | modeTrampoline, emitModeArg: true, pidSupported: true},
	{name: "disk", binary: "disk", skel: "disk.skel.h", selectionBit: selectDisk},
	{name: "dns", binary: "dns", skel: "dns.skel.h", selectionBit: selectDNS},
	{name: "fd", binary: "fd", skel: "fd.skel.h", selectionBit: selectFD, modes: modeProbe | modeTracepoint | modeTrampoline, emitModeArg: true, pidSupported: true},
	{name: "hardirq", binary: "hardirq", skel: "hardirq.skel.h", selectionBit: selectHardirq},
	{name: "mdflush", binary: "mdflush", skel: "mdflush.skel.h", selectionBit: selectMdflush, modes: modeProbe | modeTracepoint | modeTrampoline, emitModeArg: true},
	{name: "mount", binary: "mount", skel: "mount.skel.h", selectionBit: selectMount, modes: modeProbe | modeTracepoint | modeTrampoline, emitModeArg: true},
	{name: "networkviewer", binary: "networkviewer", skel: "networkviewer.skel.h", selectionBit: selectNetworkviewer, modes: modeProbe | modeTracepoint | modeTrampoline, emitModeArg: true, pidSupported: true},
	{name: "oomkill", binary: "oomkill", skel: "oomkill.skel.h", selectionBit: selectOOMKill},
	{name: "process", binary: "process", skel: "process.skel.h", selectionBit: selectProcess, modes: modeProbe | modeTracepoint | modeTrampoline, emitModeArg: true, pidSupported: true},
	{name: "shm", binary: "shm", skel: "shm.skel.h", selectionBit: selectSHM, modes: modeProbe | modeTracepoint | modeTrampoline, emitModeArg: true, pidSupported: true},
	{name: "socket", binary: "socket", skel: "socket.skel.h", selectionBit: selectSocket, modes: modeProbe | modeTracepoint | modeTrampoline, emitModeArg: true, pidSupported: true},
	{name: "softirq", binary: "softirq", skel: "softirq.skel.h", selectionBit: selectSoftirq},
	{name: "swap", binary: "swap", skel: "swap.skel.h", selectionBit: selectSwap, modes: modeProbe | modeTracepoint | modeTrampoline, emitModeArg: true, pidSupported: true},
	{name: "sync", binary: "sync", skel: "sync.skel.h", selectionBit: selectSync, modes: modeProbe | modeTracepoint | modeTrampoline, emitModeArg: true},
	{name: "vfs", binary: "vfs", skel: "vfs.skel.h", selectionBit: selectVFS, modes: modeProbe | modeTracepoint | modeTrampoline, emitModeArg: true, pidSupported: true},
	{name: "nfs", binary: "filesystem", skel: "filesystem.skel.h", extraArg: "--nfs", selectionBit: selectNFS, modes: modeProbe},
	{name: "ext4", binary: "filesystem", skel: "filesystem.skel.h", extraArg: "--ext4", selectionBit: selectExt4, modes: modeProbe},
	{name: "btrfs", binary: "filesystem", skel: "filesystem.skel.h", extraArg: "--btrfs", selectionBit: selectBtrfs, modes: modeProbe},
	{name: "xfs", binary: "filesystem", skel: "filesystem.skel.h", extraArg: "--xfs", selectionBit: selectXFS, modes: modeProbe},
	{name: "zfs", unavailableReason: "No CO-RE skeleton or tester is generated for zfs in this repository.", selectionBit: selectZFS},
}

func joinPath(left, right string) (string, error) {
	path := filepath.Join(left, right)
	if len(path) >= pathMax {
		return "", errors.New("path too long")
	}

	return path, nil
}

func realPath(path string) (string, error) {
	absPath, err := filepath.Abs(path)
	if err != nil {
		return "", err
	}

	return filepath.EvalSymlinks(absPath)
}

func resolveSelfPaths(state *aggregateState, overrideTestsDir string) error {
	if overrideTestsDir != "" {
		resolved, err := realPath(overrideTestsDir)
		if err != nil {
			return err
		}

		state.testsDir = resolved
	} else {
		selfPath, err := os.Executable()
		if err != nil {
			return err
		}

		resolvedSelf, err := filepath.EvalSymlinks(selfPath)
		if err == nil {
			selfPath = resolvedSelf
		}

		state.testsDir = filepath.Dir(selfPath)
	}

	repoRoot := filepath.Dir(filepath.Dir(state.testsDir))
	includesDir, err := joinPath(repoRoot, "includes")
	if err != nil {
		return err
	}

	state.includesDir = includesDir
	return nil
}

func modeName(mode uint) string {
	switch mode {
	case modeProbe:
		return "probe"
	case modeTracepoint:
		return "tracepoint"
	case modeTrampoline:
		return "trampoline"
	default:
		return ""
	}
}

func modeArg(mode uint) string {
	switch mode {
	case modeProbe:
		return "--probe"
	case modeTracepoint:
		return "--tracepoint"
	case modeTrampoline:
		return "--trampoline"
	default:
		return ""
	}
}

func initResult(test aggregateTestCase) aggregateResult {
	return aggregateResult{
		name:     test.name,
		binary:   test.binary,
		pid:      -1,
		exitCode: 0,
	}
}

func runChild(argv []string) int {
	cmd := exec.Command(argv[0], argv[1:]...)
	cmd.Stdout = os.Stderr
	cmd.Stderr = os.Stderr

	err := cmd.Run()
	if err == nil {
		return 0
	}

	var exitErr *exec.ExitError
	if errors.As(err, &exitErr) {
		if status, ok := exitErr.Sys().(syscall.WaitStatus); ok {
			if status.Exited() {
				return status.ExitStatus()
			}

			if status.Signaled() {
				return 128 + int(status.Signal())
			}
		}

		exitCode := exitErr.ExitCode()
		if exitCode >= 0 {
			return exitCode
		}
	}

	var errno syscall.Errno
	if errors.As(err, &errno) {
		return -int(errno)
	}

	return 1
}

func jsonWriteString(out io.Writer, text string) {
	encoded, err := json.Marshal(text)
	if err != nil {
		panic(err)
	}

	_, _ = out.Write(encoded)
}

func writeResult(out io.Writer, result aggregateResult, first *bool) {
	if !*first {
		_, _ = io.WriteString(out, ",\n")
	}

	*first = false

	_, _ = io.WriteString(out, "    {\n")
	_, _ = io.WriteString(out, "      \"name\": ")
	jsonWriteString(out, result.name)
	_, _ = io.WriteString(out, ",\n      \"binary\": ")
	jsonWriteString(out, result.binary)
	_, _ = io.WriteString(out, ",\n      \"mode\": ")
	jsonWriteString(out, result.mode)
	_, _ = fmt.Fprintf(out, ",\n      \"pid\": %d,\n", result.pid)
	_, _ = io.WriteString(out, "      \"status\": ")
	jsonWriteString(out, result.status)
	_, _ = fmt.Fprintf(out, ",\n      \"exit_code\": %d,\n", result.exitCode)
	_, _ = io.WriteString(out, "      \"command\": ")
	jsonWriteString(out, result.command)
	_, _ = io.WriteString(out, ",\n      \"detail\": ")
	jsonWriteString(out, result.detail)
	_, _ = io.WriteString(out, "\n    }")
}

func pathExists(path string) bool {
	return syscall.Access(path, 0) == nil
}

func pathExecutable(path string) bool {
	info, err := os.Stat(path)
	if err != nil {
		return false
	}

	return !info.IsDir() && info.Mode().Perm()&0111 != 0
}

func recordUnavailable(test aggregateTestCase, detail string) aggregateResult {
	result := initResult(test)
	result.status = "Unavailable"
	result.detail = detail
	result.command = ""
	return result
}

func executeTest(state aggregateState, test aggregateTestCase, mode uint, pid int) (aggregateResult, int) {
	result := initResult(test)
	if mode != modeNone {
		result.mode = modeName(mode)
	}

	if pid >= 0 {
		result.pid = pid
	}

	binaryPath, err := joinPath(state.testsDir, test.binary)
	if err != nil {
		result.status = "Fail"
		result.detail = "Binary path is too long."
		result.exitCode = 1
		return result, 1
	}

	args := []string{binaryPath}
	if test.emitModeArg && mode != modeNone {
		args = append(args, modeArg(mode))
	}

	if test.extraArg != "" {
		args = append(args, test.extraArg)
	}

	if test.name == "dns" {
		if state.dnsPorts != "" {
			args = append(args, "--dns-port", state.dnsPorts)
		}

		if state.dnsIterations != "" {
			args = append(args, "--iteration", state.dnsIterations)
		}
	}

	if pid >= 0 {
		args = append(args, "--pid", strconv.Itoa(pid))
	}

	result.command = strings.Join(args, " ")

	_, _ = fmt.Fprintf(os.Stderr, "Running %s\n", result.command)
	exitCode := runChild(args)
	result.exitCode = exitCode
	if exitCode == 0 {
		result.status = "Success"
		result.detail = "Command completed successfully."
	} else {
		result.status = "Fail"
		result.detail = fmt.Sprintf("Command exited with code %d.", exitCode)
	}

	return result, exitCode
}

func printHelp(out io.Writer, name string) {
	_, _ = fmt.Fprintf(out,
		"%s runs the CO-RE testers built in src/tests and aggregates their results.\n\n"+
			"Options:\n"+
			"  --help            Print this help.\n"+
			"  --all             Run all non-filesystem CO-RE tests. This is the default.\n"+
			"  --pid VALUE       Run PID-aware tests with a single PID level (0-3).\n"+
			"  --dns-port LIST   Forward a comma-separated DNS port list to the DNS tester.\n"+
			"  --iteration N     Forward the capture iteration count to the DNS tester.\n"+
			"  --tests-dir PATH  Override the directory that contains the compiled test binaries.\n"+
			"  --log-path FILE   Write the aggregate JSON summary to FILE instead of stdout.\n"+
			"\n"+
			"Selectors:\n"+
			"  --cachestat --dc --disk --dns --fd --hardirq --mdflush --mount\n"+
			"  --networkviewer --oomkill --process --shm --socket --softirq --swap\n"+
			"  --sync --vfs --filesystem --nfs --ext4 --btrfs --xfs --zfs\n"+
			"\n"+
			"Notes:\n"+
			"  - --all excludes filesystem coverage: nfs, ext4, btrfs, xfs, and zfs.\n"+
			"  - --filesystem expands to --nfs --ext4 --btrfs --xfs.\n"+
			"  - zfs is reported as unavailable because this repository does not generate\n"+
			"    a CO-RE zfs skeleton/tester.\n",
		name)
}

func parseLeadingInt(value string) int {
	if value == "" {
		return 0
	}

	start := 0
	sign := 1
	if value[0] == '-' {
		sign = -1
		start = 1
	} else if value[0] == '+' {
		start = 1
	}

	result := 0
	digits := 0
	for ; start < len(value); start++ {
		if value[start] < '0' || value[start] > '9' {
			break
		}

		result = result*10 + int(value[start]-'0')
		digits++
	}

	if digits == 0 {
		return 0
	}

	return sign * result
}

func nextOptionValue(args []string, index *int, inlineValue string, option string) (string, error) {
	if inlineValue != "" {
		return inlineValue, nil
	}

	*index++
	if *index >= len(args) {
		return "", fmt.Errorf("option '--%s' requires an argument", option)
	}

	return args[*index], nil
}

func parseArgs(args []string) (aggregateState, string, string, bool, error) {
	state := aggregateState{selectedPID: -1}
	testsDirOverride := ""
	logPath := ""

	for i := 0; i < len(args); i++ {
		arg := args[i]
		if arg == "--help" || arg == "-h" {
			return state, testsDirOverride, logPath, true, nil
		}

		if !strings.HasPrefix(arg, "--") {
			return state, testsDirOverride, logPath, false, fmt.Errorf("unrecognized option '%s'", arg)
		}

		option := strings.TrimPrefix(arg, "--")
		inlineValue := ""
		if equals := strings.IndexByte(option, '='); equals >= 0 {
			inlineValue = option[equals+1:]
			option = option[:equals]
		}

		switch option {
		case "pid":
			value, err := nextOptionValue(args, &i, inlineValue, option)
			if err != nil {
				return state, testsDirOverride, logPath, false, err
			}

			state.selectedPID = parseLeadingInt(value)
			if state.selectedPID < pidMin || state.selectedPID > pidMax {
				return state, testsDirOverride, logPath, false, fmt.Errorf("PID level must be between %d and %d.", pidMin, pidMax)
			}
		case "dns-port":
			value, err := nextOptionValue(args, &i, inlineValue, option)
			if err != nil {
				return state, testsDirOverride, logPath, false, err
			}

			state.dnsPorts = value
		case "iteration":
			value, err := nextOptionValue(args, &i, inlineValue, option)
			if err != nil {
				return state, testsDirOverride, logPath, false, err
			}

			state.dnsIterations = value
		case "tests-dir":
			value, err := nextOptionValue(args, &i, inlineValue, option)
			if err != nil {
				return state, testsDirOverride, logPath, false, err
			}

			testsDirOverride = value
		case "log-path":
			value, err := nextOptionValue(args, &i, inlineValue, option)
			if err != nil {
				return state, testsDirOverride, logPath, false, err
			}

			logPath = value
		case "all":
			state.selectionMask |= selectAllNonFilesystem
			state.explicitSelection = true
		case "cachestat":
			state.selectionMask |= selectCachestat
			state.explicitSelection = true
		case "dc":
			state.selectionMask |= selectDC
			state.explicitSelection = true
		case "disk":
			state.selectionMask |= selectDisk
			state.explicitSelection = true
		case "dns":
			state.selectionMask |= selectDNS
			state.explicitSelection = true
		case "fd":
			state.selectionMask |= selectFD
			state.explicitSelection = true
		case "hardirq":
			state.selectionMask |= selectHardirq
			state.explicitSelection = true
		case "mdflush":
			state.selectionMask |= selectMdflush
			state.explicitSelection = true
		case "mount":
			state.selectionMask |= selectMount
			state.explicitSelection = true
		case "networkviewer":
			state.selectionMask |= selectNetworkviewer
			state.explicitSelection = true
		case "oomkill":
			state.selectionMask |= selectOOMKill
			state.explicitSelection = true
		case "process":
			state.selectionMask |= selectProcess
			state.explicitSelection = true
		case "shm":
			state.selectionMask |= selectSHM
			state.explicitSelection = true
		case "socket":
			state.selectionMask |= selectSocket
			state.explicitSelection = true
		case "softirq":
			state.selectionMask |= selectSoftirq
			state.explicitSelection = true
		case "swap":
			state.selectionMask |= selectSwap
			state.explicitSelection = true
		case "sync":
			state.selectionMask |= selectSync
			state.explicitSelection = true
		case "vfs":
			state.selectionMask |= selectVFS
			state.explicitSelection = true
		case "filesystem":
			state.selectionMask |= selectFilesystem
			state.explicitSelection = true
		case "nfs":
			state.selectionMask |= selectNFS
			state.explicitSelection = true
		case "ext4":
			state.selectionMask |= selectExt4
			state.explicitSelection = true
		case "btrfs":
			state.selectionMask |= selectBtrfs
			state.explicitSelection = true
		case "xfs":
			state.selectionMask |= selectXFS
			state.explicitSelection = true
		case "zfs":
			state.selectionMask |= selectZFS
			state.explicitSelection = true
		default:
			return state, testsDirOverride, logPath, false, fmt.Errorf("unrecognized option '--%s'", option)
		}
	}

	if !state.explicitSelection {
		state.selectionMask = selectAllNonFilesystem
		state.explicitSelection = true
	}

	return state, testsDirOverride, logPath, false, nil
}

func main() {
	state, testsDirOverride, logPath, showHelp, err := parseArgs(os.Args[1:])
	if err != nil {
		_, _ = fmt.Fprintf(os.Stderr, "%s\n", err)
		os.Exit(1)
	}

	if showHelp {
		printHelp(os.Stdout, os.Args[0])
		return
	}

	if err := resolveSelfPaths(&state, testsDirOverride); err != nil {
		_, _ = fmt.Fprintf(os.Stderr, "Cannot resolve tester paths: %v\n", err)
		os.Exit(1)
	}

	report := io.Writer(os.Stdout)
	var reportFile *os.File
	if logPath != "" {
		reportFile, err = os.Create(logPath)
		if err != nil {
			_, _ = fmt.Fprintf(os.Stderr, "Cannot open log file: %v\n", err)
			os.Exit(1)
		}
		defer reportFile.Close()
		report = reportFile
	}

	_, _ = io.WriteString(report, "{\n  \"runs\": [\n")

	first := true
	resultCount := 0
	failures := 0
	unavailable := 0

	for _, test := range aggregateTests {
		if state.explicitSelection && (state.selectionMask&test.selectionBit) == 0 {
			continue
		}

		if test.unavailableReason != "" {
			result := recordUnavailable(test, test.unavailableReason)
			writeResult(report, result, &first)
			resultCount++
			unavailable++
			continue
		}

		skelPath, err := joinPath(state.includesDir, test.skel)
		if err != nil {
			result := recordUnavailable(test, "Skeleton path is too long.")
			writeResult(report, result, &first)
			resultCount++
			unavailable++
			continue
		}

		if !pathExists(skelPath) {
			result := recordUnavailable(test, fmt.Sprintf("Missing CO-RE artifact %s.", test.skel))
			writeResult(report, result, &first)
			resultCount++
			unavailable++
			continue
		}

		binaryPath, err := joinPath(state.testsDir, test.binary)
		if err != nil {
			result := recordUnavailable(test, "Binary path is too long.")
			writeResult(report, result, &first)
			resultCount++
			unavailable++
			continue
		}

		if !pathExecutable(binaryPath) {
			result := recordUnavailable(test, fmt.Sprintf("Missing compiled tester %s.", test.binary))
			writeResult(report, result, &first)
			resultCount++
			unavailable++
			continue
		}

		if test.modes == modeNone {
			result, exitCode := executeTest(state, test, modeNone, -1)
			if exitCode != 0 {
				failures++
			}
			writeResult(report, result, &first)
			resultCount++
			continue
		}

		orderedModes := []uint{modeProbe, modeTracepoint, modeTrampoline}
		for _, mode := range orderedModes {
			if test.modes&mode == 0 {
				continue
			}

			pidStart := -1
			pidEnd := -1
			if test.pidSupported {
				if state.selectedPID >= 0 {
					pidStart = state.selectedPID
					pidEnd = state.selectedPID
				} else {
					pidStart = pidMin
					pidEnd = pidMax
				}
			}

			if pidStart >= 0 {
				for pid := pidStart; pid <= pidEnd; pid++ {
					result, exitCode := executeTest(state, test, mode, pid)
					if exitCode != 0 {
						failures++
					}
					writeResult(report, result, &first)
					resultCount++
				}
				continue
			}

			result, exitCode := executeTest(state, test, mode, -1)
			if exitCode != 0 {
				failures++
			}
			writeResult(report, result, &first)
			resultCount++
		}
	}

	_, _ = fmt.Fprintf(report,
		"\n  ],\n"+
			"  \"summary\": {\n"+
			"    \"total\": %d,\n"+
			"    \"success\": %d,\n"+
			"    \"failed\": %d,\n"+
			"    \"unavailable\": %d\n"+
			"  }\n"+
			"}\n",
		resultCount,
		resultCount-failures-unavailable,
		failures,
		unavailable)

	if failures != 0 {
		os.Exit(1)
	}
}
