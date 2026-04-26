package main

/*
#include <stdlib.h>
#include "netdata_core_loader.h"
*/
import "C"

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"strconv"
	"strings"
	"unsafe"
)

const (
	modeNone       = uint(0)
	modeProbe      = uint(1 << 0)
	modeTracepoint = uint(1 << 1)
	modeTrampoline = uint(1 << 2)

	pidMin = 0
	pidMax = 3
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
	dnsPorts          string
	dnsIterations     string
	selectedPID       int
	selectionMask     uint64
	explicitSelection bool
}

var aggregateTests = []aggregateTestCase{
	{name: "cachestat", binary: "cachestat", selectionBit: selectCachestat, modes: modeProbe | modeTracepoint | modeTrampoline, emitModeArg: true, pidSupported: true},
	{name: "dc", binary: "dc", selectionBit: selectDC, modes: modeProbe | modeTracepoint | modeTrampoline, emitModeArg: true, pidSupported: true},
	{name: "disk", binary: "disk", selectionBit: selectDisk},
	{name: "dns", binary: "dns", selectionBit: selectDNS},
	{name: "fd", binary: "fd", selectionBit: selectFD, modes: modeProbe | modeTracepoint | modeTrampoline, emitModeArg: true, pidSupported: true},
	{name: "hardirq", binary: "hardirq", selectionBit: selectHardirq},
	{name: "mdflush", binary: "mdflush", selectionBit: selectMdflush, modes: modeProbe | modeTracepoint | modeTrampoline, emitModeArg: true},
	{name: "mount", binary: "mount", selectionBit: selectMount, modes: modeProbe | modeTracepoint | modeTrampoline, emitModeArg: true},
	{name: "networkviewer", binary: "networkviewer", selectionBit: selectNetworkviewer, modes: modeProbe | modeTracepoint | modeTrampoline, emitModeArg: true, pidSupported: true},
	{name: "oomkill", binary: "oomkill", selectionBit: selectOOMKill},
	{name: "process", binary: "process", selectionBit: selectProcess, modes: modeProbe | modeTracepoint | modeTrampoline, emitModeArg: true, pidSupported: true},
	{name: "shm", binary: "shm", selectionBit: selectSHM, modes: modeProbe | modeTracepoint | modeTrampoline, emitModeArg: true, pidSupported: true},
	{name: "socket", binary: "socket", selectionBit: selectSocket, modes: modeProbe | modeTracepoint | modeTrampoline, emitModeArg: true, pidSupported: true},
	{name: "softirq", binary: "softirq", selectionBit: selectSoftirq},
	{name: "swap", binary: "swap", selectionBit: selectSwap, modes: modeProbe | modeTracepoint | modeTrampoline, emitModeArg: true, pidSupported: true},
	{name: "sync", binary: "sync", selectionBit: selectSync, modes: modeProbe | modeTracepoint | modeTrampoline, emitModeArg: true},
	{name: "vfs", binary: "vfs", selectionBit: selectVFS, modes: modeProbe | modeTracepoint | modeTrampoline, emitModeArg: true, pidSupported: true},
	{name: "nfs", binary: "filesystem", extraArg: "--nfs", selectionBit: selectNFS, modes: modeProbe},
	{name: "ext4", binary: "filesystem", extraArg: "--ext4", selectionBit: selectExt4, modes: modeProbe},
	{name: "btrfs", binary: "filesystem", extraArg: "--btrfs", selectionBit: selectBtrfs, modes: modeProbe},
	{name: "xfs", binary: "filesystem", extraArg: "--xfs", selectionBit: selectXFS, modes: modeProbe},
	{name: "zfs", unavailableReason: "No CO-RE skeleton or tester is generated for zfs in this repository.", selectionBit: selectZFS},
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

	args := []string{test.binary}
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

	cName := C.CString(test.binary)
	defer C.free(unsafe.Pointer(cName))

	cArgs := make([]*C.char, len(args))
	for i, a := range args {
		cs := C.CString(a)
		defer C.free(unsafe.Pointer(cs))
		cArgs[i] = cs
	}

	exitCode := int(C.netdata_run_entry(cName, C.int(len(cArgs)), &cArgs[0]))
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
		"%s runs the CO-RE tests in-process and aggregates their results.\n\n"+
			"Options:\n"+
			"  --help            Print this help.\n"+
			"  --all             Run all non-filesystem CO-RE tests. This is the default.\n"+
			"  --pid VALUE       Run PID-aware tests with a single PID level (0-3).\n"+
			"  --dns-port LIST   Forward a comma-separated DNS port list to the DNS tester.\n"+
			"  --iteration N     Forward the capture iteration count to the DNS tester.\n"+
			"  --tests-dir PATH  Accepted for compatibility and ignored in in-process mode.\n"+
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

func parseArgs(args []string) (aggregateState, string, bool, error) {
	state := aggregateState{selectedPID: -1}
	logPath := ""

	for i := 0; i < len(args); i++ {
		arg := args[i]
		if arg == "--help" || arg == "-h" {
			return state, logPath, true, nil
		}

		if !strings.HasPrefix(arg, "--") {
			return state, logPath, false, fmt.Errorf("unrecognized option '%s'", arg)
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
				return state, logPath, false, err
			}

			state.selectedPID = parseLeadingInt(value)
			if state.selectedPID < pidMin || state.selectedPID > pidMax {
				return state, logPath, false, fmt.Errorf("PID level must be between %d and %d.", pidMin, pidMax)
			}
		case "dns-port":
			value, err := nextOptionValue(args, &i, inlineValue, option)
			if err != nil {
				return state, logPath, false, err
			}

			state.dnsPorts = value
		case "iteration":
			value, err := nextOptionValue(args, &i, inlineValue, option)
			if err != nil {
				return state, logPath, false, err
			}

			state.dnsIterations = value
		case "tests-dir":
			// accepted for backward compatibility; no-op in in-process mode
			_, err := nextOptionValue(args, &i, inlineValue, option)
			if err != nil {
				return state, logPath, false, err
			}
		case "log-path":
			value, err := nextOptionValue(args, &i, inlineValue, option)
			if err != nil {
				return state, logPath, false, err
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
			return state, logPath, false, fmt.Errorf("unrecognized option '--%s'", option)
		}
	}

	if !state.explicitSelection {
		state.selectionMask = selectAllNonFilesystem
		state.explicitSelection = true
	}

	return state, logPath, false, nil
}

func main() {
	state, logPath, showHelp, err := parseArgs(os.Args[1:])
	if err != nil {
		_, _ = fmt.Fprintf(os.Stderr, "%s\n", err)
		os.Exit(1)
	}

	if showHelp {
		printHelp(os.Stdout, os.Args[0])
		return
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
