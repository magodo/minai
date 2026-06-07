//go:build linux && amd64

package ptrace

// This file wraps the PTRACE_GET_SYSCALL_INFO request (Linux 5.3+).
//
// PTRACE_GET_SYSCALL_INFO lets us ask the kernel, at a syscall-stop, what
// kind of stop this is (entry vs exit vs seccomp) and to fetch the
// syscall number, the six arguments, or the return value as appropriate.
// It supersedes the older pattern of toggling an "in syscall" bool plus
// calling PTRACE_GETREGS and decoding architecture-specific argument
// registers ourselves.
//
// Neither `syscall` nor `golang.org/x/sys/unix` wrap this request, so we
// issue it via the raw ptrace syscall.

import (
	"syscall"
	"unsafe"
)

const ptraceGetSyscallInfo = 0x420e

// Values of ptraceSyscallInfo.Op, mirroring <linux/ptrace.h>.
const (
	ptraceSysInfoNone    = 0
	ptraceSysInfoEntry   = 1
	ptraceSysInfoExit    = 2
	ptraceSysInfoSeccomp = 3
)

// ptraceSyscallInfo mirrors the kernel's `struct ptrace_syscall_info`.
//
// Layout (no padding inserted by Go on amd64):
//
//	off  0:  u8  op            (PTRACE_SYSCALL_INFO_*)
//	off  1:  u8  reserved
//	off  2:  u16 flags
//	off  4:  u32 arch
//	off  8:  u64 instruction_pointer
//	off 16:  u64 stack_pointer
//	off 24:  union of:
//	           entry   { u64 nr; u64 args[6]; }            (56 bytes)
//	           exit    { s64 rval; u8 is_error; }          ( 9 bytes)
//	           seccomp { u64 nr; u64 args[6]; u32 ret_data; u32 _; } (64 bytes)
//
// The union is the largest variant (seccomp, 64 bytes). Accessors below
// decode the relevant variant based on Op.
type ptraceSyscallInfo struct {
	Op                 uint8
	_                  uint8 // reserved
	Flags              uint16
	Arch               uint32
	InstructionPointer uint64
	StackPointer       uint64
	Union              [64]byte
}

// entryUnion overlays the "entry" / "seccomp" variant of the union.
type entryUnion struct {
	nr   uint64
	args [6]uint64
}

// exitUnion overlays the "exit" variant of the union.
type exitUnion struct {
	rval    int64
	isError uint8
}

// entry returns the syscall number and six argument values. Valid when Op
// equals ptraceSysInfoEntry (or Seccomp).
func (i *ptraceSyscallInfo) entry() (uint64, [6]uint64) {
	e := (*entryUnion)(unsafe.Pointer(&i.Union[0]))
	return e.nr, e.args
}

// exit returns the syscall return value and a flag indicating whether the
// syscall failed (rval is a negated errno when isError is true). Valid
// when Op equals ptraceSysInfoExit.
func (i *ptraceSyscallInfo) exit() (rval int64, isError bool) {
	e := (*exitUnion)(unsafe.Pointer(&i.Union[0]))
	return e.rval, e.isError != 0
}

// getSyscallInfo issues PTRACE_GET_SYSCALL_INFO on pid and fills info.
func getSyscallInfo(pid int, info *ptraceSyscallInfo) error {
	sz := unsafe.Sizeof(*info)
	_, _, errno := syscall.Syscall6(
		syscall.SYS_PTRACE,
		uintptr(ptraceGetSyscallInfo),
		uintptr(pid),
		uintptr(sz),                   // addr = capacity of buffer
		uintptr(unsafe.Pointer(info)), // data = pointer to buffer
		0, 0,
	)
	if errno != 0 {
		return errno
	}
	return nil
}
