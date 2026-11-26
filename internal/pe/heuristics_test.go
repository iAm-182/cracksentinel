package pe

import "testing"

func TestDirectSyscallAndPEBWalkDetection(t *testing.T) {
	// Two SysWhispers2/Hell's Gate stubs: mov r10, rcx; mov eax, SSN; syscall; ret
	stub := []byte{
		0x4C, 0x8B, 0xD1, 0xB8, 0x18, 0x00, 0x00, 0x00, 0x0F, 0x05, 0xC3,
		0x90, 0x90,
		0x4C, 0x8B, 0xD1, 0xB8, 0x3A, 0x00, 0x00, 0x00, 0x49, 0x89, 0xCA, 0x0F, 0x05, 0xC3,
	}
	if n := countSyscallStubs64(stub); n != 2 {
		t.Fatalf("countSyscallStubs64 = %d, want 2", n)
	}

	// x64 PEB -> Ldr -> InMemoryOrderModuleList walk:
	// 65 48 8B 04 25 60 00 00 00   mov rax, gs:[0x60]
	// 48 8B 40 18                  mov rax, [rax+0x18]
	// 48 8B 70 20                  mov rsi, [rax+0x20]
	peb64 := make([]byte, 48)
	copy(peb64, []byte{
		0x65, 0x48, 0x8B, 0x04, 0x25, 0x60, 0x00, 0x00, 0x00,
		0x48, 0x8B, 0x40, 0x18,
		0x48, 0x8B, 0x70, 0x20,
	})
	if !hasPEBLDRWalk64(peb64) {
		t.Fatalf("expected hasPEBLDRWalk64 = true")
	}

	// Ordinary gs:[0x30] TEB access without Ldr chain must NOT false-positive.
	tebOnly := make([]byte, 48)
	copy(tebOnly, []byte{0x65, 0x48, 0x8B, 0x04, 0x25, 0x30, 0x00, 0x00, 0x00, 0xC3})
	if hasPEBLDRWalk64(tebOnly) {
		t.Fatalf("TEB gs:[0x30] must not trigger hasPEBLDRWalk64")
	}
}
