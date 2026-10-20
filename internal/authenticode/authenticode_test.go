package authenticode

import (
	"testing"
)

// buildPE assembles a minimal PE with a certificate table so the image hash
// rules can be tested. The layout matters: the Authenticode hash skips the
// checksum field, the certificate table directory entry and the certificate
// table itself, so a change in those bytes must NOT move the hash.
func buildPE(certTable []byte) []byte {
	const (
		peOff    = 0x40
		optOff   = peOff + 24
		sizeOpt  = 0xE0
		secOff   = optOff + sizeOpt
		sumOff   = optOff + 64
		ddOff    = optOff + 96
		certDir  = ddOff + 4*8
		rawStart = secOff + 40
	)
	total := rawStart + 512
	if certTable != nil {
		total = rawStart + 512 + len(certTable)
	}
	b := make([]byte, total)

	copy(b[0:], []byte{'M', 'Z'})
	b[0x3c] = byte(peOff)
	copy(b[peOff:], []byte{'P', 'E', 0, 0})
	b[peOff+4] = 0x4c // machine i386
	b[peOff+6] = 1    // one section
	b[peOff+20] = byte(sizeOpt)
	b[optOff] = 0x0b    // magic PE32, low byte
	b[optOff+1] = 0x01  // magic PE32, high byte
	b[optOff+2] = 0x00  // major linker version
	b[optOff+16] = 0x00 // section alignment (byte 0)
	b[optOff+17] = 0x10
	b[optOff+28] = 0x00 // image base
	b[optOff+29] = 0x00
	b[optOff+30] = 0x00
	b[optOff+31] = 0x01
	b[optOff+32] = 0x00 // section alignment
	b[optOff+33] = 0x10
	b[optOff+36] = 0x00 // file alignment
	b[optOff+37] = 0x02
	b[optOff+92] = 16 // number of data directories
	b[sumOff] = 0xde  // checksum
	// section table
	copy(b[secOff:], []byte(".text\x00\x00\x00"))
	put32(b, secOff+8, 0x200)     // virtual size
	put32(b, secOff+12, 0x1000)   // virtual address
	put32(b, secOff+16, 0x200)    // raw size
	put32(b, secOff+20, rawStart) // raw offset
	// code
	for i := 0; i < 0x200; i++ {
		b[rawStart+i] = byte(i)
	}
	if certTable != nil {
		off := uint32(rawStart + 0x200)
		b[certDir] = byte(off)
		b[certDir+1] = byte(off >> 8)
		b[certDir+2] = byte(off >> 16)
		b[certDir+3] = byte(off >> 24)
		size := uint32(len(certTable))
		b[certDir+4] = byte(size)
		b[certDir+5] = byte(size >> 8)
		b[certDir+6] = byte(size >> 16)
		b[certDir+7] = byte(size >> 24)
		copy(b[rawStart+0x200:], certTable)
	}
	return b
}

func put32(b []byte, off int, v uint32) {
	b[off] = byte(v)
	b[off+1] = byte(v >> 8)
	b[off+2] = byte(v >> 16)
	b[off+3] = byte(v >> 24)
}

func TestVerifyNoSignature(t *testing.T) {
	pe := buildPE(nil)
	res, err := verifyBytes(pe)
	if err != nil {
		t.Fatal(err)
	}
	if res.Status != StatusNone {
		t.Errorf("status = %v, want StatusNone", res.Status)
	}
	if res.Signed() {
		t.Error("a file without a certificate table must not count as signed")
	}
}

func TestVerifyNotAPe(t *testing.T) {
	res, err := verifyBytes([]byte("not a pe file at all"))
	if err != nil {
		t.Fatal(err)
	}
	if res.Status != StatusNone {
		t.Errorf("status = %v, want StatusNone", res.Status)
	}
}

// TestImageHashSkipsTheExcludedRegions pins the Authenticode hash rules: the
// checksum field, the certificate table directory entry and the certificate
// table are all excluded, so changing them must not move the hash, while
// changing a byte of code must.
func TestImageHashSkipsTheExcludedRegions(t *testing.T) {
	cert := make([]byte, 64)
	for i := range cert {
		cert[i] = byte(i * 7)
	}
	base := buildPE(cert)

	baseHash, err := HashSHA1(base)
	if err != nil {
		t.Fatal(err)
	}

	// The checksum field is excluded.
	mod := append([]byte(nil), base...)
	mod[0x40+24+64] ^= 0xFF
	h, _ := HashSHA1(mod)
	if string(h) != string(baseHash) {
		t.Error("changing the checksum field changed the image hash; it must be excluded")
	}

	// The content of the certificate table is excluded: two files with the
	// same code and a different certificate table of the same length hash
	// identically.
	other := buildPE(make([]byte, 64))
	otherHash, err := HashSHA1(other)
	if err != nil {
		t.Fatal(err)
	}
	if string(otherHash) != string(baseHash) {
		t.Error("the certificate table content changed the image hash; it must be excluded")
	}

	// A byte of code is NOT excluded.
	mod = append([]byte(nil), base...)
	mod[0x40+24+0xE0+40+0x100] ^= 0xFF
	h, _ = HashSHA1(mod)
	if string(h) == string(baseHash) {
		t.Error("changing a byte of code did not change the image hash")
	}
}

// TestVerifyDetectsModifiedContent is the behaviour that matters for a
// crack scanner: a file that carries a signature whose digest is not the
// digest of the file was modified after signing.
func TestVerifyDetectsModifiedContent(t *testing.T) {
	// Build a certificate table that contains the digest of the original
	// file, then change a byte of code. The digest no longer appears in
	// the table, so the content does not match the signature.
	pe := buildPE([]byte("placeholder certificate table"))
	sum, err := HashSHA1(pe)
	if err != nil {
		t.Fatal(err)
	}
	cert := append([]byte("table-with-digest"), sum...)
	pe = buildPE(cert)

	res, err := verifyBytes(pe)
	if err != nil {
		t.Fatal(err)
	}
	if res.Status != StatusIntact {
		t.Errorf("status = %v, want StatusIntact", res.Status)
	}
	if !res.Trusted() {
		t.Error("an intact signature must be trusted")
	}

	// Change one byte of code: the digest in the table no longer matches.
	pe[len(pe)-1] ^= 0xFF
	res, err = verifyBytes(pe)
	if err != nil {
		t.Fatal(err)
	}
	if res.Status != StatusMismatch {
		t.Errorf("status = %v, want StatusMismatch", res.Status)
	}
	if res.Trusted() {
		t.Error("a mismatched signature must not be trusted")
	}
}
