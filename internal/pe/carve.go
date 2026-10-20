package pe

// PE carving: finding executables hidden inside a data file.
//
// WHY THIS EXISTS
//
// In a repack, the game data is one huge blob - 3.8 GB for The Liar Princess
// and the Blind Prince, which is 99% of the bytes in the folder. The scanner
// skips a file that is too large, which means the largest and least
// examined file in the folder is the one most likely to hide something.
//
// A trojanized repack can append or embed a payload in that blob, where no
// import table, no string and no certificate reaches it. The only way to
// see it is to look for an executable header inside the data.
//
// The scan is a byte search for "MZ" with a PE header check behind it, so it
// runs at memory speed. It is only applied to the files the scanner would
// otherwise skip, so it costs nothing on the normal path.

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"io"
	"os"
)

// Carved is one executable image found inside a data file.
type Carved struct {
	// Offset is where the image starts in the file.
	Offset int64
	// Size is the estimated size of the image in bytes, taken from the
	// end of its last section.
	Size int64
	// Machine is the architecture, empty when it could not be read.
	Machine string
}

// Describe renders the finding for a report.
func (c Carved) Describe() string {
	m := c.Machine
	if m == "" {
		m = "unknown"
	}
	return fmt.Sprintf("an executable is embedded at offset %d (%s, about %.1f KB)", c.Offset, m, float64(c.Size)/1024)
}

const (
	carveChunk   = 4 << 20
	carveOverlap = 4096
)

// CarvePEs scans a file for embedded PE images.
//
// The file is read in chunks with a small overlap, so a header that straddles
// a chunk boundary is still found. maxCount bounds the work: a data file can
// contain a few thousand "MZ" sequences by chance, and only the ones behind
// a real PE header are reported.
func CarvePEs(path string, maxCount int) ([]Carved, error) {
	if maxCount <= 0 {
		maxCount = 32
	}
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	var out []Carved
	offset := int64(0)
	tail := make([]byte, 0, carveChunk+carveOverlap)
	buf := make([]byte, carveChunk)

	for {
		n, err := f.Read(buf)
		if n > 0 {
			chunk := append(tail, buf[:n]...)
			base := offset - int64(len(tail))
			for i := 0; i+64 <= len(chunk); i++ {
				if chunk[i] != 'M' || chunk[i+1] != 'Z' {
					continue
				}
				abs := base + int64(i)
				if abs <= 0 {
					continue
				}
				c, ok := validatePEHeader(chunk[i:])
				if !ok {
					continue
				}
				c.Offset = abs
				// The real size of the image, from its section table.
				if s := imageSizeAt(chunk[i:], 0); s > 0 {
					c.Size = s
				}
				out = append(out, c)
				if len(out) >= maxCount {
					return out, nil
				}
			}
			// Keep the tail so a header at the boundary is not missed.
			keep := carveOverlap
			if keep > len(chunk) {
				keep = len(chunk)
			}
			tail = append(tail[:0], chunk[len(chunk)-keep:]...)
			offset += int64(n)
		}
		if err == io.EOF {
			break
		}
		if err != nil {
			return out, err
		}
	}
	return out, nil
}

// validatePEHeader checks that the bytes behind an "MZ" really are a PE
// header and reports the image size.
func validatePEHeader(b []byte) (Carved, bool) {
	var c Carved
	if len(b) < 0x40 {
		return c, false
	}
	peOff := int64(binary.LittleEndian.Uint32(b[0x3c:0x40]))
	if peOff <= 0 || peOff+24 > int64(len(b)) {
		return c, false
	}
	if !bytes.Equal(b[peOff:peOff+4], []byte{'P', 'E', 0, 0}) {
		return c, false
	}
	machine := binary.LittleEndian.Uint16(b[peOff+4 : peOff+6])
	switch machine {
	case 0x14c:
		c.Machine = "x86"
	case 0x8664:
		c.Machine = "x64"
	case 0xaa64:
		c.Machine = "arm64"
	}
	c.Size = int64(peOff) + 24
	return c, true
}

// imageSizeAt returns the size of the PE image that starts at the given
// offset, taken from the end of its last section. It is 0 when the size
// cannot be determined.
func imageSizeAt(data []byte, off int64) int64 {
	if off < 0 || off+24 > int64(len(data)) {
		return 0
	}
	peOff := int64(binary.LittleEndian.Uint32(data[off+0x3c : off+0x40]))
	if peOff <= 0 || peOff+24 > int64(len(data))-off {
		return 0
	}
	base := off + peOff
	if !bytes.Equal(data[base:base+4], []byte{'P', 'E', 0, 0}) {
		return 0
	}
	numSections := int64(binary.LittleEndian.Uint16(data[base+6 : base+8]))
	sizeOpt := int64(binary.LittleEndian.Uint16(data[base+20 : base+22]))
	secTable := base + 24 + sizeOpt
	if secTable+24 > int64(len(data)) || numSections <= 0 || numSections > 96 {
		return 0
	}
	var end int64 = peOff + 24
	for i := int64(0); i < numSections; i++ {
		s := secTable + i*40
		if s+40 > int64(len(data)) {
			break
		}
		rawSize := int64(binary.LittleEndian.Uint32(data[s+16 : s+20]))
		rawOff := int64(binary.LittleEndian.Uint32(data[s+20 : s+24]))
		if rawSize > 0 && rawOff+rawSize > end {
			end = rawOff + rawSize
		}
	}
	return end
}

// ExtractEmbedded copies the PE image at the given offset into a file, so
// it can be analysed like any other binary. A payload hidden in a data blob
// is only useful if its content is actually looked at.
//
// The extraction runs to the end of the file, not to the end of the section
// table: a PE can carry an overlay after its last section, and the overlay
// is part of the file the scanner has to look at. size is the limit; 0 means
// "up to the cap".
func ExtractEmbedded(src string, off, size int64, dest string) error {
	const cap64 = 64 << 20
	if size <= 0 || size > cap64 {
		size = cap64
	}
	f, err := os.Open(src)
	if err != nil {
		return err
	}
	defer f.Close()
	if _, err := f.Seek(off, io.SeekStart); err != nil {
		return err
	}
	out, err := os.Create(dest)
	if err != nil {
		return err
	}
	defer out.Close()
	n, err := io.Copy(out, io.LimitReader(f, size))
	if err != nil {
		return err
	}
	if n == 0 {
		return fmt.Errorf("nothing extracted at offset %d", off)
	}
	return nil
}
