package text

import (
	"bufio"
	"os"
	"unicode/utf16"
)

func ExtractASCII(path string, maxBytes int64, minLen int) []string {
	f, err := os.Open(path)
	if err != nil {
		return nil
	}
	defer f.Close()
	return scanReader(f, maxBytes, minLen)
}

func ExtractASCIIBytes(b []byte, minLen int) []string {
	return extractASCIIChunk(b, minLen)
}

func ExtractUTF16(path string, maxBytes int64, minLen int) []string {
	f, err := os.Open(path)
	if err != nil {
		return nil
	}
	defer f.Close()
	br := bufio.NewReaderSize(f, 1<<20)
	buf := make([]byte, 0, 1<<20)
	read := int64(0)
	for read < maxBytes {
		chunk := make([]byte, 1<<18)
		n, err := br.Read(chunk)
		if n > 0 {
			buf = append(buf, chunk[:n]...)
			read += int64(n)
		}
		if err != nil {
			break
		}
	}
	return decodeUTF16(buf, minLen)
}

func decodeUTF16(b []byte, minLen int) []string {
	var out []string
	if len(b) < 4 {
		return out
	}
	u16 := make([]uint16, 0, len(b)/2)
	for i := 0; i+1 < len(b); i += 2 {
		u16 = append(u16, uint16(b[i])|uint16(b[i+1])<<8)
	}
	var cur []uint16
	for _, c := range u16 {
		if c == 0 {
			if len(cur) >= minLen {
				out = append(out, string(utf16.Decode(cur)))
			}
			cur = cur[:0]
			continue
		}
		cur = append(cur, c)
	}
	if len(cur) >= minLen {
		out = append(out, string(utf16.Decode(cur)))
	}
	return out
}

func scanReader(f *os.File, maxBytes int64, minLen int) []string {
	br := bufio.NewReaderSize(f, 1<<20)
	chunk := make([]byte, 1<<18)
	read := int64(0)
	var out []string
	for read < maxBytes {
		n, err := br.Read(chunk)
		if n > 0 {
			out = append(out, extractASCIIChunk(chunk[:n], minLen)...)
			read += int64(n)
		}
		if err != nil {
			break
		}
	}
	return out
}

func extractASCIIChunk(b []byte, minLen int) []string {
	var out []string
	run := make([]byte, 0, 128)
	for _, c := range b {
		if c >= 0x20 && c < 0x7F {
			run = append(run, c)
			if len(run) > 4096 {
				run = run[:0]
			}
			continue
		}
		if len(run) >= minLen {
			out = append(out, string(run))
		}
		run = run[:0]
	}
	if len(run) >= minLen {
		out = append(out, string(run))
	}
	return out
}
