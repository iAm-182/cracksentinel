package pe

import (
	"crypto/md5"
	"debug/pe"
	"encoding/binary"
	"fmt"
	"io"
	"math"
	"os"
	"strings"
)

type Info struct {
	Sections   []Section
	Imphash    string
	Imports    map[string][]string
	ImportN    int
	Packer     string
	Signed     bool
	Dotnet     bool
	Machine    string
	ParseError string
}

type Section struct {
	Name     string  `json:"name"`
	Entropy  float64 `json:"entropy"`
	Size     uint32  `json:"size"`
	Archived bool    `json:"archived"`
}

var packerNames = []string{"UPX!", "MPRESS", "ASPack", "PEC2", "pec2", "Themida", "VMProtect", ".enigma", "pepack", "PEtite", "FSG!", "nspack", "UPX0", "UPX1"}

var machineNames = map[uint16]string{
	0x14c:  "i386",
	0x8664: "amd64",
	0xaa64: "arm64",
	0x1c0:  "arm",
	0x1c4:  "armnt",
	0x200:  "ia64",
	0x166:  "mips",
}

func Analyze(path string) (*Info, error) {
	f, err := pe.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	r, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer r.Close()
	return analyze(f, r)
}

func analyze(f *pe.File, r io.ReaderAt) (*Info, error) {
	info := &Info{Imports: map[string][]string{}}
	info.Machine = machineNames[f.FileHeader.Machine]
	if info.Machine == "" {
		info.Machine = fmt.Sprintf("0x%x", f.FileHeader.Machine)
	}
	var dd [16]pe.DataDirectory
	switch oh := f.OptionalHeader.(type) {
	case *pe.OptionalHeader32:
		dd = oh.DataDirectory
	case *pe.OptionalHeader64:
		dd = oh.DataDirectory
	}
	info.Dotnet = dd[14].Size > 0
	info.Signed = dd[4].Size > 0

	for _, s := range f.Sections {
		name := strings.TrimRight(s.Name, "\x00")
		buf := make([]byte, s.Size)
		n, _ := r.ReadAt(buf, int64(s.Offset))
		ent := entropy(buf[:n])
		info.Sections = append(info.Sections, Section{Name: name, Entropy: round2(ent), Size: s.Size, Archived: ent > 7.2})
		for _, p := range packerNames {
			if strings.Contains(name, p) {
				info.Packer = p
				break
			}
		}
	}

	imps, n := parseImports(f, r)
	info.Imports = imps
	info.ImportN = n
	info.Imphash = impHash(imps)

	if info.Packer == "" {
		high := 0
		for _, s := range info.Sections {
			if s.Entropy > 7.2 {
				high++
			}
		}
		if high >= 2 && info.ImportN < 8 {
			info.Packer = "unknown(entropy)"
		}
	}
	return info, nil
}

func rvaToOffset(f *pe.File, rva uint32) uint32 {
	for _, s := range f.Sections {
		size := s.VirtualSize
		if s.Size > size {
			size = s.Size
		}
		if rva >= s.VirtualAddress && rva < s.VirtualAddress+size {
			return s.Offset + (rva - s.VirtualAddress)
		}
	}
	return rva
}

func cstringAt(r io.ReaderAt, f *pe.File, rva uint32) string {
	off := int64(rvaToOffset(f, rva))
	buf := make([]byte, 256)
	n, _ := r.ReadAt(buf, off)
	if n == 0 {
		return ""
	}
	if i := indexByte(buf[:n], 0); i >= 0 {
		return string(buf[:i])
	}
	return string(buf[:n])
}

func indexByte(b []byte, c byte) int {
	for i, x := range b {
		if x == c {
			return i
		}
	}
	return -1
}

func parseImports(f *pe.File, r io.ReaderAt) (map[string][]string, int) {
	out := map[string][]string{}
	var dd [16]pe.DataDirectory
	switch oh := f.OptionalHeader.(type) {
	case *pe.OptionalHeader32:
		dd = oh.DataDirectory
	case *pe.OptionalHeader64:
		dd = oh.DataDirectory
	}
	if dd[1].VirtualAddress == 0 {
		return out, 0
	}
	base := int64(rvaToOffset(f, dd[1].VirtualAddress))
	is64 := false
	if _, ok := f.OptionalHeader.(*pe.OptionalHeader64); ok {
		is64 = true
	}
	total := 0
	for i := 0; i < 512; i++ {
		buf := make([]byte, 20)
		if _, err := r.ReadAt(buf, base+int64(i)*20); err != nil {
			break
		}
		oft := binary.LittleEndian.Uint32(buf[0:4])
		nameRVA := binary.LittleEndian.Uint32(buf[12:16])
		ft := binary.LittleEndian.Uint32(buf[16:20])
		if nameRVA == 0 && ft == 0 {
			break
		}
		dll := strings.ToLower(cstringAt(r, f, nameRVA))
		if dll == "" {
			continue
		}
		thunk := oft
		if thunk == 0 {
			thunk = ft
		}
		var funcs []string
		for j := 0; j < 4096; j++ {
			var val uint64
			if is64 {
				tb := make([]byte, 8)
				if _, err := r.ReadAt(tb, int64(rvaToOffset(f, thunk))+int64(j)*8); err != nil {
					break
				}
				val = binary.LittleEndian.Uint64(tb)
				if val == 0 {
					break
				}
			} else {
				tb := make([]byte, 4)
				if _, err := r.ReadAt(tb, int64(rvaToOffset(f, thunk))+int64(j)*4); err != nil {
					break
				}
				val = uint64(binary.LittleEndian.Uint32(tb))
				if val == 0 {
					break
				}
			}
			if (is64 && val&0x8000000000000000 != 0) || (!is64 && val&0x80000000 != 0) {
				funcs = append(funcs, fmt.Sprintf("ord%d", val&0xFFFF))
				continue
			}
			sbuf := make([]byte, 128)
			m, _ := r.ReadAt(sbuf, int64(rvaToOffset(f, uint32(val)))+2)
			if m == 0 {
				continue
			}
			if k := indexByte(sbuf[:m], 0); k >= 0 {
				funcs = append(funcs, string(sbuf[:k]))
			} else {
				funcs = append(funcs, string(sbuf[:64]))
			}
		}
		if len(funcs) > 0 {
			out[dll] = append(out[dll], funcs...)
			total += len(funcs)
		}
	}
	return out, total
}

func impHash(imports map[string][]string) string {
	dlls := make([]string, 0, len(imports))
	for dll := range imports {
		dlls = append(dlls, dll)
	}
	sortStrings(dlls)
	var parts []string
	for _, dll := range dlls {
		d := dll
		for _, ext := range []string{".dll", ".ocx", ".sys"} {
			if strings.HasSuffix(d, ext) {
				d = strings.TrimSuffix(d, ext)
				break
			}
		}
		for _, fn := range imports[dll] {
			parts = append(parts, d+"."+strings.ToLower(fn))
		}
	}
	sum := md5.Sum([]byte(strings.Join(parts, ",")))
	return fmt.Sprintf("%x", sum)
}

func sortStrings(s []string) {
	for i := 1; i < len(s); i++ {
		for j := i; j > 0 && s[j] < s[j-1]; j-- {
			s[j], s[j-1] = s[j-1], s[j]
		}
	}
}

func entropy(b []byte) float64 {
	if len(b) == 0 {
		return 0
	}
	var freq [256]int
	for _, x := range b {
		freq[x]++
	}
	n := float64(len(b))
	var e float64
	for _, c := range freq {
		if c == 0 {
			continue
		}
		p := float64(c) / n
		e -= p * math.Log2(p)
	}
	return e
}

func round2(v float64) float64 {
	return math.Round(v*100) / 100
}
