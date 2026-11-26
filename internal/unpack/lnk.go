package unpack

import (
	"encoding/binary"
	"os"
	"strings"
)

// LNKInfo holds parsed fields from a Windows Shell Link (.lnk) binary file
// following the Microsoft [MS-SHLLINK] specification (inspired by parsiya/golnk
// and Excalibra/LNK-Malware-Analyzer).
type LNKInfo struct {
	Valid             bool
	FileSize          int64
	ZeroPadded        bool // bloated >1 MB with trailing 0x00 / repeated filler (LNK size-inflation trick)
	ShowCommand       uint32
	IsMinimizedHidden bool // SW_SHOWMINNOACTIVE (7) or SW_HIDE (0)
	LocalBasePath     string
	RelativePath      string
	WorkingDir        string
	Arguments         string
	IconLocation      string
	NameDesc          string
	MachineID         string
	ExtractedStrings  []string
}

var lnkHeaderCLSID = []byte{
	0x01, 0x14, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00,
	0xC0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x46,
}

// ParseLNK parses a binary Windows .lnk file without executing or invoking COM.
func ParseLNK(path string) LNKInfo {
	var info LNKInfo
	f, err := os.Open(path)
	if err != nil {
		return info
	}
	defer f.Close()
	st, err := f.Stat()
	if err != nil || st.Size() < 76 {
		return info
	}
	info.FileSize = st.Size()

	// Read up to first 256 KB (all genuine LNK headers, LinkInfo, StringData & ExtraData sit in the first few KB).
	readLen := st.Size()
	if readLen > 256*1024 {
		readLen = 256 * 1024
	}
	buf := make([]byte, readLen)
	n, err := f.Read(buf)
	if err != nil || n < 76 {
		return info
	}
	buf = buf[:n]

	// ShellLinkHeader: HeaderSize == 0x0000004C (76) + LinkCLSID
	if binary.LittleEndian.Uint32(buf[0:4]) != 0x4C {
		return info
	}
	for i := 0; i < 16; i++ {
		if buf[4+i] != lnkHeaderCLSID[i] {
			return info
		}
	}
	info.Valid = true
	linkFlags := binary.LittleEndian.Uint32(buf[20:24])
	info.ShowCommand = binary.LittleEndian.Uint32(buf[60:64])
	// SW_SHOWMINNOACTIVE = 7, SW_SHOWMINIMIZED = 2, SW_HIDE = 0
	if info.ShowCommand == 7 || info.ShowCommand == 0 || info.ShowCommand == 2 {
		info.IsMinimizedHidden = true
	}

	// Detect LNK file-size inflation (>1 MB shortcut padded with zeros/junk to look like a real game installer!)
	if info.FileSize >= 1<<20 {
		tail := make([]byte, 4096)
		if tn, _ := f.ReadAt(tail, info.FileSize-4096); tn >= 512 {
			same := 0
			b0 := tail[0]
			for _, b := range tail[:tn] {
				if b == b0 {
					same++
				}
			}
			if same*10 >= tn*9 {
				info.ZeroPadded = true
			}
		}
	}

	pos := 76
	// 1. LinkTargetIDList (HasLinkTargetIDList = 0x01)
	if (linkFlags & 0x01) != 0 {
		if pos+2 > len(buf) {
			return info
		}
		idListSize := int(binary.LittleEndian.Uint16(buf[pos : pos+2]))
		pos += 2
		if pos+idListSize > len(buf) {
			return info
		}
		pos += idListSize
	}

	// 2. LinkInfo (HasLinkInfo = 0x02)
	if (linkFlags & 0x02) != 0 {
		if pos+4 > len(buf) {
			return info
		}
		liSize := int(binary.LittleEndian.Uint32(buf[pos : pos+4]))
		if liSize >= 28 && pos+liSize <= len(buf) {
			li := buf[pos : pos+liSize]
			liHdrSz := int(binary.LittleEndian.Uint32(li[4:8]))
			liFlags := binary.LittleEndian.Uint32(li[8:12])
			if (liFlags & 0x01) != 0 {
				// VolumeIDAndLocalBasePath
				lbOff := int(binary.LittleEndian.Uint32(li[16:20]))
				if liHdrSz >= 0x24 && pos+liSize <= len(buf) && len(li) >= 32 {
					lbUniOff := int(binary.LittleEndian.Uint32(li[28:32]))
					if lbUniOff > 0 && lbUniOff < len(li) {
						info.LocalBasePath = readUTF16Z(li[lbUniOff:])
					}
				}
				if info.LocalBasePath == "" && lbOff > 0 && lbOff < len(li) {
					info.LocalBasePath = readASCIIZ(li[lbOff:])
				}
			}
		}
		if liSize > 0 && pos+liSize <= len(buf) {
			pos += liSize
		}
	}

	// 3. StringData sections (IsUnicode = 0x80)
	isUnicode := (linkFlags & 0x80) != 0
	readStrData := func() string {
		if pos+2 > len(buf) {
			return ""
		}
		charCount := int(binary.LittleEndian.Uint16(buf[pos : pos+2]))
		pos += 2
		if charCount == 0 {
			return ""
		}
		if isUnicode {
			byteLen := charCount * 2
			if byteLen > 32768 || pos+byteLen > len(buf) {
				pos = len(buf)
				return ""
			}
			s := decodeUTF16LEString(buf[pos : pos+byteLen])
			pos += byteLen
			return s
		}
		if charCount > 32768 || pos+charCount > len(buf) {
			pos = len(buf)
			return ""
		}
		s := strings.TrimSpace(string(buf[pos : pos+charCount]))
		pos += charCount
		return s
	}

	if (linkFlags & 0x04) != 0 { // HasName
		info.NameDesc = readStrData()
	}
	if (linkFlags & 0x08) != 0 { // HasRelativePath
		info.RelativePath = readStrData()
	}
	if (linkFlags & 0x10) != 0 { // HasWorkingDir
		info.WorkingDir = readStrData()
	}
	if (linkFlags & 0x20) != 0 { // HasArguments
		info.Arguments = readStrData()
	}
	if (linkFlags & 0x40) != 0 { // HasIconLocation
		info.IconLocation = readStrData()
	}

	// 4. ExtraData blocks (TrackerDataBlock sig 0xA0000003 holds attacker's MachineID;
	// EnvironmentVariableDataBlock sig 0xA0000001 holds target path override!)
	for pos+8 <= len(buf) {
		blkSize := int(binary.LittleEndian.Uint32(buf[pos : pos+4]))
		if blkSize < 4 || pos+blkSize > len(buf) {
			break
		}
		sig := binary.LittleEndian.Uint32(buf[pos+4 : pos+8])
		blk := buf[pos : pos+blkSize]
		switch sig {
		case 0xA0000001: // EnvironmentVariableDataBlock
			if len(blk) >= 268 {
				if envTgt := readASCIIZ(blk[8:268]); envTgt != "" {
					info.ExtractedStrings = append(info.ExtractedStrings, envTgt)
				}
			}
			if len(blk) >= 788 {
				if envUni := readUTF16Z(blk[268:788]); envUni != "" {
					info.ExtractedStrings = append(info.ExtractedStrings, envUni)
				}
			}
		case 0xA0000003: // TrackerDataBlock (MachineID at offset 16, 16 bytes)
			if len(blk) >= 32 {
				info.MachineID = readASCIIZ(blk[16:32])
			}
		}
		pos += blkSize
	}

	for _, s := range []string{info.LocalBasePath, info.RelativePath, info.WorkingDir, info.Arguments, info.IconLocation, info.NameDesc} {
		if strings.TrimSpace(s) != "" {
			info.ExtractedStrings = append(info.ExtractedStrings, s)
		}
	}
	if info.LocalBasePath != "" && info.Arguments != "" {
		info.ExtractedStrings = append(info.ExtractedStrings, info.LocalBasePath+" "+info.Arguments)
	}
	return info
}

func readASCIIZ(b []byte) string {
	for i, c := range b {
		if c == 0 {
			return strings.TrimSpace(string(b[:i]))
		}
	}
	return strings.TrimSpace(string(b))
}

func readUTF16Z(b []byte) string {
	var sb strings.Builder
	for i := 0; i+1 < len(b); i += 2 {
		u := uint16(b[i]) | uint16(b[i+1])<<8
		if u == 0 {
			break
		}
		sb.WriteRune(rune(u))
	}
	return strings.TrimSpace(sb.String())
}
