package deobf

import (
	"bytes"
	"compress/flate"
	"compress/gzip"
	"encoding/base64"
	"io"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
)

// Result holds deobfuscated script lines and obfuscation technique flags.
// Inspired by DissectMalware/batch_deobfuscator, hiroshil/batch-deobfuscator,
// and Mandiant FLOSS static string reconstruction.
type Result struct {
	Lines       []string
	Techniques  []string // e.g. ["utf16_bom_smuggling", "batch_substr_obf", "ps_base64_layer"]
	LayersFound int
}

var (
	reBatchSet      = regexp.MustCompile(`(?i)^\s*(?:@?\s*)?set\s+(?:"([^"=]+)=([^"]*)"|([A-Za-z0-9_#@$]+)=([^\r\n&|]*))`)
	reBatchVarSlice = regexp.MustCompile(`%([A-Za-z0-9_#@$]+):~(-?\d+)(?:,(-?\d+))?%`)
	reBatchSimpleV  = regexp.MustCompile(`%([A-Za-z0-9_#@$]{1,32})%`)
	rePSCharCast    = regexp.MustCompile(`(?i)\[char\]\s*(0x[0-9a-f]+|\d+)`)
	reFromBase64    = regexp.MustCompile(`(?i)(?:frombase64string\s*\(\s*['"]([A-Za-z0-9+/=\s]{24,})['"]\s*\)|-(?:e|enc|encodedcommand)\s+['"]?([A-Za-z0-9+/=]{24,})['"]?)`)
	rePSConcat      = regexp.MustCompile(`['"]\s*\+\s*['"]`)
)

// DeobfuscateScript statically unwraps obfuscated Batch (.bat/.cmd — including
// BatCloak UTF-16 BOM smuggling, caret ^ escaping, and %var:~offset,len% slicing)
// and PowerShell/JS/VBS scripts (backtick escaping, string concatenation, [char]
// arrays, and nested Base64 / Deflate / GZip streams) without executing anything.
func DeobfuscateScript(ext string, raw []byte) Result {
	var res Result
	if len(raw) == 0 {
		return res
	}
	if len(raw) > 2<<20 {
		raw = raw[:2<<20]
	}
	ext = strings.ToLower(ext)
	techSeen := map[string]bool{}
	addTech := func(t string) {
		if !techSeen[t] {
			techSeen[t] = true
			res.Techniques = append(res.Techniques, t)
		}
	}

	text := normalizeScriptEncoding(ext, raw, addTech)
	if text == "" {
		return res
	}

	seenLines := map[string]bool{}
	pushLine := func(s string) {
		s = strings.TrimSpace(s)
		if len(s) >= 6 && len(res.Lines) < 2000 && !seenLines[s] {
			seenLines[s] = true
			res.Lines = append(res.Lines, s)
		}
	}

	if ext == ".bat" || ext == ".cmd" {
		unwrapped, usedSub := deobfuscateBatch(text)
		if usedSub {
			addTech("batch_var_obfuscation")
			res.LayersFound++
		}
		for _, ln := range strings.Split(unwrapped, "\n") {
			pushLine(ln)
		}
		text = text + "\n" + unwrapped
	}

	// PowerShell / VBS / JS normalization (up to 3 recursive Base64/Compression layers)
	cur := text
	for layer := 0; layer < 3; layer++ {
		norm, changed := deobfuscatePSLayer(cur)
		if changed {
			if layer == 0 {
				addTech("ps_syntax_obfuscation")
			}
			for _, ln := range strings.Split(norm, "\n") {
				pushLine(ln)
			}
		}
		decodedLayers := extractBase64Payloads(norm)
		if len(decodedLayers) == 0 {
			break
		}
		addTech("base64_compressed_layer")
		res.LayersFound++
		var nextBuf strings.Builder
		for _, dl := range decodedLayers {
			for _, ln := range strings.Split(dl, "\n") {
				pushLine(ln)
			}
			nextBuf.WriteString(dl)
			nextBuf.WriteByte('\n')
		}
		cur = nextBuf.String()
	}

	return res
}

func normalizeScriptEncoding(ext string, raw []byte, addTech func(string)) string {
	// BatCloak / Asian-codepage BOM smuggling trick: prepends FF FE (UTF-16LE BOM)
	// followed by ASCII batch commands (`\r\n@echo off...`). Text editors show
	// Chinese mojibake characters, while cmd.exe fails line 1 and executes line 2+ as ASCII!
	if len(raw) >= 6 && ((raw[0] == 0xFF && raw[1] == 0xFE) || (raw[0] == 0xFE && raw[1] == 0xFF)) {
		body := raw[2:]
		nullCount := 0
		sample := body
		if len(sample) > 256 {
			sample = sample[:256]
		}
		for _, b := range sample {
			if b == 0 {
				nullCount++
			}
		}
		if nullCount < len(sample)/6 {
			// Fake UTF-16 BOM over plain ASCII bytes -> BOM smuggling!
			if ext == ".bat" || ext == ".cmd" || ext == ".ps1" {
				addTech("utf16_bom_smuggling")
			}
			return string(bytes.ReplaceAll(body, []byte{0}, nil))
		}
		// Genuine UTF-16
		var sb strings.Builder
		le := raw[0] == 0xFF
		for i := 0; i+1 < len(body); i += 2 {
			var u uint16
			if le {
				u = uint16(body[i]) | uint16(body[i+1])<<8
			} else {
				u = uint16(body[i])<<8 | uint16(body[i+1])
			}
			if u != 0 {
				sb.WriteRune(rune(u))
			}
		}
		return sb.String()
	}
	return string(raw)
}

func deobfuscateBatch(src string) (string, bool) {
	// 1. Strip batch `%empty%` tricks & caret `^` inline escapes outside quotes
	caretCount := strings.Count(src, "^")
	cleaned := stripBatchCarets(src)

	env := map[string]string{
		"public":  `C:\Users\Public`,
		"appdata": `C:\Users\User\AppData\Roaming`,
		"temp":    `C:\Users\User\AppData\Local\Temp`,
		"tmp":     `C:\Users\User\AppData\Local\Temp`,
		"comspec": `C:\Windows\System32\cmd.exe`,
		"windir":  `C:\Windows`,
	}

	sliceUsed := 0
	var outLines []string
	for _, rawLine := range strings.Split(cleaned, "\n") {
		line := strings.TrimRight(rawLine, "\r")
		if strings.TrimSpace(line) == "" {
			continue
		}
		// Expand %var:~start,len% slices using known env
		expanded := reBatchVarSlice.ReplaceAllStringFunc(line, func(m string) string {
			sub := reBatchVarSlice.FindStringSubmatch(m)
			if len(sub) < 3 {
				return m
			}
			val, ok := env[strings.ToLower(sub[1])]
			if !ok {
				return ""
			}
			sliceUsed++
			off, _ := strconv.Atoi(sub[2])
			if off < 0 {
				off = len(val) + off
			}
			if off < 0 || off >= len(val) {
				return ""
			}
			if sub[3] == "" {
				return val[off:]
			}
			ln, _ := strconv.Atoi(sub[3])
			if ln < 0 {
				end := len(val) + ln
				if end <= off || end > len(val) {
					return ""
				}
				return val[off:end]
			}
			end := off + ln
			if end > len(val) {
				end = len(val)
			}
			return val[off:end]
		})

		// Expand simple %var%
		expanded = reBatchSimpleV.ReplaceAllStringFunc(expanded, func(m string) string {
			name := strings.ToLower(m[1 : len(m)-1])
			if v, ok := env[name]; ok {
				sliceUsed++
				return v
			}
			return m
		})

		// Split chained `&` / `&&` statements so inline `set a=xyz & %a:~1,1%...` works!
		for _, stmt := range splitBatchStatements(expanded) {
			if sm := reBatchSet.FindStringSubmatch(stmt); len(sm) > 0 {
				k, v := sm[1], sm[2]
				if k == "" {
					k, v = sm[3], sm[4]
				}
				k = strings.ToLower(strings.TrimSpace(k))
				if k != "" && len(env) < 512 && len(v) <= 4096 {
					env[k] = v
				}
			}
			outLines = append(outLines, stmt)
		}
	}

	// Second pass expansion over all statements once full `set` table is populated
	for i, ln := range outLines {
		ln2 := reBatchVarSlice.ReplaceAllStringFunc(ln, func(m string) string {
			sub := reBatchVarSlice.FindStringSubmatch(m)
			if len(sub) < 3 {
				return m
			}
			val, ok := env[strings.ToLower(sub[1])]
			if !ok {
				return m
			}
			sliceUsed++
			off, _ := strconv.Atoi(sub[2])
			if off < 0 {
				off = len(val) + off
			}
			if off < 0 || off >= len(val) {
				return ""
			}
			if sub[3] == "" {
				return val[off:]
			}
			lnN, _ := strconv.Atoi(sub[3])
			if lnN < 0 {
				end := len(val) + lnN
				if end <= off || end > len(val) {
					return ""
				}
				return val[off:end]
			}
			end := off + lnN
			if end > len(val) {
				end = len(val)
			}
			return val[off:end]
		})
		outLines[i] = reBatchSimpleV.ReplaceAllStringFunc(ln2, func(m string) string {
			if v, ok := env[strings.ToLower(m[1:len(m)-1])]; ok {
				return v
			}
			return m
		})
	}

	return strings.Join(outLines, "\n"), (sliceUsed >= 3 || caretCount >= 8)
}

func stripBatchCarets(s string) string {
	var b strings.Builder
	b.Grow(len(s))
	inQuotes := false
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c == '"' {
			inQuotes = !inQuotes
			b.WriteByte(c)
			continue
		}
		if c == '^' && !inQuotes && i+1 < len(s) {
			if s[i+1] == '\r' || s[i+1] == '\n' {
				i++
				if i < len(s) && s[i] == '\r' && i+1 < len(s) && s[i+1] == '\n' {
					i++
				}
				continue
			}
			i++
			b.WriteByte(s[i])
			continue
		}
		b.WriteByte(c)
	}
	return b.String()
}

func splitBatchStatements(line string) []string {
	var out []string
	inQ := false
	start := 0
	for i := 0; i < len(line); i++ {
		if line[i] == '"' {
			inQ = !inQ
		} else if !inQ && line[i] == '&' {
			seg := strings.TrimSpace(line[start:i])
			if seg != "" {
				out = append(out, seg)
			}
			if i+1 < len(line) && line[i+1] == '&' {
				i++
			}
			start = i + 1
		}
	}
	if tail := strings.TrimSpace(line[start:]); tail != "" {
		out = append(out, tail)
	}
	return out
}

func deobfuscatePSLayer(src string) (string, bool) {
	changed := false
	cur := src

	// Remove PowerShell inline backtick obfuscation (`p`o`w`e`r`s`h`e`l`l)
	if strings.Count(cur, "`") >= 4 {
		var sb strings.Builder
		sb.Grow(len(cur))
		for i := 0; i < len(cur); i++ {
			if cur[i] == '`' && i+1 < len(cur) {
				next := cur[i+1]
				// Preserve `n `r `t `0, strip obfuscation ticks before other letters
				if next != 'n' && next != 'r' && next != 't' && next != '0' && next != '`' {
					changed = true
					continue
				}
			}
			sb.WriteByte(cur[i])
		}
		cur = sb.String()
	}

	// Collapse 'a' + 'b' string concatenations
	if rePSConcat.MatchString(cur) {
		collapsed := rePSConcat.ReplaceAllString(cur, "")
		if collapsed != cur {
			cur = collapsed
			changed = true
		}
	}

	// Decode [char]72 + [char]116 ... casts
	if rePSCharCast.MatchString(cur) {
		var chars strings.Builder
		matches := rePSCharCast.FindAllStringSubmatch(cur, 512)
		if len(matches) >= 4 {
			for _, m := range matches {
				vStr := m[1]
				var code int64
				if strings.HasPrefix(strings.ToLower(vStr), "0x") {
					code, _ = strconv.ParseInt(vStr[2:], 16, 32)
				} else {
					code, _ = strconv.ParseInt(vStr, 10, 32)
				}
				if code >= 0x20 && code <= 0x7E {
					chars.WriteByte(byte(code))
				}
			}
			if chars.Len() >= 6 {
				cur = cur + "\n" + chars.String()
				changed = true
			}
		}
	}

	return cur, changed
}

func extractBase64Payloads(src string) []string {
	var out []string
	matches := reFromBase64.FindAllStringSubmatch(src, 12)
	for _, m := range matches {
		b64 := m[1]
		if b64 == "" {
			b64 = m[2]
		}
		b64 = strings.Map(func(r rune) rune {
			if r == ' ' || r == '\t' || r == '\r' || r == '\n' {
				return -1
			}
			return r
		}, b64)
		raw, err := base64.StdEncoding.DecodeString(b64)
		if err != nil || len(raw) < 8 {
			continue
		}
		// Try GZip / Deflate decompression (classic PowerShell MemoryStream + DeflateStream/GZipStream)
		if len(raw) >= 2 && raw[0] == 0x1F && raw[1] == 0x8B {
			if gr, err := gzip.NewReader(bytes.NewReader(raw)); err == nil {
				dec, _ := io.ReadAll(io.LimitReader(gr, 512<<10))
				gr.Close()
				if len(dec) > 0 {
					out = append(out, decodePayloadBytes(dec))
					continue
				}
			}
		}
		fr := flate.NewReader(bytes.NewReader(raw))
		if dec, err := io.ReadAll(io.LimitReader(fr, 512<<10)); err == nil && len(dec) >= 12 && isMostlyPrintable(dec) {
			fr.Close()
			out = append(out, decodePayloadBytes(dec))
			continue
		}
		fr.Close()

		out = append(out, decodePayloadBytes(raw))
	}
	return out
}

func decodePayloadBytes(b []byte) string {
	// Check if UTF-16LE (PowerShell -EncodedCommand standard)
	nullEven := 0
	for i := 1; i < len(b) && i < 128; i += 2 {
		if b[i] == 0 {
			nullEven++
		}
	}
	if len(b) >= 8 && nullEven >= minDeobfInt(len(b)/4, 16) {
		var sb strings.Builder
		for i := 0; i+1 < len(b); i += 2 {
			u := uint16(b[i]) | uint16(b[i+1])<<8
			if u != 0 {
				sb.WriteRune(rune(u))
			}
		}
		return sb.String()
	}
	return string(b)
}

func isMostlyPrintable(b []byte) bool {
	if len(b) == 0 {
		return false
	}
	p := 0
	n := len(b)
	if n > 256 {
		n = 256
	}
	for i := 0; i < n; i++ {
		c := b[i]
		if (c >= 0x20 && c <= 0x7E) || c == '\r' || c == '\n' || c == '\t' || c == 0 {
			p++
		}
	}
	return p*10 >= n*8
}

// ExtractStackAndXORStrings scans executable code bytes for x86/x64 stack-built
// strings (`mov byte ptr [rbp/rsp+disp], imm8`) and single-byte XOR-obfuscated
// URLs/commands (lightweight pure-Go Mandiant FLOSS equivalent).
func ExtractStackAndXORStrings(code []byte) (stackStrs []string, xorStrs []string) {
	if len(code) < 16 {
		return nil, nil
	}
	if len(code) > 2<<20 {
		code = code[:2<<20]
	}

	// 1. Stack strings: consecutive `C6 45 xx <imm>` / `C6 44 24 xx <imm>` / `C6 85 xx xx xx xx <imm>`
	var cur []byte
	flushStack := func() {
		if len(cur) >= 7 {
			stackStrs = append(stackStrs, string(cur))
		}
		cur = cur[:0]
	}
	for i := 0; i < len(code) && len(stackStrs) < 256; {
		// C6 45 <disp8> <imm8>  (mov byte ptr [rbp+disp8], imm8)
		if i+4 <= len(code) && code[i] == 0xC6 && code[i+1] == 0x45 && isPrintASCII(code[i+3]) {
			cur = append(cur, code[i+3])
			i += 4
			continue
		}
		// C6 44 24 <disp8> <imm8> (mov byte ptr [rsp+disp8], imm8)
		if i+5 <= len(code) && code[i] == 0xC6 && code[i+1] == 0x44 && code[i+2] == 0x24 && isPrintASCII(code[i+4]) {
			cur = append(cur, code[i+4])
			i += 5
			continue
		}
		// C6 85 <disp32> <imm8> (mov byte ptr [rbp+disp32], imm8)
		if i+7 <= len(code) && code[i] == 0xC6 && code[i+1] == 0x85 && isPrintASCII(code[i+6]) {
			cur = append(cur, code[i+6])
			i += 7
			continue
		}
		// Allow terminator `C6 45 xx 00` without breaking before flush
		if i+4 <= len(code) && code[i] == 0xC6 && code[i+1] == 0x45 && code[i+3] == 0x00 {
			flushStack()
			i += 4
			continue
		}
		flushStack()
		i++
	}
	flushStack()

	// 2. Fast single-byte XOR crib search for high-signal C2 prefixes (`https://discord.com/api/webhooks/`, `https://api.telegram.org/bot`, `powershell -`)
	cribs := [][]byte{
		[]byte("https://discord.com/api/webhooks/"),
		[]byte("https://discordapp.com/api/webhooks/"),
		[]byte("https://api.telegram.org/bot"),
		[]byte("app_bound_encrypted_key"),
	}
	// Using differential XOR (`b[j] ^ b[j+1] == crib[j] ^ crib[j+1]`) scans in O(N) without 255 passes!
	for _, crib := range cribs {
		cLen := len(crib)
		limit := len(code) - cLen
		for i := 0; i <= limit && len(xorStrs) < 32; i++ {
			key := code[i] ^ crib[0]
			if key == 0 {
				continue // plaintext already handled by normal string extractor
			}
			match := true
			for j := 1; j < cLen; j++ {
				if (code[i+j] ^ key) != crib[j] {
					match = false
					break
				}
			}
			if match {
				// Decode up to 160 printable chars with this XOR key!
				var dec []byte
				for k := i; k < len(code) && k-i < 160; k++ {
					ch := code[k] ^ key
					if ch >= 0x20 && ch <= 0x7E {
						dec = append(dec, ch)
					} else {
						break
					}
				}
				if len(dec) >= cLen {
					xorStrs = append(xorStrs, string(dec))
				}
				i += len(dec)
			}
		}
	}

	return stackStrs, xorStrs
}

func isPrintASCII(b byte) bool {
	return b >= 0x20 && b <= 0x7E
}

func minDeobfInt(a, b int) int {
	if a < b {
		return a
	}
	return b
}

// CanDeobfuscateExt reports whether path's extension should run through DeobfuscateScript.
func CanDeobfuscateExt(path string) bool {
	switch strings.ToLower(filepath.Ext(path)) {
	case ".bat", ".cmd", ".ps1", ".psm1", ".vbs", ".vbe", ".js", ".jse", ".wsf", ".hta":
		return true
	}
	return false
}
