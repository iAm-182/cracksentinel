package model

type Verdict int

const (
	VerdictClean Verdict = iota
	VerdictSuspicious
	VerdictMalicious
)

func (v Verdict) String() string {
	switch v {
	case VerdictSuspicious:
		return "SUSPICIOUS"
	case VerdictMalicious:
		return "MALICIOUS"
	default:
		return "CLEAN"
	}
}

func (v Verdict) MarshalJSON() ([]byte, error) {
	return []byte(`"` + v.String() + `"`), nil
}

type Finding struct {
	Rule     string `json:"rule"`
	Category string `json:"category"`
	Severity int    `json:"severity"`
	Detail   string `json:"detail"`
}

type DeepStringHit struct {
	Pattern string `json:"pattern"`
	Output  string `json:"output"`
}

type DeepFuncHit struct {
	Name      string `json:"name"`
	Pseudcode string `json:"pseudocode,omitempty"`
}

type DeepReport struct {
	ServerTools int             `json:"server_tools"`
	Procedures  int             `json:"procedures"`
	StringHits  []DeepStringHit `json:"string_hits,omitempty"`
	FuncHits    []DeepFuncHit   `json:"func_hits,omitempty"`
	OpenOut     string          `json:"open_output,omitempty"`
	Errors      []string        `json:"errors,omitempty"`
	ElapsedMs   int64           `json:"elapsed_ms"`
	Available   bool            `json:"rea_available"`
}

type FileResult struct {
	Path     string       `json:"path"`
	Size     int64        `json:"size"`
	SHA256   string       `json:"sha256,omitempty"`
	Type     string       `json:"type"`
	Score    int          `json:"score"`
	Verdict  Verdict      `json:"verdict"`
	Cached   bool         `json:"cached"`
	Skipped  bool         `json:"skipped,omitempty"`
	Findings []Finding    `json:"findings,omitempty"`
	Deep     *DeepReport  `json:"deep,omitempty"`
	Imphash  string       `json:"imphash,omitempty"`
	Sections []string     `json:"sections,omitempty"`
	Signed   bool         `json:"signed,omitempty"`
	Packer   string       `json:"packer,omitempty"`
	ScanMs   int64        `json:"scan_ms"`
}

type Summary struct {
	FilesScanned int         `json:"files_scanned"`
	FilesSkipped int         `json:"files_skipped"`
	BytesScanned int64       `json:"bytes_scanned"`
	Clean        int         `json:"clean"`
	Suspicious   int         `json:"suspicious"`
	Malicious    int         `json:"malicious"`
	DurationMs   int64       `json:"duration_ms"`
	Results      []FileResult `json:"results"`
}
