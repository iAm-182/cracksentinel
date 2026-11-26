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

func (v *Verdict) UnmarshalJSON(b []byte) error {
	s := string(b)
	if len(s) >= 2 && s[0] == '"' && s[len(s)-1] == '"' {
		switch s[1 : len(s)-1] {
		case "MALICIOUS":
			*v = VerdictMalicious
		case "SUSPICIOUS":
			*v = VerdictSuspicious
		default:
			*v = VerdictClean
		}
		return nil
	}
	// Accept numeric enum fallback too.
	switch s {
	case "2":
		*v = VerdictMalicious
	case "1":
		*v = VerdictSuspicious
	default:
		*v = VerdictClean
	}
	return nil
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
	Go          *GoInfo         `json:"go,omitempty"`
	Dotnet      *DotnetInfo     `json:"dotnet,omitempty"`
	Errors      []string        `json:"errors,omitempty"`
	ElapsedMs   int64           `json:"elapsed_ms"`
	Available   bool            `json:"rea_available"`
}

// GoInfo is the parsed form of REA inspect_go_binary output.
type GoInfo struct {
	GoVersion  string            `json:"go_version,omitempty"`
	ModulePath string            `json:"module_path,omitempty"`
	MainPath   string            `json:"main_path,omitempty"`
	MainVer    string            `json:"main_version,omitempty"`
	Deps       []GoDep           `json:"dependencies,omitempty"`
	Settings   map[string]string `json:"settings,omitempty"`
}

type GoDep struct {
	Path string `json:"path"`
	Ver  string `json:"version,omitempty"`
}

// DotnetInfo is the parsed form of REA inspect_managed_artifact output.
// Shapes vary by detail level, so only widely-present fields are extracted
// and the rest stays in Summary for display.
type DotnetInfo struct {
	Assembly string `json:"assembly,omitempty"`
	Version  string `json:"version,omitempty"`
	Target   string `json:"target_framework,omitempty"`
	Module   string `json:"module,omitempty"`
	MVID     string `json:"mvid,omitempty"`
	Summary  string `json:"summary,omitempty"`
}

type FileResult struct {
	Path     string      `json:"path"`
	Size     int64       `json:"size"`
	SHA256   string      `json:"sha256,omitempty"`
	Type     string      `json:"type"`
	Score    int         `json:"score"`
	Verdict  Verdict     `json:"verdict"`
	Cached   bool        `json:"cached"`
	Skipped  bool        `json:"skipped,omitempty"`
	Findings []Finding   `json:"findings,omitempty"`
	Deep     *DeepReport `json:"deep,omitempty"`
	Imphash  string      `json:"imphash,omitempty"`
	Sections []string    `json:"sections,omitempty"`
	Signed   bool        `json:"signed,omitempty"`
	Packer   string      `json:"packer,omitempty"`
	// Signer is the common name of the signing certificate, empty when
	// the file is not signed.
	Signer string `json:"signer,omitempty"`
	// SignatureStatus is "intact", "mismatch", "unreadable" or "none".
	// A mismatch means the file was modified after it was signed.
	SignatureStatus string `json:"signature_status,omitempty"`
	ScanMs          int64  `json:"scan_ms"`
	// Judge is the independent semantic assessment, when the adjudication
	// layer ran. It is advisory: the deterministic Score and Verdict stay
	// authoritative unless the user opted into an override.
	Judge *JudgeResult `json:"judge,omitempty"`
	// DownloadSource records Windows Mark-of-the-Web (Zone.Identifier) origin
	// when the file was downloaded from a website.
	DownloadSource *DownloadSource `json:"download_source,omitempty"`
}

// DownloadSource records the Mark-of-the-Web metadata attached to a downloaded file.
type DownloadSource struct {
	ZoneID      int    `json:"zone_id"`
	ZoneName    string `json:"zone_name,omitempty"`
	HostURL     string `json:"host_url,omitempty"`
	ReferrerURL string `json:"referrer_url,omitempty"`
	HostDomain  string `json:"host_domain,omitempty"`
}

// JudgeResult is the outcome of the semantic adjudication layer.
type JudgeResult struct {
	Classification string             `json:"classification"`
	IsTrojanized   float64            `json:"is_trojanized"`
	IsMalicious    float64            `json:"is_malicious"`
	Calibrated     float64            `json:"calibrated,omitempty"`
	Probabilities  map[string]float64 `json:"probabilities,omitempty"`
	Confidence     float64            `json:"confidence"`
	Risk           float64            `json:"risk"`
	Action         string             `json:"action,omitempty"`
	Family         string             `json:"family,omitempty"`
	Model          string             `json:"model,omitempty"`
	InputTokens    int                `json:"input_tokens,omitempty"`
	OutputTokens   int                `json:"output_tokens,omitempty"`
	Summary        string             `json:"summary,omitempty"`
}

type Summary struct {
	FilesScanned int          `json:"files_scanned"`
	FilesSkipped int          `json:"files_skipped"`
	BytesScanned int64        `json:"bytes_scanned"`
	Clean        int          `json:"clean"`
	Suspicious   int          `json:"suspicious"`
	Malicious    int          `json:"malicious"`
	DurationMs   int64        `json:"duration_ms"`
	Results      []FileResult `json:"results"`
}
