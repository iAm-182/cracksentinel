package known

import (
	"strings"
)

// Known benign runtime / engine DLLs that legitimately import threading,
// input, networking, or dynamic-loading APIs and routinely trigger false
// positives (and waste minutes in Ghidra/REA deep-dive) when scanning
// legitimate or Ren'Py/Unity/Unreal game folders.
//
// IMPORTANT: Matching this list NEVER blindly whitelists a file. The scanner
// only applies a capability cap when the binary carries NO intent/payload IOCs
// (no C2, no credential target, no encoded PowerShell, no signature mismatch,
// no crypter sections). A trojanized runtime DLL still scores MALICIOUS.

var exactRuntimeDLLs = map[string]string{
	"librenpython.dll":    "Ren'Py embedded Python runtime",
	"libwinpthread-1.dll": "MinGW POSIX threads runtime",
	"libstdc++-6.dll":     "GNU C++ standard runtime",
	"libglesv2.dll":       "ANGLE OpenGL ES runtime",
	"libegl.dll":          "ANGLE EGL runtime",
	"openal32.dll":        "OpenAL audio runtime",
	"ucrtbase.dll":        "Windows Universal C Runtime",
	"unityplayer.dll":     "Unity game engine runtime",
	"mono-2.0-bdwgc.dll":  "Mono/.NET game runtime",
	"bink2w64.dll":        "RAD Bink video runtime",
	"binkw64.dll":         "RAD Bink video runtime",
	"bink2w32.dll":        "RAD Bink video runtime",
	"v8.dll":              "V8 JavaScript engine runtime",
	"ffmpeg.dll":          "FFmpeg multimedia runtime",
	"zlib1.dll":           "zlib compression runtime",
	"lz4.dll":             "LZ4 compression runtime",
	"zstd.dll":            "Zstandard compression runtime",
	"libzstd.dll":         "Zstandard compression runtime",
	"vulkan-1.dll":        "Vulkan graphics loader",
	"dxcompiler.dll":      "DirectX Shader Compiler",
	"dxil.dll":            "DirectX Intermediate Language runtime",
	"ogg.dll":             "Ogg Vorbis audio runtime",
	"opus.dll":            "Opus audio runtime",
	"steam_api.dll":       "", // handled by EMU_STEAMAPI, not runtime DLL
	"steam_api64.dll":     "",
}

type prefixEntry struct {
	prefix string
	label  string
}

var prefixRuntimeDLLs = []prefixEntry{
	{"libpython", "Python shared runtime"},
	{"python3", "Python shared runtime"},
	{"python2", "Python shared runtime"},
	{"pthreadvc", "pthreads-win32 runtime"},
	{"libgcc_s_", "GCC runtime library"},
	{"d3dcompiler_", "DirectX HLSL compiler runtime"},
	{"d3dx9_", "DirectX 9 runtime"},
	{"d3dx10_", "DirectX 10 runtime"},
	{"d3dx11_", "DirectX 11 runtime"},
	{"xinput", "DirectX XInput controller runtime"},
	{"oo2core_", "RAD Oodle game compression runtime"},
	{"amd_fidelityfx", "AMD FidelityFX graphics runtime"},
	{"qt5", "Qt5 framework runtime"},
	{"qt6", "Qt6 framework runtime"},
	{"sdl2", "SDL2 game media runtime"},
	{"sdl3", "SDL3 game media runtime"},
	{"libcurl", "libcurl HTTP client runtime"},
	{"vcruntime", "Microsoft Visual C++ runtime"},
	{"msvcp", "Microsoft Visual C++ STL runtime"},
	{"msvcr", "Microsoft Visual C runtime"},
	{"api-ms-win-", "Windows API set shim"},
	{"fmod", "FMOD game audio runtime"},
	{"wwise", "Audiokinetic Wwise audio runtime"},
	{"physx", "NVIDIA PhysX runtime"},
	{"nvngx_", "NVIDIA DLSS/NGX runtime"},
	{"amd_ags_", "AMD GPU Services runtime"},
	{"avcodec-", "FFmpeg codec runtime"},
	{"avformat-", "FFmpeg format runtime"},
	{"avutil-", "FFmpeg utility runtime"},
	{"swscale-", "FFmpeg scaler runtime"},
	{"swresample-", "FFmpeg resampler runtime"},
	{"libcrypto-", "OpenSSL crypto runtime"},
	{"libssl-", "OpenSSL TLS runtime"},
	{"vorbis", "Ogg Vorbis audio runtime"},
	{"freetype", "FreeType font runtime"},
	{"harfbuzz", "HarfBuzz text shaping runtime"},
}

// crossBase returns the lowercase filename for either Windows (\) or POSIX (/) paths.
func crossBase(path string) string {
	norm := strings.ReplaceAll(path, "\\", "/")
	if i := strings.LastIndexByte(norm, '/'); i >= 0 {
		norm = norm[i+1:]
	}
	return strings.ToLower(norm)
}

// RuntimeLabel returns a human-readable description if path's basename matches
// a known benign game/language runtime DLL, or "" otherwise.
func RuntimeLabel(path string) string {
	base := crossBase(path)
	if !strings.HasSuffix(base, ".dll") {
		return ""
	}
	if label, ok := exactRuntimeDLLs[base]; ok {
		return label
	}
	for _, pe := range prefixRuntimeDLLs {
		if strings.HasPrefix(base, pe.prefix) {
			return pe.label
		}
	}
	return ""
}

// IsRuntimeDLL reports whether path matches a known runtime DLL name.
func IsRuntimeDLL(path string) bool {
	return RuntimeLabel(path) != ""
}

// IsHijackableSystemDLL reports whether path's filename matches a classic
// Windows system DLL abused in "白加黑" (White+Black / AheadLib) DLL sideloading
// attacks when dropped next to a signed third-party executable.
// Game-modding hooks (dinput8.dll, xinput*, dxgi.dll) are intentionally excluded
// here so legitimate ReShade / mod loaders are only flagged if they carry real payloads.
var hijackableSystemDLLs = map[string]bool{
	"version.dll":   true,
	"winmm.dll":     true,
	"winhttp.dll":   true,
	"wtsapi32.dll":  true,
	"dwmapi.dll":    true,
	"uxtheme.dll":   true,
	"propsys.dll":   true,
	"ntmarta.dll":   true,
	"cryptbase.dll": true,
	"profapi.dll":   true,
	"secur32.dll":   true,
	"dbghelp.dll":   true,
	"wer.dll":       true,
	"iphlpapi.dll":  true,
	"msimg32.dll":   true,
	"hid.dll":       true,
	"oleacc.dll":    true,
	"userenv.dll":   true,
	"netapi32.dll":  true,
	"cscapi.dll":    true,
}

func IsHijackableSystemDLL(path string) bool {
	return hijackableSystemDLLs[crossBase(path)]
}

// UtilityLabel identifies structurally verified benign game-repack utilities
// (Inno Setup uninstallers, FitGirl QuickSFV checksum verifiers) by requiring
// BOTH the expected filename AND genuine internal structural strings.
// Callers MUST still veto this whenever any intent/payload IOC, signature
// mismatch, crypter layout, or online malware consensus is present.
func UtilityLabel(path string, strs []string) string {
	base := crossBase(path)
	if !strings.HasSuffix(base, ".exe") || len(strs) == 0 {
		return ""
	}
	if strings.HasPrefix(base, "unins") && len(base) == len("unins000.exe") {
		digits := base[5:8]
		if digits[0] >= '0' && digits[0] <= '9' && digits[1] >= '0' && digits[1] <= '9' && digits[2] >= '0' && digits[2] <= '9' {
			for _, s := range strs {
				l := strings.ToLower(s)
				if strings.Contains(l, "inno setup") || strings.Contains(l, "jr.inno.setup") || strings.Contains(l, "inno_setup") {
					return "Inno Setup uninstaller"
				}
			}
		}
	}
	if base == "quicksfv.exe" {
		for _, s := range strs {
			l := strings.ToLower(s)
			if strings.Contains(l, "quicksfv") || strings.Contains(l, "quick sfv") {
				return "QuickSFV checksum verifier"
			}
		}
	}
	return ""
}
