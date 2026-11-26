package known

import (
	"path/filepath"
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
}

// RuntimeLabel returns a human-readable description if path's basename matches
// a known benign game/language runtime DLL, or "" otherwise.
func RuntimeLabel(path string) string {
	base := strings.ToLower(filepath.Base(path))
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
