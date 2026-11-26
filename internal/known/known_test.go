package known

import "testing"

func TestRuntimeLabel(t *testing.T) {
	yes := []string{
		`E:\Games\Demo\lib\py3-windows-x86_64\librenpython.dll`,
		`E:\Games\Demo\libwinpthread-1.dll`,
		`C:\App\python311.dll`,
		`C:\App\Qt5Core.dll`,
		`C:\App\SDL2.dll`,
		`C:\App\d3dcompiler_47.dll`,
		`C:\App\libstdc++-6.dll`,
		`C:\App\vcruntime140_1.dll`,
		`C:\App\pthreadVC3.dll`,
	}
	for _, p := range yes {
		if !IsRuntimeDLL(p) {
			t.Errorf("expected IsRuntimeDLL(%q) = true", p)
		}
	}

	no := []string{
		`E:\Games\Demo\steam_api64.dll`,
		`E:\Games\Demo\setup.exe`,
		`E:\Games\Demo\evil_loader.dll`,
		`E:\Games\Demo\librenpython.exe`,
	}
	for _, p := range no {
		if IsRuntimeDLL(p) {
			t.Errorf("expected IsRuntimeDLL(%q) = false", p)
		}
	}
}
