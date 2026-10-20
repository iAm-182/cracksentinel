#!/usr/bin/env bash
# Package CrackSentinel into a distributable zip.
#
#   scripts/package.sh [version]
#
# Produces dist/cracksentinel-<version>-<goos>-<goarch>.zip containing the
# binary, the detonator context, the built-in YARA rules and the README.
set -euo pipefail

VERSION="${1:-$(grep -m1 'Version = ' internal/version/version.go | sed -E 's/.*"([^"]+)".*/\1/')}"
COMMIT="$(git rev-parse --short HEAD 2>/dev/null || echo unknown)"
DATE="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
GOOS="${GOOS:-$(go env GOOS)}"
GOARCH="${GOARCH:-$(go env GOARCH)}"
LDFLAGS="-X gamecrack-scanner/internal/version.Version=${VERSION} -X gamecrack-scanner/internal/version.Commit=${COMMIT} -X gamecrack-scanner/internal/version.BuildDate=${DATE}"

OUT="dist/cracksentinel-${VERSION}-${GOOS}-${GOARCH}"
BIN="scanner.exe"
[ "${GOOS}" = "windows" ] || BIN="scanner"

echo "==> building ${BIN} ${VERSION} (${GOOS}/${GOARCH}, commit ${COMMIT})"
mkdir -p "${OUT}"
# -s -w strips the symbol table and DWARF info: the binary is 30% smaller
# and carries less string surface, which matters because a malware scanner
# is exactly the kind of binary a machine learning classifier misreads.
CGO_ENABLED=0 GOOS="${GOOS}" GOARCH="${GOARCH}" \
  go build -trimpath -ldflags "${LDFLAGS} -s -w" -o "${OUT}/${BIN}" ./cmd/scanner

echo "==> staging payload"
cp README.md "${OUT}/"
# NOTE: "[ -d x ] && cmd" under `set -e` exits the whole script when the test
# is false, so every conditional here uses a proper if block.
if [ -d detonator ]; then
  cp -r detonator "${OUT}/"
fi
mkdir -p "${OUT}/yara-rules"
cp internal/yara/rules/builtin.yar "${OUT}/yara-rules/"

cat > "${OUT}/VERSION.txt" <<EOF
CrackSentinel ${VERSION}
commit: ${COMMIT}
built:  ${DATE}
go:     ${GOOS}/${GOARCH}
EOF

if command -v sha256sum >/dev/null 2>&1; then
  (cd "${OUT}" && find . -type f -exec sha256sum {} \; > SHA256SUMS.txt)
fi

echo "==> zipping"
# The zip tool differs across environments (CI has zip, git-bash on Windows
# does not), so fall back through the available options.
if command -v zip >/dev/null 2>&1; then
  (cd dist && zip -qr "$(basename "${OUT}").zip" "$(basename "${OUT}")")
elif command -v 7z >/dev/null 2>&1; then
  (cd dist && 7z a -tzip -mx=5 "$(basename "${OUT}").zip" "$(basename "${OUT}")" >/dev/null)
elif command -v python3 >/dev/null 2>&1 && python3 -c "import sys" >/dev/null 2>&1; then
  (cd dist && python3 -m zipfile -c "$(basename "${OUT}").zip" "$(basename "${OUT}")")
elif command -v python >/dev/null 2>&1 && python -c "import sys" >/dev/null 2>&1; then
  (cd dist && python -m zipfile -c "$(basename "${OUT}").zip" "$(basename "${OUT}")")
elif command -v tar >/dev/null 2>&1; then
  # bsdtar picks the format from the extension with -a.
  (cd dist && tar -a -cf "$(basename "${OUT}").zip" "$(basename "${OUT}")")
else
  echo "no zip tool found (need zip, 7z, python or tar)" >&2
  exit 1
fi
# No `cd` here: every branch above runs in a subshell, so the working
# directory never changed and a stray `cd ..` would break the paths below.

echo "==> done: dist/$(basename "${OUT}").zip"
ls -la "dist/$(basename "${OUT}").zip"
