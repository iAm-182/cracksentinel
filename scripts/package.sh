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
CGO_ENABLED=0 GOOS="${GOOS}" GOARCH="${GOARCH}" \
  go build -trimpath -ldflags "${LDFLAGS}" -o "${OUT}/${BIN}" ./cmd/scanner

echo "==> staging payload"
cp README.md "${OUT}/"
[ -d detonator ] && cp -r detonator "${OUT}/"
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
cd dist && zip -qr "$(basename "${OUT}").zip" "$(basename "${OUT}")"
cd ..

echo "==> done: dist/$(basename "${OUT}").zip"
ls -la "dist/$(basename "${OUT}").zip"
