#!/bin/sh
# Behavioral detonation runner - executed inside the container.
# Mounts: /det/target.exe (read-only), /out (writable)
# Isolation: --network none, no host paths beyond the two mounts.
set -u

export WINEPREFIX=/wine
export WINEARCH=win64
export WINEDEBUG=-all
export WINEDLLOVERRIDES="mscoree=d;winemenubuilder.exe=d"
export HOME=/root

TARGET="/det/target.exe"
rm -f /out/sys.* /out/stdout.log /out/stderr.log /out/exit.log /out/files.log 2>/dev/null

if [ ! -f "$TARGET" ]; then
    echo "exit=missing-target" > /out/exit.log
    exit 0
fi

STraceOpts="-f -ff -o /out/sys -e trace=network,file,process -s 300"
if command -v strace >/dev/null 2>&1; then
    timeout -s kill 120 xvfb-run -a strace $STraceOpts wine "$TARGET" >/out/stdout.log 2>/out/stderr.log
else
    timeout -s kill 120 xvfb-run -a wine "$TARGET" >/out/stdout.log 2>/out/stderr.log
fi
rc=$?
echo "exit=$rc" > /out/exit.log

# snapshot of interesting files inside the wine prefix after the run
find /wine/drive_c/users /wine/drive_c/windows/temp -type f -mmin -10 2>/dev/null | head -200 > /out/files.log
exit 0
