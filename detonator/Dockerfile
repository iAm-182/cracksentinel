FROM ubuntu:24.04

ENV DEBIAN_FRONTEND=noninteractive
ENV WINEPREFIX=/wine
ENV WINEARCH=win64
ENV WINEDEBUG=-all
ENV WINEDLLOVERRIDES="mscoree=d;winemenubuilder.exe=d"

# 64-bit wine only: i386 pull adds ~1.5GB of identical deps for the rare
# 32-bit target. If you need 32-bit, build a second image with wine32:i386.
RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        wine wine64 \
        xvfb strace iproute2 inetutils-ping coreutils findutils \
    && rm -rf /var/lib/apt/lists/*

RUN mkdir -p /wine /det /out \
    && WINEDLLOVERRIDES="mscoree=d" wineboot --init || true \
    && wineserver -k || true

COPY run.sh /detonator/run.sh
RUN chmod +x /detonator/run.sh

ENTRYPOINT ["/detonator/run.sh"]
