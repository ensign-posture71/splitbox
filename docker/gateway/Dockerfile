# Контейнер gateway: sing-box + сетевая обвязка + супервизор.
# Бинарь sing-box берётся из официального образа SagerNet — он multi-arch
# (amd64/arm64), и его версия зафиксирована одним ARG.
ARG SINGBOX_VERSION=v1.12.14
FROM ghcr.io/sagernet/sing-box:${SINGBOX_VERSION} AS singbox

FROM debian:bookworm-slim
RUN apt-get update && apt-get install -y --no-install-recommends \
        python3 nftables iproute2 curl ca-certificates \
    && rm -rf /var/lib/apt/lists/*
COPY --from=singbox /usr/local/bin/sing-box /usr/local/bin/sing-box
COPY docker/gateway/gateway.py /opt/splitbox/gateway.py

# Кэш rule-set'ов sing-box — том: перезапуск без сети должен подниматься
# на последних известных наборах (донорское решение cache_file).
VOLUME /var/lib/sing-box

ENV SPLITBOX_STATE=/var/lib/splitbox
ENTRYPOINT ["python3", "/opt/splitbox/gateway.py"]
