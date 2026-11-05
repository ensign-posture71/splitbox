# Патченный sing-box: обход несовместимости REALITY с Xray-core >= v26.9.8.
#
# Сервер Xray начиная с 26.9.8 требует, чтобы в ClientHello был key share
# X25519MLKEM768, иначе молча уводит соединение в fallback (клиент видит
# `reality verification failed`). sing-box этот share вырезает в
# common/tls/reality_client.go. Апстрим не исправлен (SagerNet/sing-box#4520,
# по состоянию на 2026-11-03), поэтому собираем форк.
#
# Сборка (на коробке или где есть docker):
#   docker build -t splitbox-singbox:patched -f docker/singbox/Dockerfile .
# Дальше образы собираются с подстановкой:
#   SINGBOX_IMAGE=splitbox-singbox:patched docker compose -f compose.yaml -f compose.lan.yaml build
#
# Вернуться на официальный бинарь — просто не задавать SINGBOX_IMAGE
# (по умолчанию в compose стоит ghcr.io/sagernet/sing-box:v1.12.14).
FROM golang:1.25-bookworm AS build
ARG SINGBOX_REF=dfd19d104fd1dbed9428694e166bf79283c73686
# Метка версии, которую печатает `sing-box version`: видно, что бинарь не
# официальный, и по какому коммиту собран.
ARG SINGBOX_LABEL=1.12.14-mlkem+dfd19d1
# Коммит «Fix reality client stripping X25519MLKEM768 key share» из
# https://github.com/iskhakovt/sing-box — оставляет ML-KEM только когда
# фингерпринт шлёт и группу, и share (иначе регресс у `randomized`).
RUN mkdir -p /src \
    && curl -sL "https://codeload.github.com/iskhakovt/sing-box/tar.gz/${SINGBOX_REF}" \
       | tar xz --strip-components=1 -C /src
WORKDIR /src
# Набор тегов повторяет официальный образ: tproxy, reality, wireguard,
# clash_api и quic нужны рабочему конфигу коробки.
# CGO_ENABLED=0 обязателен: базовый образ Alpine (musl), а сборка с cgo
# линкуется с glibc и падает на старте с «no such file or directory».
RUN CGO_ENABLED=0 go build -trimpath \
      -ldflags "-X github.com/sagernet/sing-box/constant.Version=${SINGBOX_LABEL}" \
      -tags with_gvisor,with_quic,with_dhcp,with_wireguard,with_utls,with_acme,with_clash_api,with_tailscale \
      -o /out/sing-box ./cmd/sing-box

FROM ghcr.io/sagernet/sing-box:v1.12.14
COPY --from=build /out/sing-box /usr/local/bin/sing-box
