# Контейнер app: веб-приложение splitbox (FastAPI).
# Бинарь sing-box здесь ТОЛЬКО ради `sing-box check` в apply-пайплайне:
# конфиг проверяется до того, как gateway попросят его перезагрузить.
ARG SINGBOX_VERSION=v1.12.14
FROM ghcr.io/sagernet/sing-box:${SINGBOX_VERSION} AS singbox

FROM python:3.13-slim
# tzdata — для подписей времени на графиках: zoneinfo без системной базы
# часовых поясов не находит даже Europe/Moscow.
RUN apt-get update && apt-get install -y --no-install-recommends \
        curl ca-certificates tzdata \
    && rm -rf /var/lib/apt/lists/*
COPY --from=singbox /usr/local/bin/sing-box /usr/local/bin/sing-box

COPY core /opt/splitbox/core
COPY catalogs /opt/splitbox/catalogs
RUN pip install --no-cache-dir /opt/splitbox/core[api]

ENV SPLITBOX_STATE=/var/lib/splitbox
# HTTPS: панель принимает пароль и показывает ключи устройств — по
# открытому HTTP это ходить не должно даже в домашней сети. Сертификат
# самоподписанный, его создаёт init-контейнер до старта панели.
CMD ["uvicorn", "splitbox.api.app:app", "--host", "0.0.0.0", "--port", "8443", \
     "--ssl-keyfile", "/var/lib/splitbox/tls/key.pem", \
     "--ssl-certfile", "/var/lib/splitbox/tls/cert.pem"]
