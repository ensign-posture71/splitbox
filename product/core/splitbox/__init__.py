"""splitbox — ядро коробочного VPN-шлюза.

Модули:
  model    — Pydantic-модель config.yaml (источник истины)
  store    — чтение/атомарная запись config.yaml
  render   — сборка конфига sing-box из модели
  subs     — разбор VLESS-подписок и ручных ссылок
  wg       — ключи и клиентские конфиги WireGuard
  catalog  — каталоги сервисов и источников наборов
"""
__version__ = "0.1.0"
