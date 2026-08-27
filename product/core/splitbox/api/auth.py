"""Авторизация вебки: scrypt-пароль + подписанная cookie-сессия.

scrypt — из stdlib (hashlib), параметры умеренные: коробка может жить
на Raspberry Pi. Сессия — подписанный itsdangerous-токен, секрет хранится
в config.yaml и переживает перезапуски (иначе каждый рестарт разлогинивал
бы пользователя).
"""
from __future__ import annotations

import base64
import hashlib
import hmac
import secrets
import time

from itsdangerous import BadSignature, URLSafeTimedSerializer

SESSION_COOKIE = "splitbox_session"
SESSION_TTL = 30 * 24 * 3600          # месяц: коробка домашняя, не банк

_SCRYPT = dict(n=2**14, r=8, p=1)


def hash_password(password: str) -> str:
    salt = secrets.token_bytes(16)
    dk = hashlib.scrypt(password.encode(), salt=salt, **_SCRYPT)
    return "scrypt$" + base64.b64encode(salt).decode() + "$" + base64.b64encode(dk).decode()


def verify_password(password: str, stored: str) -> bool:
    try:
        algo, salt_b64, dk_b64 = stored.split("$")
        if algo != "scrypt":
            return False
        salt = base64.b64decode(salt_b64)
        expected = base64.b64decode(dk_b64)
    except (ValueError, TypeError):
        return False
    got = hashlib.scrypt(password.encode(), salt=salt, **_SCRYPT)
    return hmac.compare_digest(got, expected)


def make_session(secret: str) -> str:
    return URLSafeTimedSerializer(secret).dumps({"v": 1})


def check_session(secret: str, token: str) -> bool:
    try:
        URLSafeTimedSerializer(secret).loads(token, max_age=SESSION_TTL)
        return True
    except BadSignature:
        return False


class LoginLimiter:
    """Примитивный rate-limit на вход: после 5 неудач — пауза 60 с.
    Глобальный, а не по-IP: у коробки один владелец, а по-IP обходится."""

    def __init__(self, max_fails: int = 5, cooldown: int = 60):
        self.max_fails = max_fails
        self.cooldown = cooldown
        self.fails = 0
        self.blocked_until = 0.0

    def allowed(self) -> bool:
        return time.monotonic() >= self.blocked_until

    def record(self, success: bool) -> None:
        if success:
            self.fails = 0
            return
        self.fails += 1
        if self.fails >= self.max_fails:
            self.blocked_until = time.monotonic() + self.cooldown
            self.fails = 0
