"""Самоподписанный сертификат для веб-панели.

Панель принимает пароль и показывает ключи устройств — по открытому HTTP
это ходить не должно, даже внутри домашней сети. Настоящий сертификат
получить неоткуда: у коробки нет публичного имени, а Let's Encrypt требует
доступный извне порт 80, которого в домашнем режиме нет вовсе.

Поэтому сертификат самоподписанный: браузер один раз покажет
предупреждение, зато трафик до панели зашифрован. Сертификат живёт в томе
состояния и переживает обновления.
"""
from __future__ import annotations

import datetime
import ipaddress
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID

VALID_DAYS = 3650


def _san_entries(hosts: list[str]) -> list:
    out: list = [x509.DNSName("localhost")]
    seen = {"localhost"}
    for h in hosts:
        h = (h or "").strip()
        if not h or h in seen:
            continue
        seen.add(h)
        try:
            out.append(x509.IPAddress(ipaddress.ip_address(h)))
        except ValueError:
            out.append(x509.DNSName(h))
    out.append(x509.IPAddress(ipaddress.ip_address("127.0.0.1")))
    return out


def ensure_cert(cert_dir: Path, hosts: list[str] | None = None) -> tuple[Path, Path]:
    """Вернуть (cert, key), создав их при первом запуске."""
    cert_dir.mkdir(parents=True, exist_ok=True)
    cert_path, key_path = cert_dir / "cert.pem", cert_dir / "key.pem"
    if cert_path.exists() and key_path.exists():
        return cert_path, key_path

    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "splitbox")])
    now = datetime.datetime.now(datetime.timezone.utc)
    cert = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - datetime.timedelta(minutes=5))
        .not_valid_after(now + datetime.timedelta(days=VALID_DAYS))
        .add_extension(x509.SubjectAlternativeName(_san_entries(hosts or [])),
                       critical=False)
        .add_extension(x509.BasicConstraints(ca=False, path_length=None),
                       critical=True)
        .sign(key, hashes.SHA256())
    )
    key_path.write_bytes(key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.TraditionalOpenSSL,
        serialization.NoEncryption()))
    key_path.chmod(0o600)
    cert_path.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    return cert_path, key_path
