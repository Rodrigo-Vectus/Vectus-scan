"""Helpers de seguridad puros (sin DB): hashing con pepper, generación de
códigos OTP y tokens de sesión, y comparación en tiempo constante.

El OTP y el token de sesión se guardan **hasheados** con HMAC-SHA256 usando
`AUTH_PEPPER` como clave. Nunca se persiste el valor en claro. La comparación
usa `hmac.compare_digest` para evitar fugas por timing.
"""
import hashlib
import hmac
import secrets

from app.config import settings


def hash_secret(value: str) -> str:
    """HMAC-SHA256(value, pepper) en hexadecimal. Se usa tanto para el código
    OTP como para el token de sesión."""
    return hmac.new(
        settings.auth_pepper.encode("utf-8"),
        value.encode("utf-8"),
        hashlib.sha256,
    ).hexdigest()


def verify_secret(value: str, hashed: str) -> bool:
    """Compara `value` (en claro) contra un hash previo, en tiempo constante."""
    return hmac.compare_digest(hash_secret(value), hashed)


def generate_otp_code() -> str:
    """Código OTP de 6 dígitos (con ceros a la izquierda), uniforme."""
    return f"{secrets.randbelow(1_000_000):06d}"


def generate_session_token() -> str:
    """Token de sesión opaco y de alta entropía (viaja en la cookie)."""
    return secrets.token_urlsafe(32)
