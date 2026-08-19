"""Envío del correo del OTP.

- **Con SMTP configurado** (SMTP_USER + SMTP_APP_PASSWORD en el .env): envía
  por Gmail (STARTTLS en el 587) un correo HTML con la **paleta de email**
  (fondo claro), distinta de la paleta dark de la web.
- **Sin SMTP configurado** (modo bootstrap): NO envía; registra el código en
  el log del backend con un WARNING explícito, para poder probar el flujo
  antes de cargar las credenciales reales. En este modo el código aparece en
  los logs SOLO porque no hay forma de entregarlo por correo.

El emisor nunca expone el código al cliente HTTP.
"""
import logging
import smtplib
from email.message import EmailMessage
from email.utils import formataddr

from app.config import settings

logger = logging.getLogger("vectus.auth.email")

# Paleta de email (fondo claro) — definida por Rodrigo, distinta de la web.
_NAVY = "#0B1220"
_CYAN = "#0E7490"
_BORDE = "#E2E8F0"
_TEXTO = "#1E293B"
_FONDO = "#F1F5F9"


def _render_html(code: str, minutes: int) -> str:
    return f"""\
<div style="background:{_FONDO};padding:32px 0;font-family:Segoe UI,Arial,sans-serif">
  <div style="max-width:480px;margin:0 auto;background:#ffffff;border:1px solid {_BORDE};border-radius:10px;overflow:hidden">
    <div style="background:{_NAVY};padding:20px 28px">
      <span style="color:#ffffff;font-size:18px;font-weight:600;letter-spacing:.5px">VECTUS<span style="color:{_CYAN}"> SCAN</span></span>
    </div>
    <div style="padding:28px">
      <p style="color:{_TEXTO};font-size:15px;margin:0 0 18px">Tu código de acceso para Vectus SCAN:</p>
      <div style="text-align:center;margin:24px 0">
        <span style="display:inline-block;font-family:Consolas,monospace;font-size:34px;font-weight:700;letter-spacing:10px;color:{_NAVY};background:{_FONDO};border:1px solid {_BORDE};border-radius:8px;padding:14px 22px">{code}</span>
      </div>
      <p style="color:{_TEXTO};font-size:13px;margin:0 0 6px">Vence en {minutes} minutos y es de un solo uso.</p>
      <p style="color:#64748B;font-size:12px;margin:14px 0 0">Si no solicitaste este código, ignorá este correo.</p>
    </div>
    <div style="background:{_FONDO};border-top:1px solid {_BORDE};padding:14px 28px">
      <span style="color:#94A3B8;font-size:11px">Vectus SCAN — orquestación de análisis de exposición</span>
    </div>
  </div>
</div>"""


def send_otp_email(to_email: str, code: str) -> None:
    """Envía el código a `to_email`. En modo bootstrap lo loguea.

    No lanza si el envío falla en runtime: registra el error. El flujo de
    verificación no depende de la confirmación de entrega (el usuario reintenta
    o pide otro código).
    """
    minutes = settings.otp_ttl_minutes

    if not settings.smtp_configured:
        logger.warning(
            "[BOOTSTRAP] SMTP no configurado. Código OTP para %s: %s "
            "(válido %d min). Configurá SMTP_USER/SMTP_APP_PASSWORD en el .env "
            "para enviar por correo.",
            to_email, code, minutes,
        )
        return

    msg = EmailMessage()
    msg["Subject"] = "Tu código de acceso a Vectus SCAN"
    msg["From"] = settings.smtp_from_effective
    msg["To"] = to_email
    msg.set_content(
        f"Tu código de acceso para Vectus SCAN es: {code}\n"
        f"Vence en {minutes} minutos y es de un solo uso.\n"
        f"Si no lo solicitaste, ignorá este correo."
    )
    msg.add_alternative(_render_html(code, minutes), subtype="html")

    try:
        with smtplib.SMTP(settings.smtp_host, settings.smtp_port, timeout=15) as smtp:
            smtp.starttls()
            smtp.login(settings.smtp_user, settings.smtp_app_password)
            smtp.send_message(msg)
        logger.info("OTP enviado a %s", to_email)
    except Exception as exc:  # noqa: BLE001
        logger.error("Fallo al enviar OTP a %s: %s", to_email, exc)
