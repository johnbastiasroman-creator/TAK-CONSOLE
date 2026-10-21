# SPDX-License-Identifier: Apache-2.0
"""Validación de formularios.

Todo valor que termina en un archivo de configuración, un certificado o un
comando se valida con una lista blanca de caracteres.
"""
import re
import secrets
import string


class Form:
    """Lee campos de un formulario y acumula errores por campo."""

    def __init__(self, data):
        self.data = data or {}
        self.errors = {}

    def raw(self, name, default=""):
        v = self.data.get(name, default)
        if v is None:
            return default
        return str(v).strip()

    def text(self, name, pattern, message, default="", required=True):
        v = self.raw(name, default)
        if not v:
            if required:
                self.errors[name] = "Campo obligatorio"
            return v
        if "\n" in v or "\r" in v or not re.fullmatch(pattern, v):
            self.errors[name] = message
        return v

    def integer(self, name, lo, hi, default):
        v = self.raw(name, str(default))
        try:
            n = int(v)
        except ValueError:
            self.errors[name] = "Debe ser un número entero"
            return default
        if not lo <= n <= hi:
            self.errors[name] = f"Debe estar entre {lo} y {hi}"
        return n

    def boolean(self, name):
        return self.raw(name, "").lower() in ("1", "true", "on", "yes", "si", "sí")

    def choice(self, name, options, default):
        v = self.raw(name, default)
        if v not in options:
            self.errors[name] = "Opción inválida"
            return default
        return v

    def error(self, name, msg):
        self.errors[name] = msg

    @property
    def ok(self):
        return not self.errors


# Texto ASCII imprimible en certificados X.509 (PrintableString): sin tildes ni ñ.
CERT_FIELD = r"[A-Za-z0-9 .\-]{1,64}"
CERT_FIELD_MSG = "Solo letras sin tildes, números, espacios, punto y guion (máx. 64)"
CA_NAME = r"[A-Za-z0-9\-]{5,32}"
CA_NAME_MSG = "5 a 32 caracteres: letras, números y guion (sin espacios ni guion bajo)"
# Contraseñas que terminan en scripts de TAK y keystores Java: sin caracteres de shell.
CERT_PASS = r"[A-Za-z0-9.@%+=:,\-]{6,64}"
CERT_PASS_MSG = "6 a 64 caracteres: letras, números y . @ % + = : , -"
USERNAME = r"[A-Za-z0-9._\-]{3,32}"
USERNAME_MSG = "3 a 32 caracteres: letras, números, punto, guion y guion bajo"
CLIENT_NAME = r"[A-Za-z0-9\-]{3,32}"
CLIENT_NAME_MSG = "3 a 32 caracteres: letras, números y guion"
# Contraseñas de servicios (Mumble, MediaMTX): se escriben en .env / YAML.
SERVICE_PASS = r"[A-Za-z0-9.@%+=:,_\-]{8,64}"
SERVICE_PASS_MSG = "8 a 64 caracteres: letras, números y . @ % + = : , _ -"
GROUP = r"[A-Za-z0-9 _\-]{1,40}"

TAK_SPECIALS = "-_!@#$%^&*(){}[]+=~`|:;<>,./\\?"


def tak_password_problems(pw: str) -> list:
    """Reglas de UserManager de TAK Server: ≥15, mayúscula, minúscula, número y especial."""
    probs = []
    if len(pw) < 15:
        probs.append("mínimo 15 caracteres")
    if not any(c.isupper() for c in pw):
        probs.append("una mayúscula")
    if not any(c.islower() for c in pw):
        probs.append("una minúscula")
    if not any(c.isdigit() for c in pw):
        probs.append("un número")
    if not any(c in TAK_SPECIALS for c in pw):
        probs.append("un carácter especial")
    if any(c.isspace() for c in pw) or any(ord(c) > 126 for c in pw):
        probs.append("sin espacios ni caracteres no ASCII")
    return probs


def random_password(length=20, alphabet=None) -> str:
    alphabet = alphabet or (string.ascii_letters + string.digits)
    return "".join(secrets.choice(alphabet) for _ in range(length))


def random_tak_password() -> str:
    while True:
        pw = random_password(14) + secrets.choice("@%+=:-") + secrets.choice(string.digits)
        if not tak_password_problems(pw):
            return pw
