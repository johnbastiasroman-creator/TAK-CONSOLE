# SPDX-License-Identifier: Apache-2.0
"""Apariencia de la consola: nombre, logo, icono de la pestaña y color de acento.

Todo lo que sube el administrador se valida antes de guardarse:
  · el tipo se decide por el CONTENIDO (firma del archivo), no por el nombre ni por lo que
    declare el navegador;
  · un SVG puede llevar código, así que se rechaza si trae <script>, <foreignObject>, eventos
    (onload…), referencias externas o una declaración DOCTYPE/ENTITY;
  · tamaños acotados;
  · el color debe ser legible sobre el fondo de la consola (para no dejarla inutilizable).

Los archivos se sirven desde rutas públicas (el logo y el icono se ven en la pantalla de inicio de
sesión) con cabeceras que impiden que un SVG ejecute nada si alguien abre su URL directamente.
"""
import re
import threading
import xml.etree.ElementTree as ET

from .. import config
from . import settings

SECTION = "branding"
MAX_BYTES = {"logo": 512 * 1024, "login": 512 * 1024, "favicon": 256 * 1024}
ALLOWED = {"logo": ("png", "jpg", "webp", "svg"), "login": ("png", "jpg", "webp", "svg"),
           "favicon": ("png", "ico", "svg")}
MIME = {"png": "image/png", "jpg": "image/jpeg", "webp": "image/webp",
        "ico": "image/x-icon", "svg": "image/svg+xml"}
LABEL = {"logo": "logo", "login": "logo de ingreso", "favicon": "icono"}

NAME_PATTERN = r"[\w .,_+&()/-]{1,40}"
NAME_MESSAGE = "1 a 40 caracteres: letras, números, espacios y . , _ - + & ( ) /"
BACKGROUND = "#1c2320"          # fondo de la consola (--bg en app.css)
MIN_CONTRAST = 3.0              # mínimo WCAG para elementos de interfaz sobre el fondo
DARK_INK, LIGHT_INK = "#1a1405", "#ffffff"
_LOCK = threading.RLock()

_FORBIDDEN_TAGS = {"script", "foreignobject", "iframe", "object", "embed", "audio", "video",
                   "animate", "set", "animatetransform", "animatemotion"}
_SAFE_DATA_URI = re.compile(r"data:image/(png|jpeg|webp|gif);base64,[A-Za-z0-9+/=\s]*", re.I)


# ── color ───────────────────────────────────────────────────────────────────
def _luminance(hex_color):
    def chan(i):
        c = int(hex_color[1 + 2 * i:3 + 2 * i], 16) / 255
        return c / 12.92 if c <= 0.03928 else ((c + 0.055) / 1.055) ** 2.4
    return 0.2126 * chan(0) + 0.7152 * chan(1) + 0.0722 * chan(2)


def contrast(a, b):
    la, lb = sorted((_luminance(a), _luminance(b)), reverse=True)
    return (la + 0.05) / (lb + 0.05)


def ink_for(accent):
    """Color de texto (oscuro o blanco) con mejor contraste sobre un botón del color de acento."""
    return DARK_INK if contrast(accent, DARK_INK) >= contrast(accent, LIGHT_INK) else LIGHT_INK


def check_accent(value):
    """Devuelve el color normalizado (#rrggbb) o lanza ValueError con un mensaje para el formulario."""
    v = (value or "").strip().lower()
    if not re.fullmatch(r"#[0-9a-f]{6}", v):
        raise ValueError("Usa el formato #RRGGBB, por ejemplo #e9a43c")
    if contrast(v, BACKGROUND) < MIN_CONTRAST:
        raise ValueError("Ese color es demasiado oscuro para leerse sobre el fondo de la consola")
    return v


# ── detección y validación de imágenes ──────────────────────────────────────
def _local(tag):
    return tag.rsplit("}", 1)[-1].lower()


def check_svg(data: bytes):
    try:
        text = data.decode("utf-8-sig")
    except UnicodeDecodeError:
        raise ValueError("El SVG debe estar codificado en UTF-8")
    low = text.lower()
    if "<!doctype" in low or "<!entity" in low:
        raise ValueError("El SVG no puede declarar DOCTYPE ni entidades")
    if "javascript:" in low or "@import" in low:
        raise ValueError("El SVG contiene contenido activo o referencias externas")
    try:
        root = ET.fromstring(text)
    except ET.ParseError:
        raise ValueError("El SVG está mal formado")
    if _local(root.tag) != "svg":
        raise ValueError("El archivo no es un SVG")
    for el in root.iter():
        if not isinstance(el.tag, str):
            continue
        if _local(el.tag) in _FORBIDDEN_TAGS:
            raise ValueError(f"El SVG contiene un elemento no permitido (<{_local(el.tag)}>)")
        for attr, val in el.attrib.items():
            name = _local(attr)
            if name.startswith("on"):
                raise ValueError("El SVG contiene manejadores de eventos")
            if name == "href" and not (val.startswith("#") or _SAFE_DATA_URI.fullmatch(val.strip())):
                raise ValueError("El SVG referencia recursos externos")


def detect(data: bytes, kind: str) -> str:
    """Extensión según el contenido, validando que sea un formato permitido para ese uso."""
    if data[:8] == b"\x89PNG\r\n\x1a\n":
        ext = "png"
    elif data[:3] == b"\xff\xd8\xff":
        ext = "jpg"
    elif data[:4] == b"RIFF" and data[8:12] == b"WEBP":
        ext = "webp"
    elif data[:4] == b"\x00\x00\x01\x00" and len(data) > 6 and data[4] > 0:
        ext = "ico"
    elif b"<svg" in data[:4096].lower():
        ext = "svg"
    else:
        raise ValueError("Formato no reconocido")
    if ext not in ALLOWED[kind]:
        raise ValueError("Formato no permitido para el " + LABEL[kind] + ": usa "
                         + ", ".join(e.upper() for e in ALLOWED[kind]))
    if ext == "svg":
        check_svg(data)
    return ext


# ── estado ──────────────────────────────────────────────────────────────────
def _state():
    return settings.section(SECTION)


def _image_path(kind, state):
    meta = state.get(kind)
    if not meta:
        return None
    path = config.BRANDING_DIR / meta["file"]
    return path if path.is_file() else None


def get() -> dict:
    """Datos de apariencia listos para las plantillas."""
    st = _state()
    rev = int(st.get("rev", 0))
    q = f"?v={rev}"
    accent = st.get("accent") or None
    return {
        "name": st.get("name") or config.APP_NAME,
        "custom_name": bool(st.get("name")),
        "show_name": st.get("show_name", True) is not False,
        "accent": accent,
        "accent_ink": ink_for(accent) if accent else None,
        "logo_url": "/branding/logo" + q if _image_path("logo", st) else None,
        # Logo de la pantalla de ingreso: el propio si existe; si no, el del sitio.
        "login_logo_url": ("/branding/login" + q if _image_path("login", st)
                           else ("/branding/logo" + q if _image_path("logo", st) else None)),
        "has_login_logo": bool(_image_path("login", st)),
        "favicon_url": "/branding/favicon" + q if _image_path("favicon", st) else None,
        "favicon_mime": (st.get("favicon") or {}).get("mime"),
        "theme_url": "/branding/theme.css" + q,
        "customized": bool(st.get("name") or accent or st.get("logo") or st.get("login") or st.get("favicon")
                           or st.get("show_name") is False),
    }


def image(kind):
    """(ruta, mime) del logo o icono guardado, o None."""
    st = _state()
    path = _image_path(kind, st)
    return (path, st[kind]["mime"]) if path else None


def theme_css() -> str:
    st = _state()
    accent = st.get("accent")
    if not accent:
        return "/* sin color personalizado */\n"
    return f":root {{ --accent: {accent}; --accent-ink: {ink_for(accent)}; }}\n"


def _bump(values):
    st = dict(_state())
    st.update(values)
    st["rev"] = int(st.get("rev", 0)) + 1
    settings.replace_section(SECTION, {k: v for k, v in st.items() if v is not None})


def check_name(name):
    name = (name or "").strip()
    if name and not re.fullmatch(NAME_PATTERN, name):
        raise ValueError(NAME_MESSAGE)
    return name


def set_text(name, accent, show_name=True):
    """Guarda nombre, color y si el nombre se muestra junto al logo. Vacío = valor por defecto."""
    name = check_name(name)
    accent = check_accent(accent) if (accent or "").strip() else None
    with _LOCK:
        _bump({"name": name or None, "accent": accent, "show_name": None if show_name else False})


def set_image(kind, data: bytes):
    if kind not in ALLOWED:
        raise ValueError("Tipo de imagen inválido")
    if not data:
        raise ValueError("El archivo está vacío")
    if len(data) > MAX_BYTES[kind]:
        raise ValueError(f"El {LABEL[kind]} pesa demasiado (máximo {MAX_BYTES[kind] // 1024} KB)")
    ext = detect(data, kind)
    with _LOCK:
        config.BRANDING_DIR.mkdir(parents=True, exist_ok=True)
        _remove_files(kind)
        dest = config.BRANDING_DIR / f"{kind}.{ext}"
        dest.write_bytes(data)
        dest.chmod(0o600)
        _bump({kind: {"file": dest.name, "mime": MIME[ext]}})


def _remove_files(kind):
    for old in config.BRANDING_DIR.glob(f"{kind}.*"):
        try:
            old.unlink()
        except OSError:
            pass


def clear_image(kind):
    if kind not in ALLOWED:
        raise ValueError("Tipo de imagen inválido")
    with _LOCK:
        _remove_files(kind)
        _bump({kind: None})


def reset():
    with _LOCK:
        for kind in ALLOWED:
            _remove_files(kind)
        _bump({"name": None, "accent": None, "logo": None, "login": None, "favicon": None,
               "show_name": None})
