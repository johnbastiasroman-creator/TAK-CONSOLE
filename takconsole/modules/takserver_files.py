# SPDX-License-Identifier: Apache-2.0
"""Edición de archivos de TAK Server sin efectos secundarios (fácil de probar).

* cert-metadata.sh: datos del sujeto de los certificados y contraseñas.
* CoreConfig.xml: keystores/truststores, contraseñas y firma de certificados
  (enrolamiento). Se edita como texto para conservar comentarios, espacios de
  nombres y el formato original; los comentarios se enmascaran antes de editar
  para no tocar los bloques de ejemplo comentados.
* Paquete de datos (data package) de conexión para ATAK/iTAK.
"""
import io
import re
import uuid
import zipfile
from xml.sax.saxutils import escape, quoteattr

# ── cert-metadata.sh ────────────────────────────────────────────────────────
CERT_METADATA_VARS = ("COUNTRY", "STATE", "CITY", "ORGANIZATION",
                      "ORGANIZATIONAL_UNIT", "CAPASS", "PASS")
_SAFE_SHELL_VALUE = re.compile(r"[A-Za-z0-9 .@%+=:,\-]*")


def patch_cert_metadata(text: str, values: dict) -> str:
    """Fija VAR="valor" en cert-metadata.sh. Lanza ValueError si falta alguna variable."""
    lines = text.splitlines(keepends=True)
    for var in CERT_METADATA_VARS:
        if var not in values:
            continue
        val = str(values[var])
        if not _SAFE_SHELL_VALUE.fullmatch(val):
            raise ValueError(f"valor no permitido para {var}")
        pat = re.compile(rf"^(\s*){var}=")
        for i, line in enumerate(lines):
            m = pat.match(line)
            if m:
                lines[i] = f'{m.group(1)}{var}="{val}"\n'
                break
        else:
            raise ValueError(f"cert-metadata.sh no contiene {var}=")
    return "".join(lines)


# ── CoreConfig.xml ──────────────────────────────────────────────────────────
_COMMENT = re.compile(r"<!--.*?-->", re.S)


def _mask_comments(text):
    saved = []

    def repl(m):
        saved.append(m.group(0))
        return f"\x00{len(saved) - 1}\x00"

    return _COMMENT.sub(repl, text), saved


def _unmask(text, saved):
    return re.sub(r"\x00(\d+)\x00", lambda m: saved[int(m.group(1))], text)


def set_attr(tag: str, name: str, value: str) -> str:
    """Fija un atributo en una etiqueta de apertura (`<tls ... >` o `<tls ... />`)."""
    qv = quoteattr(value)
    pat = re.compile(rf'(\s{re.escape(name)}\s*=\s*)("[^"]*"|\'[^\']*\')')
    if pat.search(tag):
        return pat.sub(lambda m: m.group(1) + qv, tag, count=1)
    m = re.search(r"\s*/?>\s*$", tag)
    return tag[:m.start()] + f" {name}={qv}" + tag[m.start():]


def _edit_first_tag(block, tag_name, attrs):
    pat = re.compile(rf"<{tag_name}\b[^>]*>", re.S)
    m = pat.search(block)
    if not m:
        raise ValueError(f"no se encontró <{tag_name}> en CoreConfig.xml")
    tag = m.group(0)
    for k, v in attrs.items():
        tag = set_attr(tag, k, v)
    return block[:m.start()] + tag + block[m.end():]


def _edit_section(text, section, fn):
    pat = re.compile(rf"<{section}\b[^>]*>.*?</{section}>", re.S)
    m = pat.search(text)
    if not m:
        return text, False
    return text[:m.start()] + fn(m.group(0)) + text[m.end():], True


def certificate_signing_block(signing_keystore, cert_pass, org, ou, validity_days):
    entries = ""
    if org:
        entries += f"\n                <nameEntry name=\"O\" value={quoteattr(org)}/>"
    if ou:
        entries += f"\n                <nameEntry name=\"OU\" value={quoteattr(ou)}/>"
    return (
        '<certificateSigning CA="TAKServer">\n'
        "        <certificateConfig>\n"
        f"            <nameEntries>{entries}\n"
        "            </nameEntries>\n"
        "        </certificateConfig>\n"
        f'        <TAKServerCAConfig keystore="JKS" keystoreFile={quoteattr(signing_keystore)} '
        f'keystorePass={quoteattr(cert_pass)} validityDays="{int(validity_days)}" '
        'signatureAlg="SHA256WithRSA"/>\n'
        "    </certificateSigning>"
    )


def patch_coreconfig(text: str, *, cert_pass: str, truststore: str,
                     keystore="certs/files/takserver.jks", enrollment=None) -> str:
    """Devuelve CoreConfig.xml ajustado.

    enrollment: None para no tocar el bloque, False para quitarlo, o un dict
    {'keystore', 'org', 'ou', 'days'} para (re)crearlo.
    """
    masked, saved = _mask_comments(text)

    def security(block):
        return _edit_first_tag(block, "tls", {
            "keystoreFile": keystore, "keystorePass": cert_pass,
            "truststoreFile": truststore, "truststorePass": cert_pass,
        })

    masked, found = _edit_section(masked, "security", security)
    if not found:
        raise ValueError("CoreConfig.xml no tiene sección <security>")

    def federation(block):
        if not re.search(r"<tls\b", block):
            return block
        return _edit_first_tag(block, "tls", {"keystorePass": cert_pass,
                                              "truststorePass": cert_pass})

    masked, _ = _edit_section(masked, "federation", federation)

    if enrollment is not None:
        masked = re.sub(r"\s*<certificateSigning\b.*?</certificateSigning>", "", masked, flags=re.S)
        if enrollment:
            block = certificate_signing_block(
                enrollment["keystore"], cert_pass, enrollment.get("org", ""),
                enrollment.get("ou", ""), enrollment.get("days", 365))
            m = re.search(r"</security>", masked)
            masked = masked[:m.end()] + "\n\n    " + block + masked[m.end():]

    return _unmask(masked, saved)


def coreconfig_summary(text: str) -> dict:
    """Lectura informativa de CoreConfig.xml para la página del módulo."""
    masked, _ = _mask_comments(text)
    inputs = re.findall(r"<input\b[^>]*>", masked)
    connectors = re.findall(r"<connector\b[^>]*>", masked)

    def attr(tag, name):
        m = re.search(rf'\s{name}\s*=\s*"([^"]*)"', tag)
        return m.group(1) if m else ""

    return {
        "inputs": [{"name": attr(t, "_name"), "protocol": attr(t, "protocol"),
                    "port": attr(t, "port"), "auth": attr(t, "auth")} for t in inputs],
        "connectors": [{"name": attr(t, "_name"), "port": attr(t, "port"),
                        "clientAuth": attr(t, "clientAuth")} for t in connectors],
        "enrollment": bool(re.search(r"<certificateSigning\b", masked)),
    }


# ── Paquete de conexión (data package) ──────────────────────────────────────
def server_pref(host, port, description, ca_file, cert_file, cert_pass, per_stream=True):
    """Preferencias de conexión.

    ATAK lee los certificados por conexión (caLocation0, ...); iTAK usa las
    claves globales de com.atakmap.app_preferences. Para ATAK se incluyen ambas.
    """
    def entry(key, cls, value):
        return (f'    <entry key="{key}" class="class java.lang.{cls}">'
                f"{escape(str(value))}</entry>\n")

    stream_certs = ""
    if per_stream:
        stream_certs = (entry("caLocation0", "String", f"cert/{ca_file}")
                        + entry("caPassword0", "String", cert_pass)
                        + entry("clientPassword0", "String", cert_pass)
                        + entry("certificateLocation0", "String", f"cert/{cert_file}"))
    return (
        "<?xml version='1.0' encoding='ASCII' standalone='yes'?>\n"
        "<preferences>\n"
        '  <preference version="1" name="cot_streams">\n'
        + entry("count", "Integer", 1)
        + entry("description0", "String", description)
        + entry("enabled0", "Boolean", "true")
        + entry("connectString0", "String", f"{host}:{port}:ssl")
        + stream_certs
        + "  </preference>\n"
        '  <preference version="1" name="com.atakmap.app_preferences">\n'
        + entry("displayServerConnectionWidget", "Boolean", "true")
        + entry("caLocation", "String", f"cert/{ca_file}")
        + entry("caPassword", "String", cert_pass)
        + entry("clientPassword", "String", cert_pass)
        + entry("certificateLocation", "String", f"cert/{cert_file}")
        + "  </preference>\n"
        "</preferences>\n"
    )


def manifest(name, entries, uid=None):
    uid = uid or str(uuid.uuid4())
    contents = "".join(f'    <Content ignore="false" zipEntry={quoteattr(e)}/>\n' for e in entries)
    return (
        '<MissionPackageManifest version="2">\n'
        "  <Configuration>\n"
        f'    <Parameter name="uid" value={quoteattr(uid)}/>\n'
        f'    <Parameter name="name" value={quoteattr(name)}/>\n'
        '    <Parameter name="onReceiveDelete" value="true"/>\n'
        "  </Configuration>\n"
        "  <Contents>\n"
        f"{contents}"
        "  </Contents>\n"
        "</MissionPackageManifest>\n"
    )


def data_package(*, user, host, port, description, truststore_name, truststore_bytes,
                 user_p12_bytes, cert_pass, kind="atak") -> bytes:
    """ZIP de conexión con truststore + certificado del usuario.

    kind="atak": paquete con MANIFEST/manifest.xml (ATAK, WinTAK).
    kind="itak": ZIP plano con config.pref (iTAK).
    """
    user_p12 = f"{user}.p12"
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        if kind == "itak":
            zf.writestr("config.pref", server_pref(host, port, description, truststore_name,
                                                   user_p12, cert_pass, per_stream=False))
            zf.writestr(truststore_name, truststore_bytes)
            zf.writestr(user_p12, user_p12_bytes)
        else:
            pref = server_pref(host, port, description, truststore_name, user_p12, cert_pass)
            entries = ["certs/server.pref", f"certs/{truststore_name}", f"certs/{user_p12}"]
            zf.writestr("MANIFEST/manifest.xml", manifest(f"{description} - {user}", entries))
            zf.writestr("certs/server.pref", pref)
            zf.writestr(f"certs/{truststore_name}", truststore_bytes)
            zf.writestr(f"certs/{user_p12}", user_p12_bytes)
    return buf.getvalue()
