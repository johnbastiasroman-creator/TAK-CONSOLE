# SPDX-License-Identifier: Apache-2.0
"""Consolas de estado y actividad: formatos de registro, clasificación y conectados.

Las líneas de ejemplo siguen los formatos del código fuente de cada servicio (MediaMTX 1.21.2:
internal/logger y servers; Mumble 1.6.870: main.cpp y Server.cpp; TAK Server: logback-spring.xml).
No son capturas de un servidor real."""
import json

import pytest

from takconsole.core import docker, monitor, settings
from takconsole.core.shell import Result
from takconsole.modules import MODULES, mediamtx, mumble, takserver, zerotier


def events(module, lines):
    return [(e["event"] or {}).get("tag") for e in monitor.process_lines(module, lines)]


# ── comunes ─────────────────────────────────────────────────────────────────
def test_redact_enmascara_contrasenas_en_consultas():
    assert monitor.redact("rtmp://x/cam?user=a&pass=secreto&k=1") == "rtmp://x/cam?user=a&pass=******&k=1"
    assert "tok123" not in monitor.redact("GET /x?token=tok123")


def test_parse_ts_acepta_nanosegundos_de_go():
    a = monitor.parse_ts("2026-10-26T14:21:17.123456789Z")
    b = monitor.parse_ts("2026-10-26T14:21:17Z")
    assert a is not None and abs(a - b) < 1
    assert monitor.parse_ts("nada") is None and monitor.parse_ts(None) is None


def test_age_y_bytes():
    assert monitor.age(5) == "5 s" and monitor.age(600) == "10 min" and monitor.age(7200) == "2 h"
    assert monitor.human_bytes(2048) == "2.0 KB" and monitor.human_bytes(None) == "—"


def test_table_limita_filas():
    t = monitor.table(["a"], [[i] for i in range(monitor.ROW_CAP + 5)])
    assert len(t["rows"]) == monitor.ROW_CAP and t["total"] == monitor.ROW_CAP + 5


# ── MediaMTX ────────────────────────────────────────────────────────────────
MTX_LINES = [
    "2026/10/26 14:21:17 INF [RTSP] [conn 10.0.0.5:5000] opened",
    "2026/10/26 14:21:17 INF [RTSP] [session 8f1c] created by 10.0.0.5:5000",
    "2026/10/26 14:21:18 INF [RTSP] [session 8f1c] is publishing to path 'camara1', 2 tracks (H264, MPEG-4 Audio)",
    "2026/10/26 14:21:18 INF [path camara1] stream is available and online, 2 tracks (H264, MPEG-4 Audio)",
    "2026/10/26 14:22:00 INF [WebRTC] [session 77aa] is reading from path 'camara1', 1 track (H264)",
    "2026/10/26 14:23:00 INF [RTSP] [conn 10.0.0.5:5000] closed: terminated",
    "2026/10/26 14:23:01 WAR [RTSP] [session 8f1c] 3 RTP packets lost",
    "2026/10/26 14:23:02 ERR [SRT] [conn 10.0.0.9:7000] closed: authentication failed",
    "2026/10/26 14:23:03 INF [API] listener opened on 127.0.0.1:9997",
]


def test_mediamtx_eventos_y_niveles():
    m = mediamtx.MediaMTX()
    assert events(m, MTX_LINES) == ["CONEXIÓN", "CONEXIÓN", "PUBLICA", "STREAM ACTIVO", "LEE",
                                    "DESCONEXIÓN", "AVISO", "CLAVE RECHAZADA", None]
    assert [m.line_level(x) for x in MTX_LINES[-3:]] == ["warn", "err", "info"]


def test_mediamtx_conectados_une_protocolos(monkeypatch):
    now = monitor.parse_ts("2026-10-26T14:23:00Z")
    monkeypatch.setattr(mediamtx.time, "time", lambda: now + 120)

    def fake(path, timeout=3):
        if path == "/v3/rtsp/sessions/list":
            return {"items": [{"id": "x", "created": "2026-10-26T14:21:00Z", "remoteAddr": "10.0.0.5:5000",
                               "state": "publish", "path": "camara1", "user": "", "bytesReceived": 4096,
                               "bytesSent": 0}]}
        if path == "/v3/hls/sessions/list":
            return {"items": [{"id": "h", "created": "2026-10-26T14:22:00Z", "remoteAddr": "10.0.0.7:1",
                               "path": "camara1", "outboundBytes": 1024}]}
        if path == "/v3/paths/list":
            return {"items": [{"name": "camara1", "ready": True, "readers": [{}, {}]}]}
        raise OSError("desactivado")

    monkeypatch.setattr(mediamtx, "_api_get", fake)
    t = mediamtx.MediaMTX().connected()
    assert t["columns"][0] == "Protocolo" and t["error"] is None
    rows = {r[0]: r for r in t["rows"]}
    assert rows["RTSP"][1:4] == ["Publica", "10.0.0.5:5000", "camara1"]
    assert rows["RTSP"][5] == "4 min" and rows["RTSP"][6] == "4.0 KB"
    assert rows["HLS"][1] == "Lee" and rows["HLS"][7] == "1.0 KB"
    assert "camara1 (2 lectores)" in t["note"]


def test_mediamtx_conectados_sin_api(monkeypatch):
    def boom(path, timeout=3):
        raise OSError("sin conexión")
    monkeypatch.setattr(mediamtx, "_api_get", boom)
    assert mediamtx.MediaMTX().connected()["error"]


# ── Mumble ──────────────────────────────────────────────────────────────────
MUM_LINES = [
    "<W>2026-10-26 11:00:00.100 1 => Server listening on 0.0.0.0:64738",
    "<W>2026-10-26 11:30:10.000 1 => <5:(-1)> New connection: 10.0.0.5:55000",
    "<W>2026-10-26 11:30:12.345 1 => <5:john(3)> Authenticated",
    "<W>2026-10-26 11:31:00.000 1 => <6:(-1)> New connection: 10.0.0.6:55001",
    "<W>2026-10-26 11:31:01.000 1 => <6:(-1)> Rejected connection from 10.0.0.6:55001: Wrong certificate or password",
    "<W>2026-10-26 11:31:01.500 1 => <6:(-1)> Connection closed: The remote host closed the connection [1]",
    "<W>2026-10-26 11:32:00.000 1 => <5:john(3)> Moved john to Sala 2",
    "<W>2026-10-26 11:33:00.000 1 => <7:ana(-1)> Timeout",
    "<C>2026-10-26 11:34:00.000 Something broke",
]


def test_mumble_eventos_y_niveles():
    m = mumble.Mumble()
    assert events(m, MUM_LINES) == ["ACTIVO", "CONEXIÓN", "AUTENTICADO", "CONEXIÓN", "RECHAZADO",
                                    "DESCONEXIÓN", "CAMBIO DE CANAL", "TIEMPO AGOTADO", "ERROR"]
    assert m.line_level(MUM_LINES[2]) == "info"      # <W> es el nivel normal del servidor
    assert m.line_level(MUM_LINES[-1]) == "err"


def test_mumble_sesiones_desde_el_registro():
    s = mumble.sessions_from_log(MUM_LINES)
    assert list(s) == ["5"]                          # la 6 se rechazó y cerró
    assert s["5"]["name"] == "john" and s["5"]["addr"] == "10.0.0.5:55000" and s["5"]["auth"]


def test_mumble_el_reinicio_olvida_sesiones():
    lines = MUM_LINES[:3] + ["<W>2026-10-26 12:00:00.000 1 => Server listening on 0.0.0.0:64738"]
    assert mumble.sessions_from_log(lines) == {}


def test_mumble_conectados_avisa_si_no_coincide_con_ss(monkeypatch):
    monkeypatch.setattr(docker, "logs", lambda name, n: "\n".join(MUM_LINES))
    monkeypatch.setattr(mumble, "tcp_peers", lambda: ["10.0.0.5:55000", "10.0.0.8:1"])
    t = mumble.Mumble().connected()
    assert t["rows"][0][:3] == ["john", "5", "10.0.0.5:55000"]
    assert "No coincide" in t["note"] and "2" in t["note"]


def test_mumble_tcp_peers_lee_la_columna_del_cliente(monkeypatch):
    out = "0 0 10.0.0.1:64738 10.0.0.5:55000\n0 0 10.0.0.1:64738 [::ffff:10.0.0.6]:55001\n"
    monkeypatch.setattr(mumble, "capture", lambda argv, **kw: Result(0, out))
    assert mumble.tcp_peers() == ["10.0.0.5:55000", "[::ffff:10.0.0.6]:55001"]
    monkeypatch.setattr(mumble, "capture", lambda argv, **kw: Result(1, ""))
    assert mumble.tcp_peers() == []


# ── TAK Server ──────────────────────────────────────────────────────────────
TAK_LINES = [
    "2026-10-26-11:36:00.123 [pool-3] INFO c.b.m.x.Foo - todo bien",
    "2026-10-26-11:36:01.123 [pool-3] WARN c.b.m.x.Foo - algo raro",
    "2026-10-26-11:36:02.123 [pool-4] ERROR c.b.m.g.LdapAuthenticator - LDAP Authentication Failed: bad",
    "2026-10-26-11:36:03.123 [main] INFO o.s.b.w.e.t.TomcatWebServer - Tomcat started on port 8443",
    '{"level":"ERROR","message":"formato json"}',
]


def test_tak_niveles_y_eventos():
    t = takserver.TakServer()
    assert [t.line_level(x) for x in TAK_LINES] == ["info", "warn", "err", "info", "err"]
    assert events(t, TAK_LINES) == [None, "AVISO", "AUTH FALLIDA", "ARRANCADO", "ERROR"]


def test_tak_conectados_arma_filas():
    payload = {"version": "3", "type": "x", "data": [
        {"callsign": "ALFA", "clientUid": "ANDROID-0123456789abcdef0123", "ipAddress": "10.0.0.5",
         "protocol": "ssl", "takClient": "ATAK-CIV", "takVersion": "5.4", "role": "Team Member",
         "team": "Cyan", "lastReportMilliseconds": 880_000}]}
    rows, unknown = takserver.subscription_rows(payload, 1000.0)
    assert unknown == 0 and rows[0][0] == "ALFA" and rows[0][1].endswith("…")
    assert rows[0][4] == "ATAK-CIV 5.4" and rows[0][5] == "Team Member / Cyan" and rows[0][6] == "2 min"


def test_tak_conectados_campos_inesperados_se_avisan(monkeypatch):
    monkeypatch.setattr(takserver, "tak_api_get", lambda path: {"data": [{"otra": 1}]})
    t = takserver.TakServer().connected()
    assert "otro formato" in t["note"]


def test_tak_conectados_error_legible_sin_certificados(data_dir, monkeypatch, tmp_path):
    monkeypatch.setattr(takserver, "FILES", tmp_path / "vacio")
    t = takserver.TakServer().connected()
    assert t["error"] and "admin.pem" in t["error"]


def test_tak_log_lee_el_final_del_archivo(monkeypatch, tmp_path):
    (tmp_path / "takserver-messaging.log").write_text("\n".join(f"linea {i}" for i in range(1000)))
    monkeypatch.setattr(takserver, "TAK_LOGS", tmp_path)
    lines = takserver.TakServer().log_lines(50, "messaging")
    assert len(lines) == 50 and lines[-1] == "linea 999"
    assert "todavía no existe" in takserver.TakServer().log_lines(5, "api")[0]


def test_tak_fuentes_de_registro():
    assert [s for s, _ in takserver.TakServer().log_sources()] == ["messaging", "api"]


# ── ZeroTier ────────────────────────────────────────────────────────────────
def test_zerotier_conectados_solo_pares_leaf(monkeypatch):
    peers = [{"address": "aaaaaaaaaa", "role": "LEAF", "latency": 12, "version": "1.14.2",
              "paths": [{"active": True, "address": "10.0.0.5/9993", "lastReceive": 1_000_000}]},
             {"address": "bbbbbbbbbb", "role": "LEAF", "latency": -1, "paths": []},
             {"address": "62f865ae71", "role": "PLANET", "paths": []}]
    monkeypatch.setattr(zerotier, "cli", lambda *a, **k: Result(0, json.dumps(peers)))
    monkeypatch.setattr(zerotier.time, "time", lambda: 1_060)
    t = zerotier.ZeroTier().connected()
    assert [r[0] for r in t["rows"]] == ["aaaaaaaaaa", "bbbbbbbbbb"]
    assert t["rows"][0][1:5] == ["Directo", "10.0.0.5/9993", "12 ms", "1.14.2"]
    assert t["rows"][1][1] == "Por relé" and t["rows"][1][3] == "—"


def test_zerotier_conectados_sin_respuesta(monkeypatch):
    monkeypatch.setattr(zerotier, "cli", lambda *a, **k: Result(1, ""))
    assert zerotier.ZeroTier().connected()["error"]


# ── ruta HTTP y página ──────────────────────────────────────────────────────
def get(client, key, **q):
    return client.get(f"/api/m/{key}/monitor", query_string=q)


def test_ruta_requiere_login(data_dir):
    from takconsole import create_app
    r = create_app().test_client().get("/api/m/mumble/monitor")
    assert r.status_code in (302, 401)


def test_ruta_modulo_inexistente(client):
    assert get(client, "nada").status_code == 404


def test_ruta_no_instalado(client):
    d = get(client, "mumble").get_json()
    assert d["ok"] and d["installed"] is False and d["lines"] == []


@pytest.mark.parametrize("key", ["mediamtx", "mumble", "zerotier"])
@pytest.mark.parametrize("view", ["events", "raw", "clients", "inventada"])
def test_ruta_instalado_nunca_falla(client, key, view):
    settings.replace_section(key, {"installed": True})
    r = get(client, key, view=view)
    d = r.get_json()
    assert r.status_code == 200 and d["ok"] and d["installed"] is True
    assert d["view"] in monitor.VIEWS and isinstance(d["checks"], list)
    assert r.headers["Cache-Control"] == "no-store"
    if d["view"] == "clients":
        assert d["clients"]["columns"] is not None


def test_ruta_enmascara_secretos_y_escapa_nada(client, monkeypatch):
    settings.replace_section("mediamtx", {"installed": True})
    monkeypatch.setattr(mediamtx.MediaMTX, "log_lines",
                        lambda self, n, source="": ["2026/10/26 14:00:00 INF x rtmp://h/c?user=a&pass=clave123",
                                                    "<script>alert(1)</script>"])
    d = get(client, "mediamtx").get_json()
    assert "clave123" not in json.dumps(d) and "pass=******" in d["lines"][0]["text"]
    assert d["lines"][1]["text"] == "<script>alert(1)</script>"   # va tal cual: la interfaz usa textContent


def test_ruta_fuente_desconocida_usa_la_primera(client, monkeypatch):
    settings.replace_section("zerotier", {"installed": True})
    d = get(client, "zerotier", source="../../etc/passwd").get_json()
    assert d["source"] == "zerotier"


def test_ruta_un_fallo_en_los_registros_no_la_tumba(client, monkeypatch):
    settings.replace_section("mumble", {"installed": True})

    def boom(self, n, source=""):
        raise RuntimeError("docker no responde")
    monkeypatch.setattr(mumble.Mumble, "log_lines", boom)
    d = get(client, "mumble").get_json()
    assert d["ok"] and d["lines"] == [] and "docker no responde" in d["log_error"]


def test_pagina_incluye_la_consola_solo_si_esta_instalado(client):
    assert "data-monitor" not in client.get("/m/mediamtx").get_data(as_text=True)
    settings.replace_section("mediamtx", {"installed": True, "params": {}})
    html = client.get("/m/mediamtx").get_data(as_text=True)
    assert 'data-monitor="mediamtx"' in html and "Registro + conectados" in html


def test_todos_los_modulos_exponen_los_ganchos():
    for m in MODULES.values():
        assert isinstance(m.log_sources(), list) and m.log_sources()
        assert isinstance(m.EVENT_RULES, list)
