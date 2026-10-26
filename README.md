# TAK-CONSOLE

Consola web para desplegar y administrar, desde el navegador, un servidor de operaciones TAK en un solo equipo:

- **TAK Server**: instalación desde el paquete `.deb` oficial, con autoridad certificadora propia, enrolamiento y paquetes de conexión para ATAK e iTAK.
- **MediaMTX**: video en vivo (RTSP, RTMP, SRT, HLS, WebRTC), por defecto sin usuario ni contraseña para publicar ni para ver (se puede exigir autenticación).
- **Mumble**: voz por canales, compatible con el plugin ATAK Vx, Mumla y el cliente Mumble.
- **ZeroTier local**: controlador propio con la interfaz web ZTNET, raíces públicas o raíz privada (planet) a elección.

Una clonación, una contraseña, una URL. La inspiración de diseño es [infra-TAK](https://github.com/takwerx/infra-TAK); este proyecto es una implementación independiente, sin código copiado de él.

> Estado: **v0.1.0, primera versión**. Probada con pruebas automáticas y con los scripts oficiales de certificados de TAK Server; falta validación en un equipo real con el `.deb` de tak.gov. Ver [Limitaciones](#limitaciones-conocidas).

## Requisitos

| Recurso | Mínimo recomendado |
|---|---|
| Sistema operativo | Ubuntu 22.04 LTS (x86-64), instalación limpia |
| Memoria | 8 GB (TAK Server recomienda 8 GB o más) |
| Disco | 40 GB o más, SSD |
| CPU | 4 núcleos |
| Acceso | `root` o `sudo` |
| Paquete | `takserver_X.Y-RELEASE-Z_all.deb` descargado de [tak.gov](https://tak.gov) |

El equipo necesita internet durante la instalación (paquetes de Ubuntu, Docker, PostgreSQL e imágenes de contenedores). Después puede operar en una red aislada, salvo que uses las raíces públicas de ZeroTier.

## Instalación

```bash
sudo apt-get update && sudo apt-get install -y git
git clone https://github.com/johnbastiasroman-creator/TAK-CONSOLE.git
cd TAK-CONSOLE
sudo ./install.sh
```

El instalador:

1. Instala Python, OpenSSL, UFW y Docker (repositorio oficial de Docker).
2. Crea un entorno virtual con dependencias fijas (`requirements.txt`).
3. Pide la contraseña del usuario `admin` de la consola (o la genera con `--random-pass`).
4. Genera un certificado HTTPS autofirmado.
5. Agrega reglas UFW para SSH y la consola **sin activar UFW**: lo activas tú desde *Red y firewall*.
6. Crea y arranca el servicio `tak-console` (gunicorn en `https://<ip>:5001`).

Se puede volver a ejecutar para reparar o actualizar. Para cambiar la contraseña: `sudo scripts/reset-password.sh`. Para actualizar desde git: `sudo scripts/update.sh`.

## Orden de despliegue

```
1. ZeroTier      Controlador + ZTNET. Crea una red y une este servidor: obtienes la IP ZeroTier.
        ↓
2. TAK Server    Sube el .deb, define la CA y el administrador, despliega.
        ↓        Crea usuarios y descarga sus paquetes de conexión con la IP ZeroTier.
3. MediaMTX      Video. Opcional: RTSPS con certificado de la CA de TAK.
   Mumble        Voz. Opcional: certificado firmado por la CA de TAK.
        ↓
4. Red y firewall  Limita los servicios a ZeroTier (y opcionalmente a una LAN) y activa UFW.
```

El orden no es obligatorio, pero cada paso deja listo lo que usa el siguiente: la IP ZeroTier va en los paquetes de conexión, y los certificados de Mumble y MediaMTX se firman con la CA que crea TAK Server.

## Qué hace cada módulo

### TAK Server

Pasos del despliegue (verificados contra los scripts oficiales del repositorio [TAK-Product-Center/Server](https://github.com/TAK-Product-Center/Server)):

1. Comprobaciones (sistema, memoria, disco, puertos 8089/8443/8446 libres).
2. Límites `nofile 32768` en `/etc/security/limits.conf`.
3. Repositorio PGDG de PostgreSQL (el `.deb` de 5.8-RELEASE92 depende de PostgreSQL 18 con PostGIS, que Ubuntu 22.04 no trae).
4. Verificación opcional de la firma con `debsig-verify` (`takserver-public-gpg.key` + `deb_policy.pol`).
5. `apt-get install ./takserver.deb` (trae Java 17 y PostgreSQL).
6. Certificados con `makeRootCa.sh` y `makeCert.sh` como usuario `tak`: CA raíz, CA intermedia, `takserver`, `admin`. Los sujetos se codifican como PrintableString (algunos clientes TAK no aceptan UTF8String), por eso los campos van sin tildes.
7. `CoreConfig.xml`: keystore, truststore de la CA intermedia, contraseñas y, si lo eliges, el bloque `<certificateSigning>` para enrolamiento. Se edita como texto, sin tocar los bloques comentados, y se guarda un respaldo.
8. `systemctl enable --now takserver` y espera a que abra 8089 y 8443.
9. `UserManager.jar certmod -A admin.pem` y `usermod -A -p … <usuario>` para el acceso web en 8446.
10. Reglas de firewall según la política.

Después del despliegue la página ofrece: descarga de `admin.p12`, truststore y CA raíz; creación de certificados de usuario (con grupo TAK opcional); paquetes de conexión `.zip` para ATAK/WinTAK (con `MANIFEST/manifest.xml`) y para iTAK (`config.pref`), con la dirección del servidor a elección; y lectura de los registros de TAK Server.

**Borrar los datos tras desinstalar.** Desinstalar quita el paquete y las reglas de firewall, pero conserva `/opt/tak` (CA, certificados, `CoreConfig.xml`) y la base `cot` de PostgreSQL. Cuando TAK Server ya no está instalado ni en marcha, la página muestra «Datos que dejó TAK Server» con el botón **Borrar datos de TAK Server…**, que pide escribir `BORRAR DATOS` y la contraseña de la consola y entonces:

1. Comprueba que el paquete no está instalado, que `takserver` no está activo y que 8089/8443/8446 están libres.
2. Guarda un respaldo opcional (marcado por defecto) de `certs`, `CoreConfig*.xml*`, `UserAuthenticationFile.xml*`, `TAKIgniteConfig.xml*` y `conf` en `<datos de la consola>/backups/takserver-<fecha>.tar.gz` (modo 0600; contiene llaves privadas; no incluye la base de datos).
3. Ejecuta `DROP DATABASE … WITH (FORCE)` y `DROP ROLE` con el nombre de base y de rol leídos de `CoreConfig.xml` (por defecto `cot` y `martiuser`); se niega si el nombre no es un identificador simple o es `postgres`/`template0`/`template1`.
4. Borra `/opt/tak` (se niega si es un enlace simbólico), opcionalmente el `.deb`, la llave y la política subidos, y restablece el estado del módulo.

No restaura los `pg_hba.conf`/`postgresql.conf` originales de PostgreSQL (TAK Server deja copias `*.backup-<fecha>`), y los certificados que Mumble o MediaMTX firmaron con la CA borrada deben volver a generarse al reinstalar.

El repositorio PGDG (PostgreSQL) se configura con la llave oficial en `/usr/share/postgresql-common/pgdg/apt.postgresql.org.asc`. En cada despliegue la consola comprueba que la llave exista y que apt (usuario `_apt`) pueda leerla, y repara los permisos si hace falta; sin eso apt falla con `NO_PUBKEY` aunque la llave sea correcta.

Si vuelves a ejecutar el despliegue sin subir un `.deb` nuevo, se reconfigura la instalación existente (CoreConfig, administradores, firewall) sin reinstalar. Los certificados solo se regeneran si marcas **Regenerar certificados**.

### MediaMTX

- Imagen `bluenviron/mediamtx:1.21.2` en red de host.
- `mediamtx.yml` completo generado por la consola y validado con `mediamtx --validate-conf` antes de arrancar.
- **Sin usuario ni contraseña por defecto**, tanto para publicar como para ver: la consola configura el usuario `any` de MediaMTX (cualquier usuario, incluso anónimo, sin restricción de IP), igual que la configuración por defecto de MediaMTX. Cualquiera que llegue a los puertos activos puede publicar y ver, así que limita la exposición con el firewall (por ejemplo, solo ZeroTier o la LAN).
- Marcando **Exigir usuario y contraseña** se usan usuarios internos: uno de publicación (publish/read/playback) y uno de lectura (o lectura anónima).
- En ambos modos la API, métricas y pprof solo aceptan conexiones desde el propio equipo.
- Las instalaciones hechas con la versión 0.1.0 conservan sus credenciales hasta que vuelvas a aplicar la configuración.
- Grabación opcional en fMP4 con retención en días.
- RTSPS opcional (8322) con certificado firmado por la CA de TAK.
- Lista de transmisiones activas leída de la API local (`/v3/paths/list`).

### Mumble

- Imagen oficial `mumblevoip/mumble-server:v1.6.870` en red de host, puerto 64738 TCP/UDP.
- Configuración por variables `MUMBLE_CONFIG_*` desde un `.env` con permisos 600; contraseña de SuperUser con `MUMBLE_SUPERUSER_PASSWORD`.
- Contraseña de servidor opcional, nombre del canal raíz, mensaje de bienvenida y límite de usuarios.
- Certificado opcional firmado por la CA de TAK, para que los equipos que ya confían en esa CA validen también la voz.
- Clientes: [ATAK Plugin: Vx](https://play.google.com/store/apps/details?id=com.atakmap.android.gbr.vx.plugin) (TAK Product Center; funciona con servidores Mumble/Murmur o en multicast), [Mumla](https://f-droid.org/packages/se.lublin.mumla) en Android y Mumble de escritorio.

### ZeroTier local

| Componente | Imagen | Rol |
|---|---|---|
| zerotier | `zyclonite/zerotier:1.14.2` | Nodo y controlador, red de host (crea las interfaces `zt*` en el equipo) |
| ztnet | `sinamics/ztnet:0.8.5` | Interfaz web del controlador, escucha solo en 127.0.0.1:3000 |
| postgres | `postgres:15-alpine` | Base de datos de ZTNET, publicada solo en 127.0.0.1:5434 |
| https | `caddy:2.11.7` | HTTPS para ZTNET en `:3443` con el certificado de la consola |

Desde la consola puedes unir este servidor a una red (y autorizarlo automáticamente si la red es de este controlador), salir de redes, ver las raíces activas, aplicar un planet propio o volver a las raíces públicas.

Ver [docs/ZEROTIER.md](docs/ZEROTIER.md) para los modos de raíz y la nota de licencia.

## Consolas de estado y actividad

Cada módulo instalado muestra al final de su página el panel **Estado y actividad**: una barra de comprobaciones (contenedor o servicio, puertos, API) y tres consolas que se actualizan solas (cada 3 s; 5 s en la tercera) y se pueden pausar:

1. **Eventos clave**: el registro con los eventos resaltados y una etiqueta (CONEXIÓN, PUBLICA, AUTH FALLIDA…), contadores por tipo y la opción «Mostrar solo eventos clave». Los avisos y errores siempre se resaltan.
2. **Registro en vivo**: las últimas 300 líneas tal cual, solo coloreadas por nivel.
3. **Registro + conectados**: una tabla de quién está conectado ahora y, debajo, las últimas líneas.

| Servicio | Registro | Eventos reconocidos | Conectados |
|---|---|---|---|
| MediaMTX | `docker logs` | conexiones, publica/lee, stream activo, clave rechazada (formato de MediaMTX 1.21.2) | API local: sesiones RTSP/RTSPS, conexiones RTMP/RTMPS/SRT, sesiones WebRTC/HLS |
| Mumble | `docker logs` | conexión, autenticado, desconexión, rechazo, expulsión, cambio de canal (servidor 1.6.870) | **Estimado** desde el registro; se contrasta con las conexiones TCP abiertas (`ss`) |
| TAK Server | `/opt/tak/logs` (mensajería o API) | avisos y errores, más pocos eventos sin lista oficial | API REST en 127.0.0.1:8443 con el certificado `admin` (`/Marti/api/subscriptions/all`) |
| ZeroTier | contenedores del nodo, ZTNET, Caddy y base de datos | solo avisos y errores | pares `LEAF` de `zerotier-cli listpeers` |

Los valores que parecen contraseñas o tokens (`pass=…`, `token=…`) se enmascaran antes de salir del servidor y la interfaz solo escribe texto, nunca HTML. Estas consolas no sustituyen a una auditoría: el registro de Docker rota y Mumble no ofrece una lista de usuarios sin activar su interfaz ICE.

## Puertos

| Puerto | Servicio | Exposición |
|---|---|---|
| 22/tcp | SSH | Siempre abierto |
| 5001/tcp | Consola TAK-CONSOLE (HTTPS) | Siempre abierto |
| 9993/udp | ZeroTier transporte | Siempre abierto |
| 3443/tcp | ZTNET (HTTPS) | Según política |
| 8089/tcp | TAK Server, clientes TLS | Según política |
| 8443/tcp | TAK Server, administración con certificado | Según política |
| 8446/tcp | TAK Server, usuario/contraseña y enrolamiento | Según política |
| 8554/tcp, 8000-8001/udp | MediaMTX RTSP | Según política (si está activo) |
| 8322/tcp | MediaMTX RTSPS | Según política (si está activo) |
| 1935/tcp | MediaMTX RTMP | Según política (si está activo) |
| 8890/udp | MediaMTX SRT | Según política (si está activo) |
| 8888/tcp | MediaMTX HLS | Según política (si está activo) |
| 8889/tcp, 8189/udp | MediaMTX WebRTC | Según política (si está activo) |
| 64738/tcp+udp | Mumble | Según política |
| 127.0.0.1 | 3000 (ZTNET), 5434 (PostgreSQL de ZTNET), 9993/tcp (API ZeroTier), 9997 (API MediaMTX) | Solo local |

**Políticas de exposición** (página *Red y firewall*): todas las interfaces, solo ZeroTier, o ZeroTier más una red local en CIDR. Cada regla UFW de la consola lleva el comentario `tak-console:<servicio>`; las tuyas no se tocan.

Docker publica puertos saltándose UFW. Por eso todos los contenedores usan `network_mode: host` o publican solo en `127.0.0.1`, y una prueba automática lo verifica.

## Seguridad

- Toda ruta exige sesión iniciada; no es posible registrar una ruta sin autenticación. Todo POST exige token CSRF.
- Bloqueo de 5 minutos tras 5 intentos fallidos por IP. Sesión inactiva caduca a los 30 minutos.
- Cabeceras CSP estrictas (sin scripts ni estilos en línea), `X-Frame-Options: DENY`.
- Los comandos se ejecutan como listas de argumentos, nunca a través de una shell; los valores que llegan a archivos de configuración, certificados o comandos se validan con listas blancas de caracteres.
- Las contraseñas se ocultan en los registros de tareas. La clave de la CA de TAK se pasa a OpenSSL por variable de entorno, no por línea de comandos.
- El estado (`data/`) tiene permisos 700/600 y queda fuera de git.
- La consola corre como `root` en esta versión: es lo que necesita para apt, systemd, UFW y Docker. Expónla solo en redes de confianza (ver *Limitaciones*).

## Estructura

```
install.sh              instalador idempotente para Ubuntu 22.04
gunicorn.conf.py        un proceso, 8 hilos, HTTPS en :5001
wsgi.py
takconsole/
  __init__.py           aplicación Flask: login, CSRF, rutas genéricas de módulos
  config.py             rutas y constantes
  cli.py                set-password, console-cert
  core/                 settings (JSON), jobs (tareas en segundo plano), shell, firewall,
                        docker, certs, system, validate, auth
  modules/              un archivo por servicio: zerotier, takserver, mediamtx, mumble
  templates/            páginas (Jinja2)
  static/               CSS, JS y fuentes Barlow (OFL) servidas localmente
scripts/                reset-password.sh, update.sh
tests/                  pytest
data/                   estado del equipo (se crea al instalar, ignorado por git)
```

Cómo agregar un módulo: [docs/ARQUITECTURA.md](docs/ARQUITECTURA.md).

## Desarrollo y pruebas

```bash
python3 -m venv .venv && . .venv/bin/activate
pip install -r requirements.txt pytest
python -m pytest -q
# Valida también la configuración de MediaMTX contra el binario real:
MEDIAMTX_BIN=/ruta/a/mediamtx python -m pytest -q
```

Las pruebas corren en modo `TAKCONSOLE_DRY_RUN=1` (no ejecutan comandos privilegiados) y cubren: edición de `CoreConfig.xml` y `cert-metadata.sh`, paquetes de conexión, reglas de firewall por política, validaciones, login/CSRF/limitación de intentos, archivos `compose.yaml` y `.env`.

Para probar la interfaz en tu equipo sin instalar nada:

```bash
export TAKCONSOLE_DATA_DIR=/tmp/tak-console-dev
python -m takconsole.cli set-password
python -m takconsole.cli console-cert          # usa openssl
TAKCONSOLE_DRY_RUN=1 TAKCONSOLE_PORT=5099 gunicorn -c gunicorn.conf.py wsgi:app   # https://127.0.0.1:5099
```

## Limitaciones conocidas

- **Consolas de actividad sin probar en un servidor real.** Los formatos de línea y las rutas de API se tomaron del código fuente de cada proyecto (MediaMTX 1.21.2, Mumble 1.6.870 y el código público de TAK Server, 5.7; tu versión puede diferir) y se probaron con datos de ejemplo. La tabla de TAK Server depende de que `/Marti/api/subscriptions/all` responda con el certificado `admin`; si falla, la consola lo indica en lugar de inventar datos.

- **Sin prueba de extremo a extremo con TAK Server real.** El flujo de certificados se probó con los scripts oficiales `makeRootCa.sh`/`makeCert.sh`, y el `CoreConfig.xml` resultante contra el esquema `CoreConfig.xsd` oficial; la instalación del `.deb`, el arranque del servicio y UserManager deben validarse en tu servidor.
- **Paquetes de conexión**: siguen el formato usado por otros proyectos abiertos (manifest + `server.pref` + truststore + `.p12`). Pruébalos con tu versión de ATAK/iTAK.
- **Enrolamiento por QR** (`tak://com.atakmap.app/enroll`) no está incluido: ATAK exige un certificado de servidor de confianza pública en 8446, que no aplica a una red solo ZeroTier.
- **Solo instalación nativa (.deb)** de TAK Server. La variante Docker (`takserver-docker-*.zip`) queda para una versión futura.
- **Mumble** no integra todavía usuarios de TAK (autenticación vía ICE) ni crea canales por grupo.
- **La consola corre como root.** Un proceso sin privilegios con un intermediario de comandos permitidos está en la hoja de ruta.
- **Solo Ubuntu 22.04 x86-64** probado.

## Licencia

Apache License 2.0. Ver [LICENSE](LICENSE) y [NOTICE](NOTICE) para los componentes de terceros que la consola descarga y ejecuta (cada uno conserva su propia licencia).

TAK, ATAK, iTAK y WinTAK son marcas de sus respectivos titulares. Este proyecto no está afiliado al TAK Product Center, a ZeroTier, Inc. ni a TAKWERX.
