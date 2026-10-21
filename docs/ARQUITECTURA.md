# Arquitectura

## Forma del producto

Un solo servicio (`takconsole`), un proceso gunicorn con hilos, una contraseña y un puerto (5001/HTTPS). La consola **orquesta** los servicios pesados; no los ejecuta dentro de su proceso:

```
Navegador ──HTTPS:5001──▶ gunicorn (1 proceso, 8 hilos)
                              │
                              ├─ takconsole/__init__.py   login, CSRF, rutas genéricas
                              ├─ core/jobs.py         una tarea a la vez, registro en vivo
                              └─ modules/*.py         lógica de cada servicio
                                     │
              ┌──────────────────────┼─────────────────────────┐
              ▼                      ▼                         ▼
     apt / systemd / UFW        docker compose            openssl / keytool
     (TAK Server nativo)   (MediaMTX, Mumble, ZeroTier)   (CA de TAK, certificados)
```

- **Sin base de datos.** Todo el estado está en `data/config/settings.json` (600), una sección por módulo.
- **Una tarea a la vez.** Los despliegues usan apt, Docker y UFW; dos simultáneos se pisarían (bloqueo de dpkg, numeración de reglas UFW). `core/jobs.py` lo impide y guarda cada registro en `data/logs/`.
- **Un proceso.** Las tareas y su registro viven en memoria; varios procesos gunicorn no compartirían ese estado.

## Reglas que el código respeta

| Regla | Dónde |
|---|---|
| Comandos como listas de argumentos, nunca `shell=True` | `core/shell.py` |
| Toda ruta requiere sesión; todo POST requiere CSRF | `before_request` en `takconsole/__init__.py` |
| Valores de formularios validados con listas blancas antes de llegar a archivos o comandos | `core/validate.py` |
| Secretos ocultos en los registros | `shell.run(..., secrets=[...])` |
| Contenedores en `network_mode: host` o publicados solo en `127.0.0.1` (Docker se salta UFW) | `compose_data()` de cada módulo + `tests/test_modules.py` |
| Reglas UFW etiquetadas `tak-console:<módulo>` | `core/firewall.py` |
| Imágenes con versión fija, nunca `latest` | constantes `IMAGE` + prueba automática |
| Archivos con secretos en modo 600 | `docker.write_env`, `docker.write_private`, `settings` |

## Cómo agregar un módulo

1. Crea `takconsole/modules/<clave>.py` con una clase que herede de `Module` (`modules/base.py`):

   ```python
   class MiServicio(Module):
       key = "miservicio"
       name = "Mi servicio"
       summary = "Qué hace, en una línea"
       order = 50
       template = "modules/miservicio.html"

       def status(self): ...          # {'installed', 'running', 'level', 'label', 'endpoints'}
       def ports(self): ...           # [{'port': '1234', 'proto': 'tcp', 'label': '...'}]
       def validate_deploy(self, data): ...   # -> (params, errores_por_campo)
       def deploy(self, job, params): ...     # usa job.step / job.ok / job.warn
       def uninstall(self, job, params): ...
       def actions(self): ...         # {'restart': ('Reiniciar', fn(job))}
       def routes(self): ...          # rutas extra; heredan login y CSRF
   ```

2. Regístralo en `takconsole/modules/__init__.py`.
3. Crea `templates/modules/<clave>.html` extendiendo `base.html`; usa los macros de `_macros.html` (`input`, `check`, `job_console`, `control_buttons`, `uninstall_panel`).
4. Los formularios con `data-api="/api/m/<clave>/deploy"` se envían solos por `app.js` y muestran los errores por campo (`data-field`).
5. Agrega pruebas en `tests/`.

La consola genera automáticamente: la página `/m/<clave>`, `POST /api/m/<clave>/deploy`, `/action/<verbo>`, `/uninstall` (pide la contraseña de la consola) y `GET /api/jobs/<clave>` para el registro.

## Archivos en el equipo

```
data/
  config/settings.json    estado y secretos de los módulos (600)
  config/auth.json        hash de la contraseña de la consola (600)
  config/secret_key       clave de sesión de Flask (600)
  certs/console.{crt,key} HTTPS de la consola y de ZTNET
  logs/<módulo>-<fecha>.log
  uploads/takserver/      .deb, llave GPG y política subidos
  stacks/mediamtx/        compose.yaml, config/mediamtx.yml, recordings/
  stacks/mumble/          compose.yaml, mumble.env, data/ (base SQLite, tls/)
  stacks/zerotier/        compose.yaml, ztnet.env, Caddyfile, zerotier-one/ (identidad del controlador), postgres/
/opt/tak/                 TAK Server (lo gestiona el paquete .deb)
```

Respalda `data/` y `/opt/tak/certs/files/`: contienen la identidad del controlador ZeroTier y la CA de TAK. Si se pierden, las redes y los certificados de los clientes dejan de servir.
