# SPDX-License-Identifier: Apache-2.0
"""Ejecución de comandos del sistema.

Reglas:
  * Siempre listas de argumentos (argv), nunca cadenas con shell=True.
  * La salida se transmite línea a línea al registro de la tarea.
  * Los secretos se ocultan antes de escribirse en el registro.
"""
import os
import shutil
import subprocess
import threading
from dataclasses import dataclass

from .. import config


class CommandError(RuntimeError):
    def __init__(self, argv, returncode, output):
        self.argv = argv
        self.returncode = returncode
        self.output = output
        name = os.path.basename(str(argv[0])) if argv else "?"
        super().__init__(f"'{name}' terminó con código {returncode}")


@dataclass
class Result:
    returncode: int
    output: str

    @property
    def ok(self):
        return self.returncode == 0


def redact(text: str, secrets) -> str:
    for s in secrets or ():
        if s and len(str(s)) >= 3:
            text = text.replace(str(s), "******")
    return text


def which(name: str):
    return shutil.which(name)


def run(argv, *, input=None, env=None, cwd=None, timeout=900, check=True,
        log=None, secrets=(), quiet=False):
    """Ejecuta argv. `log` recibe cada línea (ya redactada) salvo quiet=True."""
    argv = [str(a) for a in argv]
    shown = redact(" ".join(argv), secrets)
    if log and not quiet:
        log(f"$ {shown}")
    if config.DRY_RUN:
        return Result(0, "")

    full_env = os.environ.copy()
    full_env.setdefault("LC_ALL", "C.UTF-8")
    if env:
        full_env.update({k: str(v) for k, v in env.items()})

    try:
        proc = subprocess.Popen(
            argv, cwd=cwd, env=full_env,
            stdin=subprocess.PIPE if input is not None else subprocess.DEVNULL,
            stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
        )
    except FileNotFoundError:
        if check:
            raise CommandError(argv, 127, f"no se encontró el comando {argv[0]}")
        return Result(127, "")

    killed = {"v": False}

    def _kill():
        killed["v"] = True
        try:
            proc.kill()
        except OSError:
            pass

    timer = threading.Timer(timeout, _kill) if timeout else None
    if timer:
        timer.daemon = True
        timer.start()
    if input is not None:
        try:
            proc.stdin.write(input.encode() if isinstance(input, str) else input)
            proc.stdin.close()
        except (BrokenPipeError, OSError):
            pass

    lines = []
    for raw in iter(proc.stdout.readline, b""):
        line = redact(raw.decode("utf-8", errors="replace").rstrip("\n"), secrets)
        lines.append(line)
        if log and not quiet and line.strip():
            log("  " + line)
    proc.stdout.close()
    rc = proc.wait()
    if timer:
        timer.cancel()
    out = "\n".join(lines)
    if killed["v"]:
        out += f"\n(tiempo agotado tras {timeout}s)"
        rc = rc if rc else -9
    if check and rc != 0:
        raise CommandError(argv, rc, out)
    return Result(rc, out)


def capture(argv, timeout=15, env=None, merge=False):
    """Lectura rápida (sondas de estado). Nunca lanza excepción.

    merge=True junta stdout y stderr (p. ej. `docker logs`)."""
    if config.DRY_RUN:
        return Result(1, "")
    try:
        cp = subprocess.run(
            [str(a) for a in argv], timeout=timeout,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT if merge else subprocess.PIPE,
            env={**os.environ, "LC_ALL": "C.UTF-8", **(env or {})},
        )
        out = (cp.stdout or b"").decode("utf-8", errors="replace")
        if cp.returncode != 0 and not merge:
            out += (cp.stderr or b"").decode("utf-8", errors="replace")
        return Result(cp.returncode, out)
    except (OSError, subprocess.SubprocessError):
        return Result(1, "")
