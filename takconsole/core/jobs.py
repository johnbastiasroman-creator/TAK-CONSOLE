# SPDX-License-Identifier: Apache-2.0
"""Tareas en segundo plano con registro en vivo.

Solo se ejecuta una tarea a la vez en todo el equipo: los despliegues usan apt,
docker y el firewall, y dos a la vez se pisarían (bloqueo de dpkg, reglas UFW).
"""
import threading
import time
import traceback
from datetime import datetime

from .. import config
from .shell import CommandError


class Busy(RuntimeError):
    pass


class JobFailed(RuntimeError):
    """Error controlado: se muestra al operador sin traza."""


class Job:
    def __init__(self, key, title):
        self.key = key
        self.title = title
        self.started = time.time()
        self.finished = None
        self.status = "running"  # running | ok | error
        self.lines = []
        self.result = None
        stamp = datetime.now().strftime("%Y%m%d-%H%M%S")
        config.LOG_DIR.mkdir(parents=True, exist_ok=True)
        self.log_path = config.LOG_DIR / f"{key}-{stamp}.log"
        self._fh = open(self.log_path, "a", encoding="utf-8")
        self._lock = threading.Lock()

    # ── registro ────────────────────────────────────────────────────────────
    def log(self, msg=""):
        line = f"{datetime.now().strftime('%H:%M:%S')}  {msg}"
        with self._lock:
            self.lines.append(line)
            if len(self.lines) > 20000:
                self.lines = self.lines[-15000:]
            try:
                self._fh.write(line + "\n")
                self._fh.flush()
            except OSError:
                pass

    def step(self, n, total, title):
        self.log("")
        self.log(f"[{n}/{total}] {title}")

    def ok(self, msg):
        self.log(f"✓ {msg}")

    def warn(self, msg):
        self.log(f"⚠ {msg}")

    def close(self):
        try:
            self._fh.close()
        except OSError:
            pass

    def snapshot(self, offset=0):
        with self._lock:
            total = len(self.lines)
            start = max(0, min(offset, total))
            return {
                "key": self.key,
                "title": self.title,
                "status": self.status,
                "started": self.started,
                "finished": self.finished,
                "lines": self.lines[start:],
                "next": total,
                "result": self.result,
            }


class JobManager:
    def __init__(self):
        self._lock = threading.Lock()
        self._current = None
        self._last = {}  # key -> Job

    def current(self):
        return self._current

    def busy(self):
        return self._current is not None

    def get(self, key):
        return self._last.get(key)

    def start(self, key, title, fn, *args, **kwargs):
        with self._lock:
            if self._current is not None:
                raise Busy(f"Hay otra tarea en curso: {self._current.title}")
            job = Job(key, title)
            self._current = job
            self._last[key] = job

        def _runner():
            job.log(f"Inicio: {title}")
            try:
                job.result = fn(job, *args, **kwargs)
                job.status = "ok"
                job.log("")
                job.log("✓ Tarea completada")
            except JobFailed as e:
                job.status = "error"
                job.log("")
                job.log(f"✗ {e}")
            except CommandError as e:
                job.status = "error"
                job.log("")
                job.log(f"✗ {e}")
            except Exception as e:  # noqa: BLE001 - se registra todo
                job.status = "error"
                job.log("")
                job.log(f"✗ Error inesperado: {e}")
                for tl in traceback.format_exc().splitlines():
                    job.log("    " + tl)
            finally:
                job.finished = time.time()
                job.close()
                with self._lock:
                    self._current = None

        t = threading.Thread(target=_runner, name=f"job-{key}", daemon=True)
        t.start()
        return job


JOBS = JobManager()
