// SPDX-License-Identifier: Apache-2.0
// Consola: formularios asíncronos, registro de tareas en vivo y estado de servicios.
(function () {
  "use strict";
  const csrf = document.querySelector('meta[name="csrf-token"]')?.content || "";
  const $ = (sel, root = document) => root.querySelector(sel);
  const $$ = (sel, root = document) => Array.from(root.querySelectorAll(sel));

  async function post(url, body) {
    const resp = await fetch(url, {
      method: "POST", body: body || new FormData(),
      headers: { "X-CSRF-Token": csrf }, credentials: "same-origin",
    });
    let data = {};
    try { data = await resp.json(); } catch (e) { data = { ok: false, error: "Respuesta inválida del servidor" }; }
    if (resp.status === 401) { location.href = "/login?next=" + encodeURIComponent(location.pathname); }
    return { status: resp.status, data };
  }

  function clearErrors(form) {
    $$(".field.invalid", form).forEach((f) => f.classList.remove("invalid"));
    $$(".form-error, .form-ok", form).forEach((e) => e.remove());
  }

  function showErrors(form, data) {
    let first = null;
    Object.entries(data.errors || {}).forEach(([name, msg]) => {
      const field = form.querySelector(`[data-field="${name}"]`) || document.querySelector(`[data-field="${name}"]`);
      if (field) {
        field.classList.add("invalid");
        const err = $(".err", field);
        if (err) err.textContent = msg;
        first = first || field;
      }
    });
    if (data.error) {
      const n = document.createElement("div");
      n.className = "note bad form-error";
      n.setAttribute("role", "alert");
      n.textContent = data.error;
      (form.querySelector(".formfoot") || form).insertAdjacentElement("beforebegin", n);
      first = first || n;
    }
    if (first) first.scrollIntoView({ behavior: "smooth", block: "center" });
  }

  function busy(btn, on) {
    if (!btn) return;
    btn.disabled = on;
    btn.classList.toggle("busy", on);
  }

  // ── Registro de tareas ────────────────────────────────────────────────────
  const consoleEl = $("[data-job]");
  let jobOffset = 0, sawRunning = false, polling = false, reloadOnFinish = false;

  function classify(line) {
    if (/\[\d+\/\d+\]/.test(line)) return "s";
    if (line.includes("✓")) return "y";
    if (line.includes("⚠")) return "w";
    if (line.includes("✗")) return "x";
    if (/^\d\d:\d\d:\d\d {2}\$ /.test(line)) return "c";
    return "";
  }

  function renderJob(job) {
    const pre = $("pre", consoleEl);
    const head = $("header", consoleEl);
    if (jobOffset === 0) pre.textContent = "";
    consoleEl.classList.remove("idle");
    const frag = document.createDocumentFragment();
    job.lines.forEach((line) => {
      const span = document.createElement("span");
      const c = classify(line);
      if (c) span.className = c;
      span.textContent = line + "\n";
      frag.appendChild(span);
    });
    const atBottom = pre.scrollHeight - pre.scrollTop - pre.clientHeight < 40;
    pre.appendChild(frag);
    if (atBottom || jobOffset === 0) pre.scrollTop = pre.scrollHeight;
    jobOffset = job.next;
    $(".title", head).textContent = job.title;
    const led = $(".led", head);
    led.className = "led " + (job.status === "running" ? "warn" : job.status === "ok" ? "ok" : "err");
  }

  async function pollJob() {
    if (!consoleEl || polling) return;
    polling = true;
    const key = consoleEl.dataset.job;
    try {
      while (true) {
        const r = await fetch(`/api/jobs/${key}?offset=${jobOffset}`, { credentials: "same-origin" });
        if (r.status === 401) { location.href = "/login"; return; }
        const data = await r.json();
        if (!data.job) break;
        renderJob(data.job);
        if (data.job.status === "running") { sawRunning = true; await new Promise((res) => setTimeout(res, 1200)); continue; }
        if (sawRunning && (reloadOnFinish || data.job.status === "ok")) {
          setTimeout(() => location.reload(), 1500);
        }
        break;
      }
    } catch (e) { /* red intermitente: se reintenta en el próximo envío */ }
    polling = false;
  }

  function startedJob(reload) {
    reloadOnFinish = reloadOnFinish || !!reload;
    sawRunning = true;
    jobOffset = 0;
    if (consoleEl) {
      consoleEl.scrollIntoView({ behavior: "smooth", block: "nearest" });
      setTimeout(pollJob, 300);
    } else if (reload) {
      setTimeout(() => location.reload(), 1500);
    }
  }

  if (consoleEl) pollJob();

  // ── Formularios ───────────────────────────────────────────────────────────
  $$("form[data-api]").forEach((form) => {
    form.addEventListener("submit", async (ev) => {
      ev.preventDefault();
      if (form.dataset.confirm && !window.confirm(form.dataset.confirm)) return;
      clearErrors(form);
      const btn = form.querySelector('[type="submit"]');
      busy(btn, true);
      const { data } = await post(form.dataset.api, new FormData(form));
      busy(btn, false);
      if (!data.ok) { showErrors(form, data); return; }
      if (form.hasAttribute("data-close")) form.closest("dialog")?.close();
      $$('input[type="password"]', form).forEach((i) => (i.value = ""));
      if (form.dataset.success) {
        const ok = document.createElement("div");
        ok.className = "note form-ok";
        ok.setAttribute("role", "status");
        ok.textContent = form.dataset.success;
        (form.querySelector(".formfoot") || form).insertAdjacentElement("beforebegin", ok);
      }
      startedJob(form.hasAttribute("data-reload"));
    });
  });

  $$("form[data-upload]").forEach((form) => {
    form.addEventListener("submit", (ev) => {
      ev.preventDefault();
      clearErrors(form);
      const fd = new FormData(form);
      const hasFile = Array.from(fd.values()).some((v) => v instanceof File && v.size > 0);
      if (!hasFile) { showErrors(form, { error: "Selecciona un archivo" }); return; }
      const prog = $(".progress", form), bar = $("progress", form), btn = form.querySelector('[type="submit"]');
      const status = $("[data-upload-status]", form);
      prog?.classList.add("on");
      busy(btn, true);
      const xhr = new XMLHttpRequest();
      xhr.open("POST", form.dataset.upload);
      xhr.setRequestHeader("X-CSRF-Token", csrf);
      xhr.upload.onprogress = (e) => {
        if (e.lengthComputable && bar) bar.value = Math.round((e.loaded / e.total) * 100);
        if (status && e.lengthComputable) status.textContent = `Subiendo… ${Math.round(e.loaded / 1048576)} de ${Math.round(e.total / 1048576)} MB`;
      };
      xhr.onload = () => {
        busy(btn, false);
        let data = {};
        try { data = JSON.parse(xhr.responseText); } catch (e) { data = { ok: false, error: "Error al subir (" + xhr.status + ")" }; }
        if (!data.ok) { prog?.classList.remove("on"); showErrors(form, data); return; }
        if (data.saved && status) {
          status.textContent = "Recibido: " + Object.values(data.saved).join(", ") + (data.version ? ` (versión ${data.version})` : "");
          form.classList.add("ready");
        }
        if (form.hasAttribute("data-reload")) startedJob(true);
      };
      xhr.onerror = () => { busy(btn, false); showErrors(form, { error: "Se perdió la conexión durante la subida" }); };
      xhr.send(fd);
    });
  });

  // ── Botones de acción ─────────────────────────────────────────────────────
  $$("[data-action]").forEach((btn) => {
    btn.addEventListener("click", async () => {
      if (btn.dataset.confirm && !window.confirm(btn.dataset.confirm)) return;
      busy(btn, true);
      const { data } = await post(btn.dataset.action);
      busy(btn, false);
      if (!data.ok) { window.alert(data.error || "No se pudo ejecutar la acción"); return; }
      startedJob(true);
    });
  });

  $$("[data-logs]").forEach((btn) => {
    btn.addEventListener("click", async () => {
      const target = document.getElementById(btn.dataset.target);
      busy(btn, true);
      try {
        const r = await fetch(btn.dataset.logs, { credentials: "same-origin" });
        const data = await r.json();
        target.textContent = data.text || "(vacío)";
      } catch (e) { target.textContent = "No se pudo leer el registro"; }
      busy(btn, false);
      target.hidden = false;
      target.scrollTop = target.scrollHeight;
    });
  });

  $$("[data-copy]").forEach((btn) => {
    btn.addEventListener("click", async () => {
      const code = btn.parentElement.querySelector("code");
      try { await navigator.clipboard.writeText(code.textContent.trim()); btn.textContent = "Copiado"; }
      catch (e) {
        const range = document.createRange(); range.selectNodeContents(code);
        const sel = window.getSelection(); sel.removeAllRanges(); sel.addRange(range);
        btn.textContent = "Seleccionado";
      }
      setTimeout(() => (btn.textContent = "Copiar"), 1600);
    });
  });

  $$("[data-toggle]").forEach((a) => a.addEventListener("click", (ev) => {
    ev.preventDefault();
    const row = document.getElementById(a.dataset.toggle);
    if (row) row.hidden = !row.hidden;
  }));
  $$("[data-open]").forEach((btn) => btn.addEventListener("click", () => document.getElementById(btn.dataset.open)?.showModal()));
  $$("[data-dismiss]").forEach((btn) => btn.addEventListener("click", () => btn.closest("dialog")?.close()));

  // ── Paquetes de conexión TAK ──────────────────────────────────────────────
  const hostSel = $("[data-pkg-host]");
  const custom = $("[data-pkg-custom]");
  if (hostSel && custom) {
    const sync = () => (custom.hidden = hostSel.value !== "");
    hostSel.addEventListener("change", sync);
    sync();
  }
  $$("[data-pkg-user]").forEach((a) => {
    a.addEventListener("click", (ev) => {
      ev.preventDefault();
      const host = hostSel && hostSel.value ? hostSel.value : ($("input", custom || document)?.value || "").trim();
      if (!/^[A-Za-z0-9.\-:]{1,253}$/.test(host)) { window.alert("Indica una dirección de servidor válida"); return; }
      location.href = `/m/takserver/package/${encodeURIComponent(a.dataset.pkgUser)}?host=${encodeURIComponent(host)}&kind=${a.dataset.kind}`;
    });
  });

  // ── Transmisiones de MediaMTX ─────────────────────────────────────────────
  const paths = $("[data-mtx-paths] tbody");
  async function loadPaths() {
    try {
      const r = await fetch("/api/m/mediamtx/paths", { credentials: "same-origin" });
      const data = await r.json();
      paths.textContent = "";
      if (!data.ok) { paths.innerHTML = '<tr><td colspan="4" class="muted">La API de MediaMTX no responde.</td></tr>'; return; }
      if (!data.items.length) { paths.innerHTML = '<tr><td colspan="4" class="muted">No hay transmisiones en este momento.</td></tr>'; return; }
      data.items.forEach((it) => {
        const tr = document.createElement("tr");
        [it.name, it.source || "—", (it.tracks || []).join(", ") || "—", String(it.readers)].forEach((v, i) => {
          const td = document.createElement("td"); td.textContent = v; if (i === 0) td.className = "mono"; tr.appendChild(td);
        });
        paths.appendChild(tr);
      });
    } catch (e) { /* sin red */ }
  }
  if (paths) { loadPaths(); setInterval(loadPaths, 5000); }

  // ── Lámparas de estado ────────────────────────────────────────────────────
  async function refreshStatus() {
    try {
      const r = await fetch("/api/status", { credentials: "same-origin" });
      if (!r.ok) return;
      const data = await r.json();
      Object.entries(data.modules || {}).forEach(([key, s]) => {
        $$(`[data-led="${key}"]`).forEach((l) => (l.className = "led " + s.level));
        const row = $(`[data-status="${key}"]`);
        if (row) {
          const led = $(".led", row); if (led) led.className = "led big " + s.level;
          const lbl = $("[data-state-label]", row); if (lbl) lbl.textContent = s.label + (s.version ? `, ${s.version}` : "");
        }
      });
    } catch (e) { /* sin red */ }
  }
  if ($("[data-led]")) { refreshStatus(); setInterval(refreshStatus, 10000); }
  // ── Consolas de estado y actividad (/api/m/<servicio>/monitor) ────────────
  const monEl = $("[data-monitor]");
  if (monEl) {
    const key = monEl.dataset.monitor;
    const pre = $("[data-mon-pre]", monEl);
    const sel = $("[data-mon-source]", monEl);
    const pauseBtn = $("[data-mon-pause]", monEl);
    const onlyBox = $("[data-mon-onlyev]", monEl);
    const m = { view: "events", source: "", paused: false, timer: null, busy: false, sig: "", srcSig: "" };

    const el = (tag, cls, text) => {
      const n = document.createElement(tag);
      if (cls) n.className = cls;
      if (text !== undefined) n.textContent = text;   // nunca innerHTML: los registros los escriben terceros
      return n;
    };

    function renderChecks(checks) {
      const box = $("[data-mon-checks]", monEl);
      box.textContent = "";
      (checks || []).forEach((c) => {
        const r = el("span", "readout");
        r.appendChild(el("span", "dot" + (c.ok ? " up" : "")));
        r.appendChild(document.createTextNode(c.label + " "));
        r.appendChild(el("b", "", c.detail || ""));
        box.appendChild(r);
      });
    }

    function renderSources(list, current) {
      const sig = JSON.stringify(list);
      if (sig === m.srcSig) return;
      m.srcSig = sig;
      sel.textContent = "";
      list.forEach((s) => { const o = el("option", "", s.label); o.value = s.id; sel.appendChild(o); });
      sel.value = current;
      sel.hidden = list.length < 2;
    }

    function renderLines(lines) {
      const onlyEv = m.view === "events" && onlyBox.checked;
      const shown = lines.filter((l) => !onlyEv || l.event);
      const small = m.view === "clients";
      const slice = small ? shown.slice(-60) : shown;
      const sig = m.view + "|" + onlyEv + "|" + JSON.stringify(slice);
      if (sig === m.sig) return;
      m.sig = sig;
      const atBottom = pre.scrollHeight - pre.scrollTop - pre.clientHeight < 40;
      const frag = document.createDocumentFragment();
      slice.forEach((l) => {
        const cls = ["ln"];
        if (m.view === "raw") { if (l.level !== "info") cls.push("lv-" + l.level); }
        else if (l.event) cls.push("ev-" + l.event.kind);
        else cls.push("dim");
        const row = el("div", cls.join(" "));
        if (m.view !== "raw" && l.event) row.appendChild(el("span", "tag", l.event.tag));
        row.appendChild(document.createTextNode(l.text));
        frag.appendChild(row);
      });
      if (!slice.length) frag.appendChild(el("div", "ln dim", onlyEv ? "Sin eventos clave en las últimas líneas." : "Sin líneas de registro todavía."));
      pre.textContent = "";
      pre.appendChild(frag);
      if (atBottom || pre.scrollTop === 0) pre.scrollTop = pre.scrollHeight;
    }

    function renderChips(lines) {
      const box = $("[data-mon-chips]", monEl);
      const count = {};
      lines.forEach((l) => { if (l.event) count[l.event.tag] = (count[l.event.tag] || 0) + 1; });
      box.textContent = "";
      Object.entries(count).sort((a, b) => b[1] - a[1]).forEach(([tag, n]) => box.appendChild(el("span", "", `${tag} ${n}`)));
      box.hidden = m.view !== "events" || !Object.keys(count).length;
    }

    function renderClients(c) {
      const wrap = $("[data-mon-clients]", monEl);
      const show = m.view === "clients" && c;
      wrap.hidden = !show;
      if (!show) return;
      $("[data-mon-cnote]", monEl).textContent = c.note || "";
      const err = $("[data-mon-cerr]", monEl);
      err.hidden = !c.error;
      err.textContent = c.error || "";
      const head = $("thead", wrap), body = $("tbody", wrap);
      head.textContent = ""; body.textContent = "";
      if (c.columns.length) {
        const tr = el("tr");
        c.columns.forEach((h) => tr.appendChild(el("th", "", h)));
        head.appendChild(tr);
      }
      c.rows.forEach((r) => { const tr = el("tr"); r.forEach((v) => tr.appendChild(el("td", "", v))); body.appendChild(tr); });
      if (!c.rows.length && !c.error) {
        const tr = el("tr", "none"); const td = el("td", "", "Nadie conectado ahora mismo."); td.colSpan = Math.max(1, c.columns.length); tr.appendChild(td); body.appendChild(tr);
      }
      if (c.total > c.rows.length) body.appendChild(el("tr", "none")).appendChild(el("td", "", `Se muestran ${c.rows.length} de ${c.total}.`));
    }

    function render(d) {
      $("[data-mon-led]", monEl).className = "led " + (d.level || "off");
      $("[data-mon-label]", monEl).textContent = d.label || "";
      renderChecks(d.checks);
      renderSources(d.sources || [], d.source || "");
      const note = $("[data-mon-note]", monEl);
      note.textContent = m.view === "events" ? (d.events_note || "") : "";
      $("[data-mon-only]", monEl).hidden = m.view !== "events";
      pre.parentElement.classList.toggle("small", m.view === "clients");
      renderChips(d.lines || []);
      renderLines(d.lines || []);
      renderClients(d.clients);
      const foot = $("[data-mon-foot]", monEl);
      foot.textContent = (d.log_error ? d.log_error + " · " : "") + "Actualizado " + new Date().toLocaleTimeString() + (m.paused ? " (en pausa)" : " · cada " + interval() / 1000 + " s");
    }

    const interval = () => (m.view === "clients" ? 5000 : 3000);

    async function tick() {
      if (m.busy || m.paused || document.hidden) return;
      m.busy = true;
      const view = m.view;
      try {
        const q = new URLSearchParams({ view, source: m.source });
        const r = await fetch(`/api/m/${key}/monitor?${q}`, { credentials: "same-origin", cache: "no-store" });
        if (r.status === 401) { location.href = "/login?next=" + encodeURIComponent(location.pathname); return; }
        const d = await r.json();
        if (view === m.view && d.ok) { if (!m.source) m.source = d.source || ""; render(d); }
      } catch (e) {
        $("[data-mon-foot]", monEl).textContent = "Sin respuesta de la consola; reintentando…";
      } finally { m.busy = false; }
    }

    function schedule() {
      clearInterval(m.timer);
      m.timer = setInterval(tick, interval());
    }

    $$("[data-mon-view]", monEl).forEach((b) => b.addEventListener("click", () => {
      m.view = b.dataset.monView;
      $$("[data-mon-view]", monEl).forEach((x) => x.setAttribute("aria-selected", String(x === b)));
      m.sig = "";
      schedule(); tick();
    }));
    sel.addEventListener("change", () => { m.source = sel.value; m.sig = ""; tick(); });
    onlyBox.addEventListener("change", () => { m.sig = ""; tick(); });
    pauseBtn.addEventListener("click", () => {
      m.paused = !m.paused;
      pauseBtn.textContent = m.paused ? "Reanudar" : "Pausar";
      pauseBtn.setAttribute("aria-pressed", String(m.paused));
      if (!m.paused) tick();
    });
    document.addEventListener("visibilitychange", () => { if (!document.hidden) tick(); });
    schedule(); tick();
  }
})();
