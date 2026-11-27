/* Minimal SVG charts for the TunFrame dashboard: line (crosshair), grouped bars,
   heatmap, horizontal bar list. Colors come from CSS custom properties so the
   light and dark themes both apply. Labels from data go through textContent. */
"use strict";
const TF = (() => {
  const NS = "http://www.w3.org/2000/svg";
  const esc = s => String(s ?? "").replace(/[&<>"']/g, c => ({"&":"&amp;","<":"&lt;",">":"&gt;",'"':"&quot;","'":"&#39;"}[c]));
  // ANSI SGR foreground codes -> theme colours (the exfil tools print [!]/[+]/[*] in red/green/blue).
  const ANSI_FG = {30:"var(--muted)", 31:"var(--critical)", 32:"var(--good)", 33:"var(--warning)",
    34:"var(--s1)", 35:"var(--s5)", 36:"var(--s3)", 37:"var(--ink)",
    90:"var(--muted)", 91:"var(--critical)", 92:"var(--good)", 93:"var(--warning)",
    94:"var(--s1)", 95:"var(--s5)", 96:"var(--s3)", 97:"var(--ink)"};
  function ansiToHtml(text) {
    const re = /\x1b\[([0-9;]*)m/g;
    let html = "", last = 0, color = null, bold = false, m;
    const emit = s => {
      if (!s) return;
      const style = (color ? `color:${color};` : "") + (bold ? "font-weight:700;" : "");
      html += style ? `<span style="${style}">${esc(s)}</span>` : esc(s);
    };
    while ((m = re.exec(text))) {
      emit(text.slice(last, m.index));
      last = re.lastIndex;
      for (const code of (m[1] || "0").split(";").map(n => +n || 0)) {
        if (code === 0) { color = null; bold = false; }
        else if (code === 1) bold = true;
        else if (code === 22) bold = false;
        else if (code === 39) color = null;
        else if (ANSI_FG[code] != null) color = ANSI_FG[code];
      }
    }
    emit(text.slice(last));
    return html;
  }
  const series = i => i < 8 ? `var(--s${i + 1})` : "var(--muted)";
  const HEAT = ["#cde2fb","#b7d3f6","#9ec5f4","#86b6ef","#6da7ec","#5598e7","#3987e5","#2a78d6","#256abf","#1c5cab","#184f95","#104281","#0d366b"];

  function fmtBytes(v) {
    v = Number(v || 0);
    for (const unit of ["B","KB","MB","GB"]) {
      if (Math.abs(v) < 1000) return unit === "B" ? `${v.toFixed(0)} B` : `${v.toFixed(1)} ${unit}`;
      v /= 1000;
    }
    return `${v.toFixed(1)} TB`;
  }
  function fmtDuration(seconds) {
    seconds = Math.max(0, Math.round(seconds));
    const h = Math.floor(seconds / 3600), m = Math.floor(seconds % 3600 / 60), s = seconds % 60;
    return h ? `${h}h ${String(m).padStart(2, "0")}m` : m ? `${m}m ${String(s).padStart(2, "0")}s` : `${s}s`;
  }
  function fmtCompact(v) {
    const a = Math.abs(v);
    if (a >= 1e6) return `${+(v / 1e6).toFixed(1)}M`;
    if (a >= 1e4) return `${+(v / 1e3).toFixed(0)}K`;
    if (a >= 100 || Number.isInteger(v)) return `${Math.round(v)}`;
    return `${+v.toFixed(a < 1 ? 2 : 1)}`;
  }
  const fmtClock = d => d.toLocaleTimeString([], {hour:"2-digit", minute:"2-digit", second:"2-digit"});
  const isDark = () => document.documentElement.dataset.theme !== "light";

  function niceTicks(max, count = 4) {
    if (!(max > 0)) return [0, 1];
    const raw = max / count, mag = 10 ** Math.floor(Math.log10(raw));
    const step = [1, 2, 2.5, 5, 10].map(m => m * mag).find(s => s >= raw);
    const ticks = [];
    for (let v = 0; v < max + step * 0.999; v += step) ticks.push(+v.toPrecision(12));
    return ticks;
  }

  // Shared tooltip per chart container.
  function tooltip(el) {
    let tip = el.querySelector(":scope > .tip");
    if (!tip) { tip = document.createElement("div"); tip.className = "tip"; el.appendChild(tip); }
    return {
      show(head, rows, x, y) {
        tip.replaceChildren();
        if (head) { const h = document.createElement("div"); h.className = "tip-head"; h.textContent = head; tip.appendChild(h); }
        for (const r of rows) {
          const row = document.createElement("div"); row.className = "tip-row";
          const name = document.createElement("span");
          if (r.color) { const sw = document.createElement("span"); sw.className = "swatch"; sw.style.background = r.color; name.appendChild(sw); }
          name.appendChild(document.createTextNode(r.name));
          const val = document.createElement("span"); val.className = "mono"; val.textContent = r.value;
          row.append(name, val); tip.appendChild(row);
        }
        tip.style.display = "block";
        const box = el.getBoundingClientRect();
        tip.style.left = `${Math.max(0, Math.min(x + 12, box.width - tip.offsetWidth - 4))}px`;
        tip.style.top = `${Math.max(0, y - tip.offsetHeight - 8)}px`;
      },
      hide() { tip.style.display = "none"; },
    };
  }

  // Group label shortened to the width of its span (≈6.5 px per character); "" if it cannot fit.
  function fitLabel(label, px) {
    const room = Math.floor((px - 6) / 6.5);
    if (label.length <= room) return label;
    return room >= 4 ? `${label.slice(0, room - 1)}…` : "";
  }

  function legend(el, items, always = false) {
    let lg = el.querySelector(":scope > .legend");
    if (items.length < (always ? 1 : 2)) { lg?.remove(); return; }
    if (!lg) { lg = document.createElement("div"); lg.className = "legend"; el.prepend(lg); }
    lg.replaceChildren(...items.map(it => {
      const s = document.createElement("span");
      const sw = document.createElement("span"); sw.className = "swatch"; sw.style.background = it.color;
      s.append(sw, document.createTextNode(it.name));
      return s;
    }));
  }

  function mount(el, svgText) {
    el.querySelector(":scope > svg")?.remove();
    el.insertAdjacentHTML("beforeend", svgText);
    return el.querySelector(":scope > svg");
  }

  function empty(el, text, height = 60) {
    legend(el, []);
    mount(el, `<svg height="${height}" viewBox="0 0 300 ${height}" preserveAspectRatio="xMinYMid meet"><text class="empty" x="0" y="${height / 2}">${esc(text)}</text></svg>`);
  }

  /* Line chart. opts: series [{name, color, points:[{x, y}]}], yMax (fixed), yFmt, height,
     markers [{x}], headFor(x) -> tooltip header. x is a time in ms unless xFmt is given;
     xTickValues sets explicit x ticks, dots draws a marker on every point. */
  function line(el, opts) {
    const all = opts.series.filter(s => s.points.length);
    if (!all.length) return empty(el, opts.emptyText || "No data yet");
    legend(el, opts.series.map(s => ({name: s.name, color: s.color})), opts.alwaysLegend);
    const width = Math.max(el.clientWidth, 260), height = opts.height || 200;
    const pad = {l: 44, r: 10, t: 8, b: 22};
    const xs = all.flatMap(s => s.points.map(p => p.x));
    let x0 = Math.min(...xs), x1 = Math.max(...xs);
    if (x1 === x0) x1 = x0 + 1000;
    const yMaxData = Math.max(0, ...all.flatMap(s => s.points.map(p => p.y ?? 0)));
    const ticks = opts.yMax != null ? niceTicks(opts.yMax, 5) : niceTicks(yMaxData || 1, 4);  // 5: 0.2 steps on [0, 1]
    const yMax = ticks[ticks.length - 1] || 1;
    const pw = width - pad.l - pad.r, ph = height - pad.t - pad.b;
    const X = x => pad.l + (x - x0) / (x1 - x0) * pw, Y = y => pad.t + ph - (y / yMax) * ph;
    const fmt = opts.yFmt || fmtCompact, xf = opts.xFmt || (x => fmtClock(new Date(x)));
    let svg = `<svg viewBox="0 0 ${width} ${height}" height="${height}" role="img" aria-label="${esc(opts.label || "")}">`;
    for (const t of ticks) {
      svg += `<line x1="${pad.l}" x2="${width - pad.r}" y1="${Y(t)}" y2="${Y(t)}" stroke="var(--grid)" stroke-width="1"/>`;
      svg += `<text x="${pad.l - 6}" y="${Y(t) + 4}" text-anchor="end">${esc(fmt(t))}</text>`;
    }
    for (const m of opts.markers || []) {
      if (m.x < x0 || m.x > x1) continue;
      svg += `<line x1="${X(m.x)}" x2="${X(m.x)}" y1="${pad.t}" y2="${pad.t + ph}" stroke="var(--baseline)" stroke-width="1"/>`;
    }
    svg += `<line x1="${pad.l}" x2="${width - pad.r}" y1="${Y(0)}" y2="${Y(0)}" stroke="var(--baseline)" stroke-width="1"/>`;
    const xTicks = Math.max(2, Math.min(6, Math.floor(pw / 110)));
    const tickXs = opts.xTickValues || Array.from({length: xTicks + 1}, (_, i) => x0 + (x1 - x0) * i / xTicks);
    tickXs.forEach((x, i) => {
      const anchor = opts.xTickValues ? "middle" : i === 0 ? "start" : i === tickXs.length - 1 ? "end" : "middle";
      svg += `<text x="${X(x)}" y="${height - 6}" text-anchor="${anchor}">${esc(xf(x))}</text>`;
    });
    const maxPts = Math.max(50, Math.floor(pw / 2));
    for (const s of all) {
      const step = Math.ceil(s.points.length / maxPts);
      const pts = s.points.filter((_, i) => i % step === 0 || i === s.points.length - 1);
      const d = pts.map((p, i) => `${i ? "L" : "M"}${X(p.x).toFixed(1)},${Y(Math.min(p.y ?? 0, yMax)).toFixed(1)}`).join("");
      svg += `<path d="${d}" fill="none" stroke="${s.color}" stroke-width="2" stroke-linejoin="round" stroke-linecap="round"/>`;
      if (opts.dots) svg += pts.map(p => `<circle cx="${X(p.x)}" cy="${Y(Math.min(p.y ?? 0, yMax))}" r="4" fill="${s.color}" stroke="var(--surface)" stroke-width="2"/>`).join("");
    }
    svg += `<line class="xhair" x1="0" x2="0" y1="${pad.t}" y2="${pad.t + ph}" stroke="var(--muted)" stroke-width="1" visibility="hidden"/>`;
    svg += all.map((s, i) => `<circle class="xdot" data-i="${i}" r="4" fill="${s.color}" stroke="var(--surface)" stroke-width="2" visibility="hidden"/>`).join("");
    svg += `<rect class="hit" x="${pad.l}" y="${pad.t}" width="${pw}" height="${ph}" fill="transparent"/></svg>`;
    const node = mount(el, svg), tip = tooltip(el);
    const xhair = node.querySelector(".xhair"), dots = [...node.querySelectorAll(".xdot")];
    const hide = () => { xhair.setAttribute("visibility", "hidden"); dots.forEach(d => d.setAttribute("visibility", "hidden")); tip.hide(); };
    node.querySelector(".hit").addEventListener("pointermove", ev => {
      const box = node.getBoundingClientRect(), scale = width / box.width;
      const px = (ev.clientX - box.left) * scale;
      const target = x0 + (px - pad.l) / pw * (x1 - x0);
      let best = null;
      for (const x of xs) if (best === null || Math.abs(x - target) < Math.abs(best - target)) best = x;
      xhair.setAttribute("x1", X(best)); xhair.setAttribute("x2", X(best)); xhair.setAttribute("visibility", "visible");
      const rows = all.map((s, i) => {
        const p = s.points.reduce((a, b) => Math.abs(b.x - best) < Math.abs(a.x - best) ? b : a);
        dots[i].setAttribute("cx", X(p.x)); dots[i].setAttribute("cy", Y(Math.min(p.y ?? 0, yMax))); dots[i].setAttribute("visibility", "visible");
        return {name: s.name, color: s.color, value: p.y == null ? "–" : fmt(p.y)};
      });
      const ebox = el.getBoundingClientRect();
      tip.show(opts.headFor ? opts.headFor(best) : xf(best), rows, box.left - ebox.left + X(best) / scale, ev.clientY - ebox.top);
    });
    node.querySelector(".hit").addEventListener("pointerleave", hide);
  }

  /* Grouped bars: groups [{name, values:{series: number|null}}], seriesNames, colorOf(name). */
  function bars(el, opts) {
    const groups = opts.groups;
    if (!groups.length) return empty(el, opts.emptyText || "No finished configuration yet");
    const names = opts.seriesNames;
    legend(el, names.map(n => ({name: n, color: opts.colorOf(n)})));
    const width = Math.max(el.clientWidth, 260), sec = opts.sections;
    const shown = g => g.name.length > 26 ? `${g.name.slice(0, 25)}…` : g.name;
    const longest = Math.max(...groups.map(g => shown(g).length));
    // Rotate (-35°) once the labels would not fit side by side; the label band then grows
    // with the longest label (≈3.6 px down and 5.1 px left per character) so names never
    // run into the group labels below or out of the card on the left.
    const longLabels = groups.length > 1 && longest * 7 + 8 > (width - 56) / groups.length;
    const labelBand = longLabels ? 18 + Math.ceil(longest * 3.6) : 24;
    const gw0 = (width - 56) / groups.length;
    // Left padding so that no rotated label reaches past the left edge of the chart.
    const spill = longLabels ? Math.max(...groups.map((g, i) => shown(g).length * 5.1 - gw0 * (i + 0.5))) : 0;
    const pad = {l: Math.max(48, Math.ceil(48 + spill)), r: 8, t: 8, b: labelBand + (sec ? 18 : 0)};
    const height = pad.t + (opts.plotHeight || 170) + pad.b;
    const values = groups.flatMap(g => names.map(n => g.values[n] ?? 0));
    const ticks = opts.yMax ? niceTicks(opts.yMax, 5) : niceTicks(Math.max(...values, 0) || 1, 4);
    const yMax = ticks[ticks.length - 1] || 1, fmt = opts.yFmt || fmtCompact;
    const pw = width - pad.l - pad.r, ph = height - pad.t - pad.b, gw = pw / groups.length;
    const bw = Math.max(2, Math.min(24, gw * 0.8 / Math.max(names.length, 1) - 2));
    const Y = v => pad.t + ph - (v / yMax) * ph;
    let svg = `<svg viewBox="0 0 ${width} ${height}" height="${height}" role="img" aria-label="${esc(opts.label || "")}">`;
    for (const t of ticks) {
      svg += `<line x1="${pad.l}" x2="${width - pad.r}" y1="${Y(t)}" y2="${Y(t)}" stroke="var(--grid)" stroke-width="1"/>`;
      svg += `<text x="${pad.l - 6}" y="${Y(t) + 4}" text-anchor="end">${esc(fmt(t))}</text>`;
    }
    svg += `<line x1="${pad.l}" x2="${width - pad.r}" y1="${Y(0)}" y2="${Y(0)}" stroke="var(--baseline)" stroke-width="1"/>`;
    const hits = [];
    groups.forEach((g, gi) => {
      const cx = pad.l + gw * (gi + 0.5), total = names.length * (bw + 2) - 2;
      names.forEach((n, ni) => {
        const raw = g.values[n], v = Math.min(Number(raw ?? 0), yMax);
        const x = cx - total / 2 + ni * (bw + 2), top = Y(v), base = Y(0), h = base - top, r = Math.min(4, h, bw / 2);
        if (h > 0.5) svg += `<path d="M${x},${base} V${top + r} Q${x},${top} ${x + r},${top} H${x + bw - r} Q${x + bw},${top} ${x + bw},${top + r} V${base} Z" style="fill:${opts.colorOf(n)}"/>`;
        hits.push({group: g.name, name: n, value: raw == null ? "–" : fmt(Number(raw)), color: opts.colorOf(n)});
        svg += `<rect class="bar-hit" data-h="${hits.length - 1}" x="${x - 1}" y="${pad.t}" width="${bw + 2}" height="${ph}" fill="transparent"/>`;
      });
      const label = shown(g);
      svg += longLabels
        ? `<text transform="translate(${cx},${Y(0) + 12}) rotate(-35)" text-anchor="end">${esc(label)}</text>`
        : `<text x="${cx}" y="${Y(0) + 16}" text-anchor="middle">${esc(label)}</text>`;
    });
    for (const s of sec || []) {  // group bands: separator + label under the axis
      if (s.start > 0) { const x = pad.l + gw * s.start; svg += `<line x1="${x}" x2="${x}" y1="${pad.t}" y2="${Y(0)}" stroke="var(--baseline)" stroke-width="1" stroke-dasharray="3 3"/>`; }
      const cx = pad.l + gw * (s.start + s.count / 2), label = fitLabel(s.label, gw * s.count);
      svg += `<text x="${cx}" y="${height - 4}" text-anchor="middle" style="font-weight:600">${esc(label)}</text>`;
    }
    svg += "</svg>";
    const node = mount(el, svg), tip = tooltip(el);
    node.querySelectorAll(".bar-hit").forEach(r => {
      r.addEventListener("pointermove", ev => {
        const h = hits[+r.dataset.h], box = el.getBoundingClientRect();
        tip.show(h.group, [{name: h.name, color: h.color, value: h.value}], ev.clientX - box.left, ev.clientY - box.top);
      });
      r.addEventListener("pointerleave", () => tip.hide());
    });
  }

  /* Heatmap: rows (detectors), cols (configurations), value(row, col) or null.
     Colour scales over [0, max] (default 1); fmt formats the cell text. */
  function heatmap(el, opts) {
    const {rows, cols} = opts;
    if (!rows.length || !cols.length) return empty(el, opts.emptyText || "No finished configuration yet");
    legend(el, []);
    const dark = isDark(), fmt = opts.fmt || (v => v.toFixed(2)), vmax = opts.max > 0 ? opts.max : 1;
    const rowLabelW = Math.min(160, 8 + 7 * Math.max(...rows.map(r => r.length)));
    const width = Math.max(el.clientWidth, 260), cell = Math.max(18, Math.min(96, (width - rowLabelW) / cols.length));
    const rotate = cols.some(c => c.length * 6.5 > cell);
    const sec = opts.sections;
    const top = (rotate ? Math.min(140, 10 + 6 * Math.max(...cols.map(c => Math.min(c.length, 26)))) : 20) + (sec ? 16 : 0);
    const height = top + rows.length * 26 + 4;
    let svg = `<svg viewBox="0 0 ${width} ${height}" height="${height}" role="img" aria-label="${esc(opts.label || "")}">`;
    cols.forEach((c, ci) => {
      const x = rowLabelW + ci * cell + cell / 2, label = c.length > 26 ? `${c.slice(0, 25)}…` : c;
      svg += rotate ? `<text transform="translate(${x},${top - 6}) rotate(-45)">${esc(label)}</text>`
                    : `<text x="${x}" y="${top - 6}" text-anchor="middle">${esc(label)}</text>`;
    });
    for (const s of sec || []) {  // group bands: separator + label above the columns
      if (s.start > 0) { const x = rowLabelW + s.start * cell; svg += `<line x1="${x}" x2="${x}" y1="${top - 14}" y2="${height}" stroke="var(--baseline)" stroke-width="1" stroke-dasharray="3 3"/>`; }
      const cx = rowLabelW + (s.start + s.count / 2) * cell, label = fitLabel(s.label, cell * s.count);
      svg += `<text x="${cx}" y="10" text-anchor="middle" style="font-weight:600">${esc(label)}</text>`;
    }
    const cells = [];
    rows.forEach((r, ri) => {
      const y = top + ri * 26;
      svg += `<text x="0" y="${y + 17}">${esc(r)}</text>`;
      cols.forEach((c, ci) => {
        const v = opts.value(r, c), x = rowLabelW + ci * cell;
        let fill = "var(--surface-2)", ink = "var(--muted)", text = "–";
        if (v != null) {
          const step = Math.round(Math.max(0, Math.min(1, v / vmax)) * (HEAT.length - 1));
          const idx = dark ? HEAT.length - 1 - step : step;   // near zero recedes toward the surface
          fill = HEAT[idx]; ink = idx >= 6 ? "#ffffff" : "#0b0b0b"; text = fmt(v);
        }
        cells.push({row: r, col: c, value: text});
        svg += `<rect class="cell" data-c="${cells.length - 1}" x="${x + 1}" y="${y + 1}" width="${cell - 2}" height="24" rx="3" style="fill:${fill}"/>`;
        if (cell >= 34) svg += `<text x="${x + cell / 2}" y="${y + 17}" text-anchor="middle" style="fill:${ink}" pointer-events="none">${esc(text)}</text>`;
      });
    });
    svg += "</svg>";
    const node = mount(el, svg), tip = tooltip(el);
    node.querySelectorAll(".cell").forEach(r => {
      r.addEventListener("pointermove", ev => {
        const c = cells[+r.dataset.c], box = el.getBoundingClientRect();
        tip.show(c.col, [{name: c.row, value: c.value}], ev.clientX - box.left, ev.clientY - box.top);
      });
      r.addEventListener("pointerleave", () => tip.hide());
    });
    let scale = el.querySelector(":scope > .heat-scale");
    if (!scale) { scale = document.createElement("div"); scale.className = "heat-scale"; }
    el.appendChild(scale);  // keep the scale below the freshly mounted grid
    const ramp = (dark ? [...HEAT].reverse() : HEAT).join(",");
    scale.innerHTML = `<span>${esc(fmt(0))}</span><span class="ramp" style="background:linear-gradient(90deg,${ramp})"></span><span>${esc(fmt(vmax))}</span>${opts.note ? `<span>${esc(opts.note)}</span>` : ""}`;
  }

  /* Scatter: series [{name, color, points:[{x, y, label}]}], xMax/yMax (fixed), xFmt, yFmt,
     xLabel, yLabel. One tooltip per point (series, label, both values). */
  function scatter(el, opts) {
    const all = opts.series.filter(s => s.points.length);
    if (!all.length) return empty(el, opts.emptyText || "No finished configuration yet");
    legend(el, opts.series.map(s => ({name: s.name, color: s.color})));
    const width = Math.max(el.clientWidth, 260), height = opts.height || 240;
    const pad = {l: 52, r: 12, t: 8, b: 40};
    const pts = all.flatMap(s => s.points.map(p => ({...p, s})));
    const xt = niceTicks(opts.xMax ?? (Math.max(...pts.map(p => p.x)) || 1), 4);
    const yt = opts.yMax != null ? niceTicks(opts.yMax, 5) : niceTicks(Math.max(...pts.map(p => p.y)) || 1, 4);
    const xMax = xt[xt.length - 1] || 1, yMax = yt[yt.length - 1] || 1;
    const pw = width - pad.l - pad.r, ph = height - pad.t - pad.b;
    const X = x => pad.l + x / xMax * pw, Y = y => pad.t + ph - y / yMax * ph;
    const xf = opts.xFmt || fmtCompact, yf = opts.yFmt || fmtCompact;
    let svg = `<svg viewBox="0 0 ${width} ${height}" height="${height}" role="img" aria-label="${esc(opts.label || "")}">`;
    for (const t of yt) svg += `<line x1="${pad.l}" x2="${width - pad.r}" y1="${Y(t)}" y2="${Y(t)}" stroke="var(--grid)"/><text x="${pad.l - 6}" y="${Y(t) + 4}" text-anchor="end">${esc(yf(t))}</text>`;
    for (const t of xt) svg += `<line x1="${X(t)}" x2="${X(t)}" y1="${pad.t}" y2="${pad.t + ph}" stroke="var(--grid)"/><text x="${X(t)}" y="${pad.t + ph + 16}" text-anchor="middle">${esc(xf(t))}</text>`;
    svg += `<line x1="${pad.l}" x2="${width - pad.r}" y1="${Y(0)}" y2="${Y(0)}" stroke="var(--baseline)"/>`;
    if (opts.xLabel) svg += `<text x="${pad.l + pw / 2}" y="${height - 4}" text-anchor="middle">${esc(opts.xLabel)}</text>`;
    if (opts.yLabel) svg += `<text transform="translate(12,${pad.t + ph / 2}) rotate(-90)" text-anchor="middle">${esc(opts.yLabel)}</text>`;
    pts.forEach((p, i) => {
      svg += `<circle cx="${X(Math.min(p.x, xMax))}" cy="${Y(Math.min(p.y, yMax))}" r="5" fill="${p.s.color}" stroke="var(--surface)" stroke-width="2" fill-opacity="0.9"/>`;
      svg += `<circle class="pt-hit" data-i="${i}" cx="${X(Math.min(p.x, xMax))}" cy="${Y(Math.min(p.y, yMax))}" r="10" fill="transparent"/>`;
    });
    svg += "</svg>";
    const node = mount(el, svg), tip = tooltip(el);
    node.querySelectorAll(".pt-hit").forEach(c => {
      c.addEventListener("pointermove", ev => {
        const p = pts[+c.dataset.i], box = el.getBoundingClientRect();
        tip.show(p.label || "", [{name: p.s.name, color: p.s.color, value: ""},
                                 {name: opts.xName || "x", value: xf(p.x)}, {name: opts.yName || "y", value: yf(p.y)}],
                 ev.clientX - box.left, ev.clientY - box.top);
      });
      c.addEventListener("pointerleave", () => tip.hide());
    });
  }

  /* Horizontal bar list: items [{label, value, note}], fmt. One series, one color. */
  function hbars(el, items, fmt = fmtCompact) {
    el.replaceChildren();
    if (!items.length) { const p = document.createElement("div"); p.className = "muted small"; p.textContent = "No data yet"; el.appendChild(p); return; }
    const max = Math.max(...items.map(i => i.value), 1);
    for (const it of items) {
      const row = document.createElement("div"); row.className = "hbar";
      const label = document.createElement("span"); label.className = "hbar-label"; label.textContent = it.label;
      if (it.note) { const tag = document.createElement("span"); tag.className = "tag"; tag.textContent = it.note; label.appendChild(tag); }
      const val = document.createElement("span"); val.className = "mono"; val.textContent = fmt(it.value);
      const track = document.createElement("div"); track.className = "hbar-track";
      const fill = document.createElement("div"); fill.className = "hbar-fill"; fill.style.width = `${100 * it.value / max}%`;
      track.appendChild(fill); row.append(label, val, track); el.appendChild(row);
    }
  }

  return {esc, series, ansiToHtml, fmtBytes, fmtDuration, fmtCompact, fmtClock, line, bars, heatmap, scatter, hbars, empty};
})();
