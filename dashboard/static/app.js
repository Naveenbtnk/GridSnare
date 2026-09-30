/* GridSnare dashboard client (SPEC.md Section 7.5, Section 9 step 5).
 *
 * Renders the server-rendered payload immediately, then polls /api/dashboard on the
 * configured interval. All values come from the data store; nothing here fabricates a
 * number, and an empty store renders an explicit empty state.
 *
 * Colour system: every hue is a pair — `mark` (saturated: dots, arcs, bars, chips) and
 * `ink` (a darkened partner that stays readable as text). Body copy is never neon.
 *
 * Controls: each one does real work against the loaded payload — the nav scrolls and
 * tracks the section you are reading, the search and the filter chips narrow the feed
 * on screen (labelled as such, because the feed is capped at feed_limit rows), the
 * window buttons re-query the timeline range from the API, and the row button copies
 * that alert as JSON for a report. There are no placeholder buttons.
 */
(function () {
  "use strict";

  var SEVERITIES = ["Critical", "High", "Medium", "Low"];

  /* Data marks and their text partners. */
  var SEVERITY = {
    Critical: { mark: "#ff2e63", ink: "#b3123c" },
    High:     { mark: "#ff7a00", ink: "#9a4a00" },
    Medium:   { mark: "#e0a500", ink: "#7a5a00" },
    Low:      { mark: "#00c888", ink: "#046b4b" },
    Unknown:  { mark: "#94a3b8", ink: "#4a5666" }
  };

  var SOURCE = {
    honeypot: { mark: "#7c5cff", ink: "#5433cc", label: "Honeypot (decoy) events" },
    monitor:  { mark: "#00a3c4", ink: "#00637a", label: "Monitor (capture) events" }
  };

  /* Bounded historical replays (e.g. swat_replay). They are shown so the event
     totals add up, but carry the dataset's own timestamps rather than capture
     time, so they are never graded fresh/stale and never throb as a fault. */
  var HISTORICAL = { mark: "#94a3b8", ink: "#4a5666", label: "historical replay" };

  var RULES = {
    "DR-1": { mark: "#ff2e63", ink: "#b3123c" },
    "DR-2": { mark: "#ff7a00", ink: "#9a4a00" },
    "DR-3": { mark: "#e0a500", ink: "#7a5a00" },
    "DR-4": { mark: "#7c5cff", ink: "#5433cc" },
    "DR-5": { mark: "#4f46e5", ink: "#322ca8" },
    "DR-6": { mark: "#00c888", ink: "#046b4b" },
    "DR-7": { mark: "#e1009f", ink: "#a3006f" },
    "GR-1": { mark: "#38bdf8", ink: "#0b6ea8" },
    "GR-2": { mark: "#f97316", ink: "#b34a00" },
    "GR-3": { mark: "#a3e635", ink: "#4d7c0f" },
    "GR-4": { mark: "#e879f9", ink: "#a21caf" },
    "—":    { mark: "#94a3b8", ink: "#4a5666" }
  };

  var PROTOCOLS = {
    modbus: { mark: "#4f46e5", ink: "#322ca8" },
    goose:  { mark: "#38bdf8", ink: "#0b6ea8" },
    http:   { mark: "#e1009f", ink: "#a3006f" },
    snmp:   { mark: "#00b3a4", ink: "#00665e" },
    s7comm: { mark: "#38bdf8", ink: "#0b6ea8" },
    enip:   { mark: "#7c5cff", ink: "#5433cc" },
    ftp:    { mark: "#e0a500", ink: "#7a5a00" },
    bacnet: { mark: "#00c888", ink: "#046b4b" }
  };
  var PROTOCOL_DEFAULT = { mark: "#94a3b8", ink: "#4a5666" };

  /* Pipeline state -> the emphasized card's fill, banner colour and label. */
  /* `label` is the sentence used on the banner, `headline` the state of the KPI card
     and the CTA, and `short` the one word the sidebar badge can hold — a full
     headline there wrapped onto two lines and squeezed the nav label with it. */
  var PIPELINE = {
    healthy:  { fill: "#0f8a4d", mark: "#00c888", ink: "#046b4b", label: "Healthy",       headline: "Detection running", short: "healthy" },
    quiet:    { fill: "#9a6b00", mark: "#e0a500", ink: "#7a5a00", label: "Quiet — nothing new from any source", headline: "Lab quiet", short: "quiet" },
    blind:    { fill: "#b45309", mark: "#ff7a00", ink: "#9a4a00", label: "Degraded — a capture path has gone silent", headline: "Capture degraded", short: "degraded" },
    down:     { fill: "#b3123c", mark: "#ff2e63", ink: "#b3123c", label: "Detection stopped", headline: "Detection stopped", short: "stopped" },
    starting: { fill: "#3730a3", mark: "#4f46e5", ink: "#322ca8", label: "Starting up",   headline: "Starting up", short: "starting" }
  };

  var HEALTH = {
    fresh:         { mark: "#00c888", ink: "#046b4b", label: "fresh" },
    stale:         { mark: "#ff7a00", ink: "#9a4a00", label: "stale" },
    silent:        { mark: "#ff2e63", ink: "#b3123c", label: "silent" },
    unknown:       { mark: "#94a3b8", ink: "#4a5666", label: "unknown" },
    current:       { mark: "#00c888", ink: "#046b4b", label: "current" },
    catching_up:   { mark: "#4f46e5", ink: "#322ca8", label: "catching up" },
    behind:        { mark: "#ff2e63", ink: "#b3123c", label: "stalled" },
    stopped:       { mark: "#ff2e63", ink: "#b3123c", label: "stopped" },
    not_reporting: { mark: "#ff7a00", ink: "#9a4a00", label: "not reporting" },
    never_run:     { mark: "#ff2e63", ink: "#b3123c", label: "never run" }
  };

  var GRID = "rgba(15,23,42,.06)";
  var TICK = "#64748b";
  var WINDOW_KEY = "gridsnare.timeline_minutes";

  var charts = { severity: null, source: null, timeline: null };
  var everLoaded = false;
  var lastBanner = null;
  var latest = null;
  var filters = { severity: "All", rule: "All", text: "" };
  var timelineMinutes = null;

  function el(id) { return document.getElementById(id); }
  function setText(node, value) { if (node) { node.textContent = String(value); } }

  function rgba(hex, alpha) {
    var n = parseInt(hex.slice(1), 16);
    return "rgba(" + ((n >> 16) & 255) + "," + ((n >> 8) & 255) + "," + (n & 255) + "," + alpha + ")";
  }

  function paint(node, token) {
    node.style.setProperty("--chip-mark", token.mark);
    node.style.setProperty("--chip-ink", token.ink);
    node.style.setProperty("--chip-bg", rgba(token.mark, 0.12));
    node.style.setProperty("--chip-line", rgba(token.mark, 0.34));
  }

  function chip(text, token, withDot) {
    var node = document.createElement("span");
    node.className = "chip";
    paint(node, token);
    if (withDot !== false) { node.appendChild(document.createElement("i")); }
    var label = document.createElement("b");
    label.style.fontWeight = "650";
    setText(label, text);
    node.appendChild(label);
    return node;
  }

  function localTime(iso) {
    var when = new Date(iso);
    if (isNaN(when.getTime())) { return iso; }
    return when.toLocaleTimeString([], { hour: "2-digit", minute: "2-digit", second: "2-digit" });
  }

  function localClock(iso) {
    return localTime(iso).replace(/:\d\d(\s|$)/, "$1");
  }

  /* ---------------------------- chart plugins ---------------------------- */

  var neonGlow = {
    id: "neonGlow",
    beforeDatasetDraw: function (chart, args) {
      var dataset = args.meta && args.meta.dataset;
      var colour = dataset && dataset.backgroundColor;
      if (Array.isArray(colour)) { colour = colour[0]; }
      if (typeof colour !== "string" || colour.charAt(0) !== "#") { return; }
      chart.ctx.shadowColor = rgba(colour, 0.32);
      chart.ctx.shadowBlur = 12;
      chart.ctx.shadowOffsetY = 3;
    },
    afterDatasetDraw: function (chart) {
      chart.ctx.shadowBlur = 0;
      chart.ctx.shadowOffsetY = 0;
    }
  };

  var centreTotal = {
    id: "centreTotal",
    afterDraw: function (chart) {
      var cfg = chart.options.plugins && chart.options.plugins.centreTotal;
      // Chart.js materialises an options object for every registered plugin, so a
      // chart that never configured this one arrives as `{}` rather than `undefined`.
      if (!cfg || cfg.disabled || typeof cfg.value !== "number") { return; }
      var area = chart.chartArea;
      if (!area) { return; }
      var ctx = chart.ctx;
      var cx = (area.left + area.right) / 2;
      var cy = (area.top + area.bottom) / 2;
      ctx.save();
      ctx.textAlign = "center";
      ctx.textBaseline = "middle";
      ctx.fillStyle = cfg.color || "#0f172a";
      ctx.font = "700 26px " + Chart.defaults.font.family;
      ctx.fillText(String(cfg.value), cx, cy - 3);
      ctx.fillStyle = TICK;
      ctx.font = "700 9px " + Chart.defaults.font.family;
      ctx.fillText(String(cfg.label).toUpperCase(), cx, cy + 17);
      ctx.restore();
    }
  };

  function applyChartDefaults() {
    if (typeof window.Chart !== "function") { return false; }
    Chart.defaults.font.family = window.getComputedStyle(document.body).fontFamily;
    Chart.defaults.font.size = 11;
    Chart.defaults.color = TICK;
    Chart.defaults.animation.duration = 460;
    Chart.defaults.plugins.tooltip.backgroundColor = "rgba(255,255,255,.98)";
    Chart.defaults.plugins.tooltip.titleColor = "#0f172a";
    Chart.defaults.plugins.tooltip.bodyColor = "#475569";
    Chart.defaults.plugins.tooltip.borderColor = "rgba(15,23,42,.12)";
    Chart.defaults.plugins.tooltip.borderWidth = 1;
    Chart.defaults.plugins.tooltip.padding = 10;
    Chart.defaults.plugins.tooltip.cornerRadius = 10;
    Chart.defaults.plugins.tooltip.boxPadding = 5;
    Chart.defaults.plugins.tooltip.usePointStyle = true;
    Chart.register(neonGlow, centreTotal);
    return true;
  }

  /* ------------------------------ scroll-spy nav ------------------------------ */

  var navItems = [];

  function initNav() {
    navItems = Array.prototype.slice.call(document.querySelectorAll(".nav-item"));
    navItems.forEach(function (item) {
      item.addEventListener("click", function (event) {
        event.preventDefault();
        var target = document.getElementById(item.getAttribute("data-target"));
        if (target) { target.scrollIntoView({ behavior: "smooth", block: "start" }); }
      });
    });
    Array.prototype.slice.call(document.querySelectorAll("[data-scroll]")).forEach(function (link) {
      link.addEventListener("click", function (event) {
        event.preventDefault();
        var target = document.getElementById(link.getAttribute("data-scroll"));
        if (target) { target.scrollIntoView({ behavior: "smooth", block: "start" }); }
      });
    });

    // Highlight whichever section is nearest the top of the viewport. Built on
    // scroll position rather than IntersectionObserver ratios so two sections can
    // never both claim to be active.
    var sections = navItems
      .map(function (item) { return document.getElementById(item.getAttribute("data-target")); })
      .filter(Boolean);
    function update() {
      var best = sections[0];
      var bestDistance = Infinity;
      sections.forEach(function (section) {
        var distance = Math.abs(section.getBoundingClientRect().top - 90);
        if (distance < bestDistance) { bestDistance = distance; best = section; }
      });
      navItems.forEach(function (item) {
        item.classList.toggle("active", item.getAttribute("data-target") === best.id);
      });
    }
    window.addEventListener("scroll", update, { passive: true });
    window.addEventListener("resize", update);
    update();
  }

  /* ------------------------------ KPI row ------------------------------ */

  function renderKpis(payload) {
    var totals = payload.totals || {};
    var pipeline = payload.pipeline || {};
    var state = PIPELINE[pipeline.state] || PIPELINE.starting;

    var card = el("kpi-detection");
    if (card) { card.style.setProperty("--fill", state.fill); }
    setText(el("detection-label"), "Detection");
    setText(el("detection-value"), state.headline);
    setText(el("detection-sub"), pipeline.summary || "waiting for the first poll…");
    var engine = pipeline.engine || {};
    setText(el("detection-meta"),
      engine.state === "behind" || engine.state === "stopped" || engine.state === "not_reporting"
        ? "engine " + engine.state.replace("_", " ")
        : "engine poll " + (engine.age_text || "—"));

    setText(el("kpi-alerts"), totals.alerts_total || 0);
    var correlated = totals.alerts_correlated || 0;
    var delta = el("kpi-correlated");
    delta.textContent = correlated + " correlated (DR-7)";
    delta.className = "delta" + (correlated ? "" : " neutral");

    setText(el("kpi-events"), totals.events_total || 0);
    setText(el("kpi-split"),
      (totals.events_honeypot || 0) + " honeypot · " + (totals.events_monitor || 0) + " monitor");
    setText(el("kpi-store"), payload.database_present ? "store live" : "store absent");

    // The CTA in the topbar is the pipeline state, not a decorative button.
    var cta = el("cta");
    if (cta) { cta.style.background = state.fill; }
    setText(el("cta-text"), pipeline.state === "healthy" ? "Detection running" : state.headline);

    setText(el("nav-alerts"), totals.alerts_total || 0);
    setText(el("nav-sources"), totals.events_total || 0);
    setText(el("nav-health"), state.short);
  }

  function renderNotice(payload) {
    var box = el("notice");
    if (payload.notice) {
      setText(box, payload.notice);
      box.hidden = false;
    } else {
      box.hidden = true;
      box.textContent = "";
    }
  }

  /* ------------------------------ sensor health ------------------------------ */

  function healthRow(name, token, fact, alerting) {
    var row = document.createElement("div");
    row.className = "hrow" + (alerting ? " alert" : "");
    row.style.setProperty("--hmark", token.mark);
    row.appendChild(document.createElement("i"));
    var label = document.createElement("span");
    label.className = "hname";
    setText(label, name);
    row.appendChild(label);
    row.appendChild(chip(token.label, token, false));
    var detail = document.createElement("span");
    detail.className = "hfact";
    setText(detail, fact);
    row.appendChild(detail);
    return row;
  }

  function sourceFact(entry) {
    if (entry.state === "silent") { return "no event ever stored"; }
    if (entry.state === "unknown") { return entry.events + " event(s) · newest timestamp unreadable"; }
    return entry.events + " event(s) · newest " + entry.age_text;
  }

  function renderPipeline(payload) {
    var pipeline = payload.pipeline || {};
    var state = PIPELINE[pipeline.state] || PIPELINE.starting;

    var banner = el("pipeline-banner");
    var verdict = (pipeline.state || "") + "|" + (pipeline.summary || "");
    if (pipeline.summary && pipeline.state !== "healthy") {
      if (verdict !== lastBanner) {
        banner.style.setProperty("--pstate-mark", state.mark);
        banner.style.setProperty("--pstate-ink", state.ink);
        banner.style.setProperty("--pstate-bg", rgba(state.mark, 0.07));
        banner.style.setProperty("--pstate-line", rgba(state.mark, 0.3));
        banner.classList.toggle("alert", pipeline.state === "down" || pipeline.state === "blind");
        setText(el("pipeline-label"), state.label);
        setText(el("pipeline-summary"), pipeline.summary);
        lastBanner = verdict;
      }
      banner.hidden = false;
    } else {
      banner.hidden = true;
      lastBanner = verdict;
    }

    var host = el("health-rows");
    host.textContent = "";
    (pipeline.sources || []).forEach(function (entry) {
      var token = HEALTH[entry.state] || HEALTH.unknown;
      host.appendChild(healthRow(entry.source, token, sourceFact(entry), entry.state !== "fresh"));
    });
    var engine = pipeline.engine;
    if (engine) {
      var engineToken = HEALTH[engine.state] || HEALTH.unknown;
      var engineFact;
      if (engine.lag_events > 0) {
        engineFact = engine.lag_events + " unjudged · oldest waiting " + engine.lag_age_text +
          " · watermark " + engine.watermark_text + " / newest event id " + engine.latest_event_id;
      } else {
        engineFact = "0 unjudged · last poll " + engine.age_text;
      }
      host.appendChild(healthRow("engine", engineToken, engineFact, !!engine.fault));
    }
    (pipeline.historical || []).forEach(function (entry) {
      var fact = entry.events + " event(s) · historical replay, not freshness-graded";
      host.appendChild(healthRow(entry.source, HISTORICAL, fact, false));
    });

    // Sidebar mirror of the same state, so the nav area is never decorative.
    var side = el("side-rows");
    side.textContent = "";
    (pipeline.sources || []).concat(engine ? [Object.assign({ source: "engine" }, engine)] : [])
      .forEach(function (entry) {
        var token = HEALTH[entry.state] || HEALTH.unknown;
        var row = document.createElement("div");
        row.className = "side-row";
        row.style.setProperty("--hmark", token.mark);
        row.appendChild(document.createElement("i"));
        var name = document.createElement("b");
        setText(name, entry.source === "engine" ? "engine" : entry.source);
        row.appendChild(name);
        var tail = document.createElement("small");
        if (entry.source === "engine") {
          setText(tail, entry.lag_events > 0 ? entry.lag_events + " unjudged" : entry.age_text);
        } else {
          setText(tail, entry.state === "fresh" ? entry.age_text : entry.state);
        }
        row.appendChild(tail);
        side.appendChild(row);
      });

    var alerts = pipeline.alerts || {};
    setText(el("pipeline-caption"),
      "checked " + localTime(pipeline.checked_at) +
      " · stale after " + (pipeline.stale_after_seconds || 0) + "s" +
      (alerts.total ? " · last alert " + alerts.age_text : " · no alerts yet"));
  }

  /* ------------------------------ doughnuts ------------------------------ */

  function doughnut(host, existing, config) {
    if (existing) {
      existing.data.labels = config.labels;
      existing.data.datasets = config.datasets;
      existing.options.plugins.legend.display = !config.empty;
      existing.options.plugins.tooltip.enabled = !config.empty;
      existing.options.plugins.centreTotal = config.centre;
      existing.update();
      return existing;
    }
    return new Chart(host, {
      type: "doughnut",
      data: { labels: config.labels, datasets: config.datasets },
      options: {
        responsive: true,
        maintainAspectRatio: false,
        cutout: "71%",
        layout: { padding: 4 },
        plugins: {
          legend: {
            display: !config.empty,
            position: "bottom",
            labels: { color: TICK, boxWidth: 8, boxHeight: 8, padding: 13, usePointStyle: true, pointStyle: "circle" }
          },
          tooltip: { enabled: !config.empty, callbacks: config.tooltip },
          centreTotal: config.centre
        }
      }
    });
  }

  /* A zero total would draw nothing, which looks broken: a colourless ring with a
     "0" reads as "no data" without pretending there is a category to show. */
  function emptyRing() {
    return {
      datasets: [{
        data: [1],
        backgroundColor: ["rgba(15,23,42,.055)"],
        borderColor: "#ffffff",
        borderWidth: 2,
        hoverBackgroundColor: ["rgba(15,23,42,.055)"]
      }],
      labels: ["-"]
    };
  }

  function dominantColour(values, tokens, fallback) {
    var best = -1;
    var colour = fallback;
    values.forEach(function (value, index) {
      if (value > best) { best = value; colour = tokens[index].mark; }
    });
    return best > 0 ? colour : fallback;
  }

  /* A <canvas> is opaque to assistive tech, so each chart states its own contents
     in text. Built from the same values that are drawn, so the label cannot claim
     something the chart does not show. */
  function labelChart(id, text) {
    var canvas = el(id);
    if (canvas) { canvas.setAttribute("role", "img"); canvas.setAttribute("aria-label", text); }
  }

  function renderSeverity(payload) {
    var breakdown = payload.severity || {};
    var values = SEVERITIES.map(function (name) { return breakdown[name] || 0; });
    var tokens = SEVERITIES.map(function (name) { return SEVERITY[name]; });
    var total = values.reduce(function (a, b) { return a + b; }, 0);
    var empty = total === 0;
    var ring = empty ? emptyRing() : {
      labels: SEVERITIES,
      datasets: [{
        data: values,
        backgroundColor: tokens.map(function (t) { return t.mark; }),
        borderColor: "#ffffff",
        borderWidth: 2.5,
        hoverBorderColor: "#ffffff"
      }]
    };

    labelChart("severity-chart", empty
      ? "Severity breakdown: no alerts in the store."
      : "Severity breakdown doughnut of " + total + " stored alert(s): " +
        SEVERITIES.map(function (name, index) { return name + " " + values[index]; }).join(", ") + ".");

    charts.severity = doughnut(el("severity-chart"), charts.severity, {
      empty: empty,
      labels: ring.labels,
      datasets: ring.datasets,
      centre: {
        value: total,
        label: "alerts",
        color: empty ? SEVERITY.Unknown.ink : SEVERITY[SEVERITIES[0]].ink
      },
      tooltip: { label: function (ctx) { return " " + ctx.label + ": " + ctx.parsed + " alert(s)"; } }
    });
  }

  function renderSourceSplit(payload) {
    var totals = payload.totals || {};
    var values = [totals.events_honeypot || 0, totals.events_monitor || 0];
    var tokens = [SOURCE.honeypot, SOURCE.monitor];
    var total = values[0] + values[1];
    var empty = total === 0;
    var ring = empty ? emptyRing() : {
      labels: [SOURCE.honeypot.label, SOURCE.monitor.label],
      datasets: [{
        data: values,
        backgroundColor: tokens.map(function (t) { return t.mark; }),
        borderColor: "#ffffff",
        borderWidth: 2.5,
        hoverBorderColor: "#ffffff"
      }]
    };

    labelChart("source-chart", empty
      ? "Honeypot versus monitor events: nothing captured yet."
      : "Honeypot versus monitor events doughnut of " + total + " captured event(s): honeypot " +
        values[0] + ", monitor " + values[1] + ".");

    charts.source = doughnut(el("source-chart"), charts.source, {
      empty: empty,
      labels: ring.labels,
      datasets: ring.datasets,
      centre: {
        value: total,
        label: "events",
        color: empty ? SEVERITY.Unknown.ink : dominantColour(values, tokens, SOURCE.monitor.mark)
      },
      tooltip: { label: function (ctx) { return " " + ctx.label + ": " + ctx.parsed + " event(s)"; } }
    });
  }

  /* ------------------------------ timeline ------------------------------ */

  function barFill(chart, colour) {
    var area = chart.chartArea;
    if (!area) { return colour; }
    var gradient = chart.ctx.createLinearGradient(0, area.top, 0, area.bottom);
    gradient.addColorStop(0, colour);
    gradient.addColorStop(1, rgba(colour, 0.6));
    return gradient;
  }

  function renderTimeline(payload) {
    var timeline = payload.timeline || { labels: [], series: {} };
    var labels = (timeline.labels || []).map(localClock);
    var series = timeline.series || {};
    var names = SEVERITIES.filter(function (name) { return series[name]; });

    var datasets = names.map(function (name) {
      return {
        label: name,
        data: series[name],
        backgroundColor: SEVERITY[name].mark,
        hoverBackgroundColor: SEVERITY[name].mark,
        borderRadius: 5,
        borderSkipped: false,
        maxBarThickness: 26,
        stack: "alerts"
      };
    });

    var windowMinutes = timeline.window_minutes || 0;
    setText(el("timeline-caption"),
      "last " + windowMinutes + " min · per minute · local time");

    var peak = names.reduce(function (best, name) {
      return Math.max(best, Math.max.apply(null, (series[name] || [0]).concat([0])));
    }, 0);
    labelChart("timeline-chart", names.length && peak
      ? "Alert timeline: stacked bars per minute over the last " + windowMinutes +
        " minutes by severity, busiest minute " + peak + " alert(s)."
      : "Alert timeline: no alerts in the last " + windowMinutes + " minutes.");

    if (charts.timeline) {
      charts.timeline.data.labels = labels;
      charts.timeline.data.datasets = datasets;
      charts.timeline.update();
      return;
    }

    charts.timeline = new Chart(el("timeline-chart"), {
      type: "bar",
      data: { labels: labels, datasets: datasets },
      options: {
        responsive: true,
        maintainAspectRatio: false,
        interaction: { mode: "index", intersect: false },
        scales: {
          x: {
            stacked: true,
            grid: { display: false },
            border: { display: false },
            ticks: { color: TICK, font: { size: 10 }, maxRotation: 0, autoSkipPadding: 18 }
          },
          y: {
            stacked: true,
            beginAtZero: true,
            border: { display: false },
            grid: { color: GRID },
            ticks: { color: TICK, font: { size: 10 }, precision: 0, padding: 6 }
          }
        },
        plugins: {
          legend: {
            position: "top",
            align: "end",
            labels: { color: TICK, boxWidth: 8, boxHeight: 8, padding: 14, usePointStyle: true, pointStyle: "circle" }
          }
        },
        animation: {
          onProgress: function () {
            this.data.datasets.forEach(function (dataset, index) {
              dataset.backgroundColor = barFill(this, SEVERITY[names[index]].mark);
            }, this);
          }
        }
      }
    });
  }

  /* ------------------------------ feed: filters ------------------------------ */

  function matchesFilters(alert) {
    if (filters.severity !== "All" && alert.severity !== filters.severity) { return false; }
    if (filters.rule !== "All" && alert.rule_id !== filters.rule) { return false; }
    if (filters.text) {
      var haystack = [alert.src_ip, alert.dst_ip, alert.rule_id, alert.protocol,
                      alert.severity, alert.description, alert.id]
        .join(" ").toLowerCase();
      if (haystack.indexOf(filters.text) === -1) { return false; }
    }
    return true;
  }

  function filterChip(label, token, pressed, onClick) {
    var button = document.createElement("button");
    button.type = "button";
    button.className = "filter-chip";
    button.setAttribute("aria-pressed", pressed ? "true" : "false");
    if (token) {
      button.style.setProperty("--chip-mark", token.mark);
      button.style.setProperty("--chip-ink", token.ink);
      button.style.setProperty("--chip-bg", rgba(token.mark, 0.14));
      button.style.setProperty("--chip-line", rgba(token.mark, 0.4));
      button.appendChild(document.createElement("i"));
    }
    var text = document.createElement("span");
    setText(text, label);
    button.appendChild(text);
    button.addEventListener("click", onClick);
    return button;
  }

  function renderFilters(payload) {
    var host = el("filters");
    var feed = payload.feed || [];
    host.textContent = "";

    host.appendChild(filterChip("All", null, filters.severity === "All", function () {
      filters.severity = "All"; renderFeed(latest);
    }));
    SEVERITIES.forEach(function (name) {
      var count = feed.filter(function (a) { return a.severity === name; }).length;
      host.appendChild(filterChip(name + " " + count, SEVERITY[name], filters.severity === name,
        function () { filters.severity = name; renderFeed(latest); }));
    });

    // Rule filter: options come from the rows actually loaded, so it never offers a
    // rule that is not on screen.
    var rules = [];
    feed.forEach(function (alert) {
      if (rules.indexOf(alert.rule_id) === -1) { rules.push(alert.rule_id); }
    });
    rules.sort();
    var select = document.createElement("select");
    select.className = "filter-chip";
    select.setAttribute("aria-label", "Filter by detection rule");
    select.appendChild(new Option("Rule: all", "All", false, filters.rule === "All"));
    rules.forEach(function (rule) {
      var count = feed.filter(function (a) { return a.rule_id === rule; }).length;
      select.appendChild(new Option(rule + " (" + count + ")", rule, false, filters.rule === rule));
    });
    select.addEventListener("change", function () {
      filters.rule = select.value;
      renderFeed(latest);
    });
    host.appendChild(select);
  }

  function syncFilterUi() {
    var active = filters.severity !== "All" || filters.rule !== "All" || filters.text !== "";
    var clear = el("clear-filters");
    if (clear) { clear.disabled = !active; }
    setText(el("search-hint"),
      filters.text ? 'matching "' + filters.text + '"' : "filters the loaded rows");
  }

  /* ------------------------------ feed ------------------------------ */

  function severityCell(alert) {
    var cell = document.createElement("td");
    cell.appendChild(chip(alert.severity, SEVERITY[alert.severity] || SEVERITY.Unknown));
    if (alert.correlated_event_id) {
      var badge = chip("correlated", SOURCE.honeypot, false);
      badge.style.marginLeft = "7px";
      cell.appendChild(badge);
    }
    return cell;
  }

  /* Copies one alert as JSON, for pasting into a report. The button reports what it
     did instead of silently succeeding. */
  function copyCell(alert) {
    var cell = document.createElement("td");
    var button = document.createElement("button");
    button.type = "button";
    button.className = "copy";
    button.title = "Copy this alert as JSON";
    button.setAttribute("aria-label", "Copy alert " + alert.id + " as JSON");
    button.innerHTML = '<svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><rect x="9" y="9" width="11" height="11" rx="2"></rect><path d="M15 5H6a2 2 0 0 0-2 2v9"></path></svg>';
    button.addEventListener("click", function () {
      var payload = JSON.stringify({
        id: alert.id,
        raised_at_utc: alert.timestamp,
        rule_id: alert.rule_id,
        severity: alert.severity,
        protocol: alert.protocol,
        src_ip: alert.src_ip,
        dst_ip: alert.dst_ip,
        raw_event_id: alert.event_id,
        correlated_event_id: alert.correlated_event_id,
        description: alert.description
      }, null, 2);

      function settle(ok) {
        button.classList.toggle("done", ok);
        button.title = ok ? "Copied" : "Copy failed — select the row manually";
        window.setTimeout(function () { button.classList.remove("done"); }, 1200);
      }

      if (navigator.clipboard && navigator.clipboard.writeText) {
        navigator.clipboard.writeText(payload).then(function () { settle(true); },
          function () { settle(false); });
      } else {
        // The dashboard is served over plain HTTP on 127.0.0.1, where the async
        // clipboard API is unavailable outside a secure context.
        settle(false);
        window.prompt("Copy this alert:", payload);
      }
    });
    cell.appendChild(button);
    return cell;
  }

  function renderFeed(payload) {
    var body = el("feed-body");
    var empty = el("feed-empty");
    var feed = payload.feed || [];
    var total = (payload.totals || {}).alerts_total || 0;

    body.textContent = "";
    var shown = feed.filter(matchesFilters);

    empty.hidden = shown.length > 0;
    if (!shown.length) {
      setText(empty, feed.length
        ? "No alerts match the current filters."
        : "No alerts in the store.");
    }

    // Honest scope: the feed is capped, so search/filters act on what is loaded.
    setText(el("feed-caption"),
      shown.length === feed.length
        ? "showing all " + feed.length + " loaded alert(s)" + (total > feed.length ? " — " + total + " in the store" : "")
        : "showing " + shown.length + " of " + feed.length + " loaded alert(s) — filters act on loaded rows only");

    shown.forEach(function (alert) {
      var row = document.createElement("tr");
      var token = SEVERITY[alert.severity] || SEVERITY.Unknown;
      row.style.setProperty("--dot", token.mark);

      var when = document.createElement("td");
      when.className = "mono";
      setText(when, localTime(alert.timestamp));
      row.appendChild(when);

      row.appendChild(severityCell(alert));

      var rule = document.createElement("td");
      rule.appendChild(chip(alert.rule_id, RULES[alert.rule_id] || RULES["—"], false));
      row.appendChild(rule);

      var protocol = document.createElement("td");
      var key = String(alert.protocol || "").toLowerCase();
      protocol.appendChild(chip(alert.protocol, PROTOCOLS[key] || PROTOCOL_DEFAULT, false));
      row.appendChild(protocol);

      var source = document.createElement("td");
      source.className = "mono";
      setText(source, alert.src_ip || "—");
      row.appendChild(source);

      var target = document.createElement("td");
      target.className = "mono";
      setText(target, alert.dst_ip || "—");
      row.appendChild(target);

      var id = document.createElement("td");
      var idText = document.createElement("span");
      idText.className = "rowid";
      setText(idText, "#" + alert.id);
      id.appendChild(idText);
      row.appendChild(id);

      var description = document.createElement("td");
      description.className = "desc";
      setText(description, alert.description);
      row.appendChild(description);

      row.appendChild(copyCell(alert));
      body.appendChild(row);
    });

    renderFilters(payload);
    syncFilterUi();
  }

  /* ------------------------------ controls ------------------------------ */

  function setWindowButtons(payload) {
    var host = el("window-control");
    var windows = payload.timeline_windows || [];
    if (!windows.length) { host.parentNode && (host.hidden = true); return; }
    if (timelineMinutes === null) {
      var stored = null;
      try { stored = parseInt(window.localStorage.getItem(WINDOW_KEY), 10); } catch (err) { stored = null; }
      timelineMinutes = windows.indexOf(stored) !== -1 ? stored : (payload.timeline.window_minutes || windows[0]);
    }
    host.textContent = "";
    windows.forEach(function (minutes) {
      var button = document.createElement("button");
      button.type = "button";
      button.setAttribute("aria-pressed", minutes === timelineMinutes ? "true" : "false");
      setText(button, minutes >= 60 ? (minutes / 60) + "h" : minutes + "m");
      button.addEventListener("click", function () {
        timelineMinutes = minutes;
        try { window.localStorage.setItem(WINDOW_KEY, String(minutes)); } catch (err) { /* private mode */ }
        setWindowButtons(latest);
        fetchPayload(false);
      });
      host.appendChild(button);
    });
  }

  function initControls() {
    var search = el("search");
    search.addEventListener("input", function () {
      filters.text = search.value.trim().toLowerCase();
      renderFeed(latest);
    });
    el("clear-filters").addEventListener("click", function () {
      filters = { severity: "All", rule: "All", text: "" };
      search.value = "";
      renderFeed(latest);
    });
    el("cta").addEventListener("click", function () {
      var health = el("health");
      if (health) { health.scrollIntoView({ behavior: "smooth", block: "start" }); }
    });
    initNav();
  }

  function setLink(state, text) {
    var host = el("link-state");
    var label = el("link-state-text");
    if (host) {
      host.classList.remove("live", "stale");
      if (state) { host.classList.add(state); }
    }
    if (label) { setText(label, text); }
  }

  function render(payload) {
    everLoaded = true;
    latest = payload;
    setLink("live", "live");
    renderNotice(payload);
    renderKpis(payload);
    renderPipeline(payload);
    if (window.__chartsReady) {
      renderSeverity(payload);
      renderSourceSplit(payload);
      renderTimeline(payload);
    }
    renderFeed(payload);
    setWindowButtons(payload);
    setText(el("last-updated"), localTime(payload.generated_at));
  }

  /* Server-rendered first paint uses the configured window; later polls re-request
     whatever window the viewer selected. */
  function fetchPayload(first) {
    var url = "/api/dashboard";
    if (timelineMinutes !== null) { url += "?minutes=" + timelineMinutes; }
    fetch(url, { cache: "no-store" })
      .then(function (response) { return response.json(); })
      .then(render)
      .catch(function (error) {
        setLink("stale", "reconnecting");
        if (!everLoaded) {
          var box = el("notice");
          setText(box, "Could not reach the dashboard API yet: " + error);
          box.hidden = false;
        }
      });
  }

  window.__chartsReady = applyChartDefaults();
  initControls();

  var initial = window.GRIDSNARE || {};
  render(initial);

  var seconds = Math.max(1, initial.refresh_seconds || 3);
  setText(el("refresh-every"), seconds + "s");
  window.setInterval(function () { fetchPayload(false); }, seconds * 1000);
})();
