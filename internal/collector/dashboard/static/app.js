// Expiry Radar dashboard: theme toggle, filters and sorting.
// Everything here is an enhancement; the pages work without it.
(function () {
  "use strict";
  var root = document.documentElement;
  var KEY = "er-theme";

  function stored() { try { return localStorage.getItem(KEY); } catch (e) { return null; } }
  function store(v) { try { localStorage.setItem(KEY, v); } catch (e) { /* private mode */ } }
  var t = stored();
  if (t === "dark" || t === "light") { root.setAttribute("data-theme", t); }
  root.classList.add("has-js");

  function effective() {
    var cur = root.getAttribute("data-theme");
    if (cur === "dark" || cur === "light") { return cur; }
    return window.matchMedia && window.matchMedia("(prefers-color-scheme: dark)").matches ? "dark" : "light";
  }

  function ready(fn) {
    if (document.readyState !== "loading") { fn(); } else { document.addEventListener("DOMContentLoaded", fn); }
  }

  ready(function () {
    var toggle = document.getElementById("theme-toggle");
    function label() {
      if (!toggle) { return; }
      var dark = effective() === "dark";
      toggle.textContent = dark ? "☀" : "☾";
      toggle.title = dark ? "Light theme / Tema claro" : "Dark theme / Tema escuro";
    }
    if (toggle) {
      label();
      toggle.addEventListener("click", function () {
        var next = effective() === "dark" ? "light" : "dark";
        root.setAttribute("data-theme", next);
        store(next);
        label();
      });
    }

    // Close other open menus when one opens, and on outside click.
    document.addEventListener("click", function (e) {
      document.querySelectorAll("details.menu[open]").forEach(function (d) {
        if (!d.contains(e.target)) { d.removeAttribute("open"); }
      });
    });

    var table = document.getElementById("records");
    if (!table) { return; }
    var tbody = table.tBodies[0];
    var rows = Array.prototype.slice.call(tbody.querySelectorAll("tr[data-name]"));
    var q = document.getElementById("f-q");
    var fk = document.getElementById("f-kind");
    var fs = document.getElementById("f-source");
    var fst = document.getElementById("f-state");
    var cards = document.querySelectorAll(".card[data-state]");
    var shown = document.getElementById("shown");
    var none = document.getElementById("no-match");

    function apply() {
      var text = (q.value || "").toLowerCase();
      var kind = fk.value, src = fs.value, state = fst.value, n = 0;
      rows.forEach(function (r) {
        var ok = (!kind || r.dataset.kind === kind) && (!src || r.dataset.source === src) &&
          (!state || r.dataset.state === state) &&
          (!text || (r.dataset.name + " " + r.dataset.source + " " + r.dataset.kind + " " + (r.dataset.owner || "")).toLowerCase().indexOf(text) >= 0);
        r.hidden = !ok;
        if (ok) { n++; }
      });
      cards.forEach(function (c) { c.classList.toggle("active", c.dataset.state === state); });
      if (shown) { shown.textContent = n + " / " + rows.length; }
      if (none) { none.hidden = n !== 0 || rows.length === 0; }
    }
    [q, fk, fs, fst].forEach(function (el) { el.addEventListener("input", apply); el.addEventListener("change", apply); });
    cards.forEach(function (c) {
      c.addEventListener("click", function () {
        fst.value = fst.value === c.dataset.state ? "" : c.dataset.state;
        apply();
      });
    });

    table.querySelectorAll("th[data-sort]").forEach(function (th) {
      th.classList.add("sortable");
      th.tabIndex = 0;
      function sort() {
        var key = th.dataset.sort;
        var asc = th.getAttribute("aria-sort") !== "ascending";
        table.querySelectorAll("th[data-sort]").forEach(function (o) { o.removeAttribute("aria-sort"); });
        th.setAttribute("aria-sort", asc ? "ascending" : "descending");
        rows.sort(function (a, b) {
          var x = a.dataset[key] || "", y = b.dataset[key] || "";
          if (key === "days") {
            // Records without a date stay last either way.
            if (x === "" || y === "") { return x === y ? 0 : (x === "" ? 1 : -1); }
            return (asc ? 1 : -1) * (Number(x) - Number(y));
          }
          return (asc ? 1 : -1) * x.localeCompare(y);
        });
        rows.forEach(function (r) { tbody.appendChild(r); });
        if (none) { tbody.appendChild(none); }
      }
      th.addEventListener("click", sort);
      th.addEventListener("keydown", function (e) { if (e.key === "Enter" || e.key === " ") { e.preventDefault(); sort(); } });
    });
    apply();
  });
})();
