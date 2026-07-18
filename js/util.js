/* Shared utilities. Attaches to window.EHA namespace. */
(function (global) {
  "use strict";
  const EHA = global.EHA || (global.EHA = {});

  function escapeHtml(str) {
    if (str === null || str === undefined) return "";
    return String(str)
      .replace(/&/g, "&amp;")
      .replace(/</g, "&lt;")
      .replace(/>/g, "&gt;")
      .replace(/"/g, "&quot;")
      .replace(/'/g, "&#39;");
  }

  // Build a DOM element safely from static tag/props/children (no HTML string parsing).
  function el(tag, props, children) {
    const node = document.createElement(tag);
    if (props) {
      for (const [k, v] of Object.entries(props)) {
        if (v === null || v === undefined || v === false) continue;
        if (k === "class") node.className = v;
        else if (k === "text") node.textContent = v;
        else if (k === "html") node.innerHTML = v; // only ever called with our own trusted static markup
        else if (k.startsWith("on") && typeof v === "function") node.addEventListener(k.slice(2), v);
        else if (k === "dataset") { for (const [dk, dv] of Object.entries(v)) node.dataset[dk] = dv; }
        else node.setAttribute(k, v);
      }
    }
    (children || []).forEach((c) => {
      if (c === null || c === undefined || c === false) return;
      node.appendChild(typeof c === "string" ? document.createTextNode(c) : c);
    });
    return node;
  }

  function formatDuration(seconds) {
    if (seconds === null || seconds === undefined || isNaN(seconds)) return "—";
    const sign = seconds < 0 ? "-" : "";
    seconds = Math.abs(Math.round(seconds));
    if (seconds < 60) return `${sign}${seconds}s`;
    const m = Math.floor(seconds / 60);
    const s = seconds % 60;
    if (m < 60) return `${sign}${m}m ${s}s`;
    const h = Math.floor(m / 60);
    const mm = m % 60;
    if (h < 24) return `${sign}${h}h ${mm}m`;
    const d = Math.floor(h / 24);
    const hh = h % 24;
    return `${sign}${d}d ${hh}h`;
  }

  function formatDateUTC(date) {
    if (!date) return null;
    return date.toISOString().replace("T", " ").replace(/\.\d+Z$/, " UTC");
  }

  function formatDateLocal(date) {
    if (!date) return null;
    try {
      return new Intl.DateTimeFormat(undefined, {
        dateStyle: "medium", timeStyle: "medium",
      }).format(date);
    } catch (e) {
      return date.toString();
    }
  }

  function debounce(fn, wait) {
    let t;
    return function (...args) {
      clearTimeout(t);
      t = setTimeout(() => fn.apply(this, args), wait);
    };
  }

  function copyToClipboard(text) {
    if (navigator.clipboard && window.isSecureContext) {
      return navigator.clipboard.writeText(text);
    }
    return new Promise((resolve, reject) => {
      try {
        const ta = document.createElement("textarea");
        ta.value = text;
        ta.style.position = "fixed";
        ta.style.opacity = "0";
        document.body.appendChild(ta);
        ta.select();
        document.execCommand("copy");
        document.body.removeChild(ta);
        resolve();
      } catch (e) {
        reject(e);
      }
    });
  }

  function toast(message, ms = 2200) {
    let node = document.querySelector(".toast");
    if (!node) {
      const tpl = document.getElementById("tpl-toast");
      node = tpl ? tpl.content.firstElementChild.cloneNode(true) : el("div", { class: "toast" });
      document.body.appendChild(node);
    }
    node.textContent = message;
    node.classList.add("is-visible");
    clearTimeout(node._timer);
    node._timer = setTimeout(() => node.classList.remove("is-visible"), ms);
  }

  function safeHostname(url) {
    try { return new URL(url).hostname; } catch (e) { return null; }
  }

  EHA.util = { escapeHtml, el, formatDuration, formatDateUTC, formatDateLocal, debounce, copyToClipboard, toast, safeHostname };
})(window);
