/* App orchestration: settings persistence, event wiring, analysis pipeline,
   and progressive enrichment via MxToolbox + GeoIP once the base report
   (which never depends on the network) is already on screen. */
(function (global) {
  "use strict";
  const EHA = global.EHA || (global.EHA = {});

  const SETTINGS_KEY = "eha:settings:v1";
  let currentAnalysis = null;

  function makeId() {
    return "k" + Date.now().toString(36) + Math.random().toString(36).slice(2, 8);
  }
  function normalizeKeyEntry(k) {
    return {
      id: k.id || makeId(),
      label: k.label || "Key",
      key: k.key || "",
      exhaustedUntil: (k.exhaustedUntil && typeof k.exhaustedUntil === "object") ? k.exhaustedUntil : {},
    };
  }
  // v1 settings stored a single `apiKey` string. Newer versions store an
  // `apiKeys` array so more than one key can be configured. Transparently
  // upgrade old saved settings into the new shape on read.
  function migrateApiKeys(raw) {
    if (Array.isArray(raw.apiKeys)) return raw.apiKeys.map(normalizeKeyEntry);
    if (raw.apiKey && String(raw.apiKey).trim()) {
      return [normalizeKeyEntry({ label: "Key 1", key: raw.apiKey })];
    }
    return [];
  }

  function loadSettings() {
    let s = {};
    try { s = JSON.parse(localStorage.getItem(SETTINGS_KEY) || "{}"); } catch (e) { /* ignore corrupt value */ }
    return {
      apiKeys: migrateApiKeys(s),
      proxyBase: s.proxyBase || "",
      liveLookups: s.liveLookups !== false,
      geoip: s.geoip !== false,
      theme: s.theme || "dark",
    };
  }
  function saveSettings(patch) {
    const next = Object.assign(loadSettings(), patch);
    try { localStorage.setItem(SETTINGS_KEY, JSON.stringify(next)); } catch (e) { /* storage unavailable: settings won't persist */ }
    return next;
  }

  // ---------- analysis pipeline ----------
  function runAnalysis(rawText) {
    hideError();
    let parsed;
    try {
      parsed = EHA.parser.parseRaw(rawText);
    } catch (err) {
      showError(err.message);
      return;
    }

    try {
      const headerMap = parsed.headerMap;
      const fromAddresses = EHA.parser.parseAddressList(EHA.parser.firstValue(headerMap, "from"));
      const fromAddress = fromAddresses[0] || null;
      const toAddresses = EHA.parser.parseAddressList(EHA.parser.firstValue(headerMap, "to"));
      const ccAddresses = EHA.parser.parseAddressList(EHA.parser.firstValue(headerMap, "cc"));
      const replyToAddresses = EHA.parser.parseAddressList(EHA.parser.firstValue(headerMap, "reply-to"));
      const replyToAddress = replyToAddresses[0] || null;
      const subject = EHA.parser.firstValue(headerMap, "subject");
      const dateHeader = EHA.parser.firstValue(headerMap, "date");
      const dateParsed = EHA.parser.parseHeaderDate(dateHeader);
      const messageId = EHA.parser.firstValue(headerMap, "message-id");

      const receivedChain = EHA.parser.parseReceivedChain(headerMap);
      const hops = receivedChain.hops;
      const originatingIP = EHA.parser.findOriginatingIP(hops, headerMap);
      const authAnalysis = EHA.auth.analyze(headerMap, fromAddress);

      const ctx = {
        headerMap, hops,
        fromDomain: fromAddress ? fromAddress.domain : null,
        fromAddress, fromAddresses, replyToAddress, authAnalysis,
      };
      const espMatches = EHA.heuristics.detectESPs(ctx);
      const flags = EHA.heuristics.evaluateFlags(ctx);
      const risk = EHA.heuristics.computeRiskScore(flags);

      const analysis = {
        parsed, hops, totalSeconds: receivedChain.totalSeconds, originatingIP,
        fromAddress, fromAddresses, toAddresses, ccAddresses, replyToAddress,
        fromDomain: ctx.fromDomain, subject, dateHeader, dateParsed, messageId,
        authAnalysis, espMatches, flags, risk,
      };

      currentAnalysis = analysis;
      EHA.render.renderReport(analysis);
      const results = document.getElementById("results");
      results.hidden = false;
      results.scrollIntoView({ behavior: "smooth", block: "start" });
      switchTab("overview");

      kickOffEnrichment(analysis);
    } catch (err) {
      console.error(err);
      showError("Something went wrong analyzing these headers: " + err.message);
    }
  }

  function guessDkimArgument(analysis) {
    const sig = analysis.authAnalysis.dkimSigHeaders[0];
    const selector = sig && sig.selector;
    const domain = (sig && sig.domain) || analysis.fromDomain;
    return selector && domain ? `${domain}:${selector}` : null;
  }

  // SPF authenticates the envelope sender (Return-Path / MAIL FROM), not the
  // visible From address -- so an independent SPF check should target that
  // domain, not fromDomain. Prefer what the receiving server actually checked
  // (Authentication-Results' smtp.mailfrom), then the Return-Path header,
  // then fall back to From as a last resort.
  function guessSpfArgument(analysis) {
    const mailfrom = analysis.authAnalysis.primarySpf && analysis.authAnalysis.primarySpf.props
      ? analysis.authAnalysis.primarySpf.props["smtp.mailfrom"]
      : null;
    if (mailfrom && mailfrom.includes("@")) return mailfrom.split("@").pop().toLowerCase();
    if (analysis.authAnalysis.returnPathDomain) return analysis.authAnalysis.returnPathDomain;
    return analysis.fromDomain;
  }

  function dnsArgumentFor(cmd, analysis) {
    if (cmd === "dkim") return guessDkimArgument(analysis);
    if (cmd === "spf") return guessSpfArgument(analysis);
    return analysis.fromDomain;
  }

  function dnsDisabledReason(cmd, argument) {
    if (argument) return null;
    if (cmd === "dkim") return "No DKIM selector found in headers (MxToolbox needs domain:selector).";
    if (cmd === "spf") return "No envelope-sender or From domain detected.";
    return "No sender domain detected in these headers.";
  }

  function blacklistKey(target) {
    return `blacklist-${EHA.parser.safeDomId(target.value)}`;
  }

  async function kickOffEnrichment(analysis) {
    const settings = loadSettings();

    if (settings.geoip) {
      const ips = analysis.hops.map((h) => h.fromIP).filter((ip) => ip && !EHA.parser.isPrivateIP(ip));
      if (analysis.originatingIP && !EHA.parser.isPrivateIP(analysis.originatingIP.ip)) ips.push(analysis.originatingIP.ip);
      if (ips.length) {
        EHA.geoip.lookupMany(ips).then((map) => {
          analysis.hops.forEach((h) => { if (h.fromIP && map.get(h.fromIP)) EHA.render.renderGeoForHop(h.hopNumber, map.get(h.fromIP)); });
          if (analysis.originatingIP && map.get(analysis.originatingIP.ip)) EHA.render.renderOriginatingIPGeo(map.get(analysis.originatingIP.ip));
        });
      }
    }

    const dnsCommands = ["spf", "dkim", "dmarc", "mx", "txt"];
    const blacklistTargets = EHA.parser.collectBlacklistTargets(analysis.hops, analysis.originatingIP, [
      { value: analysis.fromDomain, label: "From domain" },
      { value: analysis.authAnalysis.returnPathDomain, label: "Return-Path domain" },
    ]);

    if (!settings.liveLookups || !settings.apiKeys.length) {
      const message = !settings.liveLookups ? "Live lookups disabled in Settings." : "Add your MxToolbox API key in Settings to run this check.";
      dnsCommands.forEach((cmd) => EHA.render.renderMxResult(cmd, { status: "disabled", message, argument: dnsArgumentFor(cmd, analysis) }));
      blacklistTargets.forEach((t) => EHA.render.renderMxResult(blacklistKey(t), { status: "disabled", message, argument: t.value }));
      return;
    }

    const config = {
      keys: settings.apiKeys,
      proxyBase: settings.proxyBase,
      // Fires when a key hits 401/429 and rotation moves to the next one.
      // The key object handed back is already mutated in place (with an
      // exhaustedUntil timestamp for a quota hit), so this just persists
      // that same array and refreshes the Settings key list if it's open.
      onKeyExhausted: () => {
        saveSettings({ apiKeys: settings.apiKeys });
        if (document.getElementById("settings-modal").open) renderApiKeysList();
      },
    };

    dnsCommands.forEach(async (cmd) => {
      const argument = dnsArgumentFor(cmd, analysis);
      const disabledReason = dnsDisabledReason(cmd, argument);
      if (disabledReason) {
        EHA.render.renderMxResult(cmd, { status: "disabled", message: disabledReason });
        return;
      }
      EHA.render.renderMxResult(cmd, { status: "loading", argument });
      try {
        const data = await EHA.mxtoolbox.lookup(config, cmd, argument);
        EHA.render.renderMxResult(cmd, { status: "success", data, argument });
      } catch (err) {
        EHA.render.renderMxResult(cmd, { status: "error", message: err.message, argument });
      }
    });

    blacklistTargets.forEach(async (t) => {
      const key = blacklistKey(t);
      EHA.render.renderMxResult(key, { status: "loading", argument: t.value });
      try {
        const data = await EHA.mxtoolbox.lookup(config, "blacklist", t.value);
        EHA.render.renderMxResult(key, { status: "success", data, argument: t.value });
      } catch (err) {
        EHA.render.renderMxResult(key, { status: "error", message: err.message, argument: t.value });
      }
    });

    refreshQuotaPill(settings);
  }

  // ---------- API key list UI ----------
  function quotaBadgeText(entry) {
    const now = Date.now();
    const dnsEx = entry.exhaustedUntil && entry.exhaustedUntil.dns > now;
    const netEx = entry.exhaustedUntil && entry.exhaustedUntil.network > now;
    if (dnsEx && netEx) return "DNS + Network quota hit today";
    if (dnsEx) return "DNS quota hit today";
    if (netEx) return "Network quota hit today";
    return "";
  }

  function apiKeyRow(entry, idx) {
    const el = EHA.util.el;
    const labelInput = el("input", { type: "text", class: "key-label-input", value: entry.label, placeholder: `Key ${idx + 1}`, "aria-label": "Key label" });
    const keyInput = el("input", { type: "password", class: "key-value-input", value: entry.key, placeholder: "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx", "aria-label": "API key value", autocomplete: "off" });
    const toggleBtn = el("button", { type: "button", class: "btn btn-ghost btn-sm" }, ["Show"]);
    toggleBtn.addEventListener("click", () => {
      const showing = keyInput.type === "text";
      keyInput.type = showing ? "password" : "text";
      toggleBtn.textContent = showing ? "Show" : "Hide";
    });
    const quotaBadge = el("span", { class: "key-quota", id: `key-quota-${entry.id}` }, [quotaBadgeText(entry)]);
    const removeBtn = el("button", { type: "button", class: "icon-btn", "aria-label": "Remove key", title: "Remove key" }, ["✕"]);
    removeBtn.addEventListener("click", () => {
      const s = loadSettings();
      saveSettings({ apiKeys: s.apiKeys.filter((k) => k.id !== entry.id) });
      renderApiKeysList();
      EHA.util.toast("Key removed");
    });

    const persist = EHA.util.debounce(() => {
      const s = loadSettings();
      const target = s.apiKeys.find((k) => k.id === entry.id);
      if (!target) return;
      target.label = labelInput.value.trim() || `Key ${idx + 1}`;
      target.key = keyInput.value.trim();
      saveSettings({ apiKeys: s.apiKeys });
    }, 300);
    labelInput.addEventListener("input", persist);
    keyInput.addEventListener("input", persist);

    return el("div", { class: "api-key-row" }, [labelInput, keyInput, toggleBtn, quotaBadge, removeBtn]);
  }

  function renderApiKeysList() {
    const container = document.getElementById("api-keys-list");
    if (!container) return;
    const settings = loadSettings();
    if (!settings.apiKeys.length) {
      container.replaceChildren(EHA.util.el("div", { class: "api-keys-empty" }, ["No API keys added yet — live MxToolbox lookups are off until you add one."]));
      return;
    }
    container.replaceChildren(...settings.apiKeys.map(apiKeyRow));
  }

  // ---------- settings UI ----------
  function initSettingsUI() {
    const settings = loadSettings();
    const proxyInput = document.getElementById("proxy-input");
    const liveToggle = document.getElementById("toggle-live-lookups");
    const geoToggle = document.getElementById("toggle-geoip");

    proxyInput.value = settings.proxyBase;
    liveToggle.checked = settings.liveLookups;
    geoToggle.checked = settings.geoip;
    renderApiKeysList();

    // Save as the user types (debounced) rather than only on blur/change --
    // closing the <dialog> via its submit button can skip a trailing
    // `change` event, which previously made the proxy URL look like it
    // hadn't saved. The dialog's `close` handler below is a second safety
    // net that flushes current field values regardless of how it closed.
    const persistProxy = EHA.util.debounce(() => saveSettings({ proxyBase: proxyInput.value.trim() }), 300);
    proxyInput.addEventListener("input", persistProxy);
    liveToggle.addEventListener("change", () => saveSettings({ liveLookups: liveToggle.checked }));
    geoToggle.addEventListener("change", () => saveSettings({ geoip: geoToggle.checked }));

    const modal = document.getElementById("settings-modal");
    modal.addEventListener("close", () => {
      saveSettings({ proxyBase: proxyInput.value.trim(), liveLookups: liveToggle.checked, geoip: geoToggle.checked });
    });

    document.getElementById("btn-settings").addEventListener("click", () => {
      renderApiKeysList();
      modal.showModal();
    });

    document.getElementById("btn-add-key").addEventListener("click", () => {
      const s = loadSettings();
      const newEntry = normalizeKeyEntry({ label: `Key ${s.apiKeys.length + 1}`, key: "" });
      saveSettings({ apiKeys: [...s.apiKeys, newEntry] });
      renderApiKeysList();
      const inputs = document.querySelectorAll("#api-keys-list .key-value-input");
      const last = inputs[inputs.length - 1];
      if (last) last.focus();
    });

    document.getElementById("btn-reset-settings").addEventListener("click", () => {
      localStorage.removeItem(SETTINGS_KEY);
      localStorage.removeItem("eha:mx:cache:v1");
      localStorage.removeItem("eha:geoip:cache:v1");
      proxyInput.value = ""; liveToggle.checked = true; geoToggle.checked = true;
      renderApiKeysList();
      document.getElementById("quota-pill").hidden = true;
      EHA.util.toast("Settings and caches cleared");
    });

    document.getElementById("btn-refresh-usage").addEventListener("click", async () => {
      const s = loadSettings();
      if (!s.apiKeys.length) { EHA.util.toast("Add an API key first."); return; }
      const btn = document.getElementById("btn-refresh-usage");
      btn.disabled = true;
      btn.textContent = "Checking…";
      await Promise.all(s.apiKeys.map(async (entry, idx) => {
        const badge = document.getElementById(`key-quota-${entry.id}`);
        if (!entry.key.trim()) return;
        try {
          const data = await EHA.mxtoolbox.usageForKey(entry.key.trim(), s.proxyBase);
          if (badge) badge.textContent = `DNS ${data.DnsRequests}/${data.DnsMax} · Net ${data.NetworkRequests}/${data.NetworkMax}`;
          if (idx === 0) updateQuotaPill(data);
        } catch (err) {
          if (badge) badge.textContent = "Check failed";
        }
      }));
      btn.disabled = false;
      btn.textContent = "Check Quota (all keys)";
    });
  }

  function updateQuotaPill(usageData) {
    const pillEl = document.getElementById("quota-pill");
    if (!usageData) { pillEl.hidden = true; return; }
    pillEl.hidden = false;
    pillEl.textContent = `MxToolbox DNS ${usageData.DnsRequests}/${usageData.DnsMax}`;
  }

  async function refreshQuotaPill(settings) {
    const first = settings.apiKeys[0];
    if (!first || !first.key) return;
    try {
      const data = await EHA.mxtoolbox.usageForKey(first.key, settings.proxyBase);
      updateQuotaPill(data);
    } catch (e) { /* non-critical background check */ }
  }

  function initTheme() {
    const settings = loadSettings();
    document.body.dataset.theme = settings.theme;
    document.getElementById("btn-theme").addEventListener("click", () => {
      const next = document.body.dataset.theme === "dark" ? "light" : "dark";
      document.body.dataset.theme = next;
      saveSettings({ theme: next });
    });
  }

  function initHowto() {
    const btn = document.getElementById("btn-howto");
    const panel = document.getElementById("howto-panel");
    btn.addEventListener("click", () => {
      const expanded = btn.getAttribute("aria-expanded") === "true";
      btn.setAttribute("aria-expanded", String(!expanded));
      panel.hidden = expanded;
    });
  }

  function initFileInput() {
    const textarea = document.getElementById("header-input");
    const fileInput = document.getElementById("file-input");
    const dropzone = document.getElementById("dropzone");

    function readFileIntoTextarea(file) {
      if (file.size > 5 * 1024 * 1024) { showError("File is too large (max 5 MB)."); return; }
      const reader = new FileReader();
      reader.onload = () => { textarea.value = String(reader.result); EHA.util.toast(`Loaded ${file.name}`); };
      reader.onerror = () => showError("Could not read that file.");
      reader.readAsText(file);
    }

    fileInput.addEventListener("change", () => {
      const file = fileInput.files[0];
      if (file) readFileIntoTextarea(file);
      fileInput.value = "";
    });

    ["dragenter", "dragover"].forEach((evt) => dropzone.addEventListener(evt, (e) => { e.preventDefault(); dropzone.classList.add("is-dragover"); }));
    ["dragleave", "drop"].forEach((evt) => dropzone.addEventListener(evt, (e) => { e.preventDefault(); dropzone.classList.remove("is-dragover"); }));
    dropzone.addEventListener("drop", (e) => {
      const file = e.dataTransfer.files && e.dataTransfer.files[0];
      if (file) readFileIntoTextarea(file);
    });
  }

  function switchTab(key) {
    document.querySelectorAll(".tab-btn").forEach((b) => b.classList.toggle("is-active", b.dataset.tab === key));
    document.querySelectorAll(".report-section").forEach((s) => s.classList.toggle("is-active", s.id === `sec-${key}`));
  }

  function initTabs() {
    document.getElementById("report-tabs").addEventListener("click", (e) => {
      const btn = e.target.closest(".tab-btn");
      if (btn) switchTab(btn.dataset.tab);
    });
    EHA.render.setTabSwitcher(switchTab);
  }

  function showError(msg) {
    const node = document.getElementById("parse-error");
    node.textContent = msg;
    node.hidden = false;
  }
  function hideError() {
    const node = document.getElementById("parse-error");
    node.hidden = true;
    node.textContent = "";
  }

  function initActions() {
    const textarea = document.getElementById("header-input");
    document.getElementById("btn-analyze").addEventListener("click", () => runAnalysis(textarea.value));
    document.getElementById("btn-clear").addEventListener("click", () => {
      textarea.value = "";
      document.getElementById("results").hidden = true;
      hideError();
      textarea.focus();
    });
    document.getElementById("btn-sample").addEventListener("click", () => {
      textarea.value = EHA.SAMPLE_HEADERS;
      EHA.util.toast("Sample headers loaded");
    });
    textarea.addEventListener("keydown", (e) => {
      if ((e.ctrlKey || e.metaKey) && e.key === "Enter") {
        e.preventDefault();
        runAnalysis(textarea.value);
      }
    });
  }

  document.addEventListener("DOMContentLoaded", () => {
    initTheme();
    initSettingsUI();
    initHowto();
    initFileInput();
    initTabs();
    initActions();
    const settings = loadSettings();
    if (settings.apiKeys.length) refreshQuotaPill(settings);
  });

  EHA.app = { runAnalysis, loadSettings, saveSettings };
})(window);
