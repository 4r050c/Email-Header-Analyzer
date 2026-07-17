/* Renders the analysis object into the report DOM. All header-derived text
   goes through the DOM as text nodes (via util.el's `text`/children path) --
   never through innerHTML -- so hostile header content can't execute as HTML. */
(function (global) {
  "use strict";
  const EHA = global.EHA || (global.EHA = {});
  const { el, escapeHtml } = EHA.util;

  const ICONS = {
    copy: '<svg viewBox="0 0 24 24" width="12" height="12" aria-hidden="true"><path fill="currentColor" d="M16 1H4a2 2 0 0 0-2 2v14h2V3h12V1Zm3 4H8a2 2 0 0 0-2 2v14a2 2 0 0 0 2 2h11a2 2 0 0 0 2-2V7a2 2 0 0 0-2-2Zm0 16H8V7h11v14Z"/></svg>',
    download: '<svg viewBox="0 0 24 24" width="12" height="12" aria-hidden="true"><path fill="currentColor" d="M12 16 6 10l1.4-1.4L11 12.2V3h2v9.2l3.6-3.6L18 10l-6 6Zm-7 4v-2h14v2H5Z"/></svg>',
  };

  let tabSwitcher = () => {};
  function setTabSwitcher(fn) { tabSwitcher = fn; }

  // ---------- small shared builders ----------
  function toneClass(sev) {
    return { good: "good", warning: "warning", serious: "serious", critical: "critical", neutral: "neutral", info: "neutral" }[sev] || "neutral";
  }
  function pill(text, tone) {
    return el("span", { class: `pill pill-${tone}` }, [el("span", { class: "pill-dot" }), text]);
  }
  function copyBtn(getText) {
    return el("button", {
      class: "copy-btn", type: "button", "aria-label": "Copy", title: "Copy", html: ICONS.copy,
      onclick: (e) => {
        e.preventDefault();
        const text = typeof getText === "function" ? getText() : getText;
        EHA.util.copyToClipboard(text).then(() => EHA.util.toast("Copied to clipboard"));
      },
    });
  }
  function downloadBtn(filename, getText) {
    return el("button", {
      class: "copy-btn", type: "button", "aria-label": "Download", title: "Download", html: ICONS.download,
      onclick: (e) => {
        e.preventDefault();
        const text = typeof getText === "function" ? getText() : getText;
        triggerDownload(filename, text, "text/plain");
      },
    });
  }
  function triggerDownload(filename, text, mime) {
    const blob = new Blob([text], { type: mime || "text/plain" });
    const url = URL.createObjectURL(blob);
    const link = document.createElement("a");
    link.href = url;
    link.download = filename;
    document.body.appendChild(link);
    link.click();
    document.body.removeChild(link);
    URL.revokeObjectURL(url);
  }

  function kvRow(label, text, opts) {
    if (text === null || text === undefined || text === "") return null;
    const children = [el("span", {}, [String(text)])];
    if (opts && opts.copy) children.push(copyBtn(String(text)));
    return el("tr", {}, [el("th", {}, [label]), el("td", { class: "copyable" }, children)]);
  }

  function formatAddressList(list) {
    if (!list || !list.length) return null;
    return list.map((a) => (a.name ? `${a.name} <${a.email}>` : a.email)).join(", ");
  }

  function flagItemNode(f) {
    const icon = { critical: "!", serious: "!", warning: "i", info: "i", good: "✓" }[f.severity] || "i";
    return el("div", { class: "flag-item" }, [
      el("div", { class: `flag-icon sev-${f.severity}` }, [icon]),
      el("div", {}, [
        el("div", { class: "flag-title" }, [f.title]),
        el("div", { class: "flag-desc" }, [f.description]),
        f.evidence ? el("div", { class: "flag-evidence" }, [f.evidence]) : null,
      ].filter(Boolean)),
    ]);
  }

  // ---------- summary banner ----------
  function summaryCell(label, ...content) {
    return el("div", { class: "summary-cell" }, [el("div", { class: "label" }, [label]), ...content.filter(Boolean)]);
  }

  function riskCell(risk, flagCount) {
    const r = 22, c = 2 * Math.PI * r;
    const pct = Math.max(0, Math.min(1, risk.score / 100));
    const svgNS = "http://www.w3.org/2000/svg";
    const svg = document.createElementNS(svgNS, "svg");
    svg.setAttribute("viewBox", "0 0 52 52"); svg.setAttribute("width", "52"); svg.setAttribute("height", "52");
    const track = document.createElementNS(svgNS, "circle");
    track.setAttribute("class", "risk-ring-track"); track.setAttribute("cx", "26"); track.setAttribute("cy", "26"); track.setAttribute("r", String(r));
    const val = document.createElementNS(svgNS, "circle");
    val.setAttribute("class", "risk-ring-value"); val.setAttribute("cx", "26"); val.setAttribute("cy", "26"); val.setAttribute("r", String(r));
    val.setAttribute("stroke-dasharray", String(c));
    val.setAttribute("stroke-dashoffset", String(c * (1 - pct)));
    const colorVar = { low: "var(--status-good)", medium: "var(--status-warning)", high: "var(--status-serious)", critical: "var(--status-critical)" }[risk.band] || "var(--series-1)";
    val.style.setProperty("--risk-color", colorVar);
    svg.appendChild(track); svg.appendChild(val);
    const ring = el("div", { class: "risk-ring" }, [svg, el("div", { class: "risk-ring-num" }, [String(risk.score)])]);
    const toneCls = { low: "text-good", medium: "text-warning", high: "text-serious", critical: "text-critical" }[risk.band] || "";
    const label = el("div", {}, [
      el("div", { class: `value cap ${toneCls}` }, [`${risk.band} risk`]),
      el("div", { class: "sub" }, [`${flagCount} signal${flagCount === 1 ? "" : "s"}`]),
    ]);
    return el("div", { class: "summary-cell" }, [el("div", { class: "label" }, ["Risk Assessment"]), el("div", { class: "risk-cell" }, [ring, label])]);
  }

  function authQuickPills(auth) {
    const mk = (label, entry) => pill(`${label}: ${entry ? entry.result : "n/a"}`, toneClass(EHA.auth.severityFor(entry ? entry.result : null)));
    return el("div", { class: "badge-row" }, [mk("SPF", auth.primarySpf), mk("DKIM", auth.primaryDkim), mk("DMARC", auth.primaryDmarc)]);
  }

  function renderSummaryBanner(a) {
    const banner = document.getElementById("summary-banner");
    const fromText = a.fromAddress ? (a.fromAddress.name || a.fromAddress.email) : "—";
    const fromSub = a.fromAddress && a.fromAddress.name ? a.fromAddress.email : (a.fromDomain || "");
    const ipNode = el("div", { class: "value mono", id: "summary-origip-value" }, [a.originatingIP ? a.originatingIP.ip : "Unknown"]);
    const ipSub = el("div", { class: "sub", id: "summary-origip-geo" }, [a.originatingIP ? a.originatingIP.source : "No Received headers to trace"]);

    const cells = [
      riskCell(a.risk, a.flags.length),
      summaryCell("Authentication", authQuickPills(a.authAnalysis)),
      summaryCell("From", el("div", { class: "value" }, [fromText]), fromSub ? el("div", { class: "sub mono" }, [fromSub]) : null),
      summaryCell("Subject", el("div", { class: "value" }, [a.subject || "(no subject)"])),
      summaryCell("Sent", el("div", { class: "value" }, [a.dateParsed ? EHA.util.formatDateLocal(a.dateParsed) : (a.dateHeader || "—")])),
      summaryCell("Relay Hops", el("div", { class: "value" }, [String(a.hops.length)]),
        el("div", { class: "sub" }, [a.totalSeconds != null ? `Total transit ${EHA.util.formatDuration(a.totalSeconds)}` : "Transit time unknown"])),
      summaryCell("Originating IP", ipNode, ipSub),
      summaryCell("Sending Platform", el("div", { class: "value" }, [a.espMatches.length ? a.espMatches.join(", ") : "Not fingerprinted"])),
    ];
    banner.replaceChildren(...cells);
  }

  // ---------- overview ----------
  function messageDetailsTable(a) {
    const rows = [
      kvRow("From", formatAddressList(a.fromAddresses), { copy: true }),
      kvRow("To", formatAddressList(a.toAddresses)),
      kvRow("Cc", formatAddressList(a.ccAddresses)),
      kvRow("Reply-To", formatAddressList(a.replyToAddress ? [a.replyToAddress] : null)),
      kvRow("Return-Path", EHA.parser.firstValue(a.parsed.headerMap, "return-path")),
      kvRow("Subject", a.subject),
      kvRow("Date", a.dateHeader),
      kvRow("Message-ID", a.messageId, { copy: true }),
      kvRow("MIME-Version", EHA.parser.firstValue(a.parsed.headerMap, "mime-version")),
      kvRow("Content-Type", EHA.parser.firstValue(a.parsed.headerMap, "content-type")),
      kvRow("X-Mailer / User-Agent", EHA.parser.firstValue(a.parsed.headerMap, "x-mailer") || EHA.parser.firstValue(a.parsed.headerMap, "user-agent")),
    ].filter(Boolean);
    return el("table", { class: "kv-table" }, rows.length ? rows : [el("tr", {}, [el("td", {}, ["No standard headers found."])])]);
  }

  function deliverySummaryTable(a) {
    const rows = [
      kvRow("Originating IP", a.originatingIP ? a.originatingIP.ip : null, { copy: !!a.originatingIP }),
      kvRow("IP Source", a.originatingIP ? a.originatingIP.source : null),
      kvRow("Relay Hops", String(a.hops.length)),
      kvRow("Total Transit Time", a.totalSeconds != null ? EHA.util.formatDuration(a.totalSeconds) : "Unknown"),
      kvRow("Detected Sending Platform(s)", a.espMatches.length ? a.espMatches.join(", ") : "None matched"),
    ].filter(Boolean);
    return el("table", { class: "kv-table" }, rows);
  }

  function flagsPreviewList(flags) {
    if (!flags.length) return el("div", { class: "empty-state good" }, ["No red flags detected from header analysis."]);
    return el("div", {}, EHA.heuristics.sortFlags(flags).slice(0, 3).map(flagItemNode));
  }

  function renderOverview(a) {
    const root = document.getElementById("sec-overview");
    const details = el("div", { class: "card" }, [
      el("div", { class: "card-title" }, [el("h3", {}, ["Message Details"])]),
      messageDetailsTable(a),
    ]);
    const delivery = el("div", { class: "card" }, [
      el("div", { class: "card-title" }, [el("h3", {}, ["Delivery Summary"])]),
      deliverySummaryTable(a),
    ]);
    const flagsPreview = el("div", { class: "card" }, [
      el("div", { class: "card-title" }, [
        el("h3", {}, ["Top Security Signals"]),
        a.flags.length ? el("button", { class: "link-btn", type: "button", onclick: () => tabSwitcher("security") }, ["View all →"]) : null,
      ].filter(Boolean)),
      flagsPreviewList(a.flags),
    ]);
    root.replaceChildren(el("div", { class: "grid-2" }, [details, delivery]), flagsPreview);
  }

  // ---------- hops ----------
  function metaItem(label, value) {
    return el("span", {}, [el("b", {}, [label + ": "]), value]);
  }

  function hopNode(hop) {
    const delayClass = hop.delaySeconds == null ? "" : hop.delaySeconds >= 3600 ? "d-bad" : hop.delaySeconds >= 300 ? "d-warn" : "d-ok";
    const route = el("div", { class: "hop-route" }, [
      hop.fromHost || hop.fromIP || hop.fromRaw || "unknown",
      el("span", { class: "arrow" }, ["→"]),
      hop.byHost || "unknown",
    ]);
    const metaItems = [];
    if (hop.fromIP) metaItems.push(metaItem("IP", hop.fromIP));
    if (hop.protocol) metaItems.push(metaItem("Protocol", hop.protocol));
    if (hop.id) metaItems.push(metaItem("ID", hop.id));
    if (hop.forAddr) metaItems.push(metaItem("For", hop.forAddr));
    if (hop.timestamp) metaItems.push(metaItem("Time (UTC)", EHA.util.formatDateUTC(hop.timestamp)));
    if (hop.delaySeconds != null) metaItems.push(el("span", { class: `hop-delay ${delayClass}` }, [`+${EHA.util.formatDuration(hop.delaySeconds)}`]));
    const geo = el("div", { class: "hop-geo", id: `hop-geo-${hop.hopNumber}` }, [hop.fromPrivate && hop.fromIP ? "Private/reserved IP range" : ""]);
    const rawDetails = el("details", { class: "hop-raw" }, [el("summary", {}, ["Raw header"]), el("pre", {}, [hop.raw])]);
    const dot = el("div", { class: "hop-dot" }, [String(hop.hopNumber)]);
    const card = el("div", { class: "hop-card" }, [el("div", { class: "hop-head" }, [route]), el("div", { class: "hop-meta" }, metaItems), geo, rawDetails]);
    return el("div", { class: "hop" }, [dot, card]);
  }

  function renderHops(a) {
    const root = document.getElementById("sec-hops");
    const body = a.hops.length
      ? el("div", { class: "timeline" }, a.hops.map(hopNode))
      : el("div", { class: "empty-state" }, ["No Received headers were found in this message."]);
    const card = el("div", { class: "card" }, [
      el("div", { class: "card-title" }, [el("h3", {}, ["Relay Path"]), el("span", { class: "muted" }, [`${a.hops.length} hop${a.hops.length === 1 ? "" : "s"}`])]),
      el("p", { class: "card-desc" }, ["Reconstructed from Received headers, oldest (sender) to newest (final delivery). Delay is the time elapsed since the previous hop."]),
      body,
    ]);
    root.replaceChildren(card);
  }

  // ---------- authentication ----------
  function propRow(label, value) {
    if (!value) return null;
    return `${label}: ${value}`;
  }

  function mechRow(entry, propsFn, align) {
    const sev = EHA.auth.severityFor(entry.result);
    const rows = propsFn(entry).filter(Boolean);
    const alignNode = align && align.aligned !== null && align.aligned !== undefined
      ? el("div", { class: `align-badge ${align.aligned ? "text-good" : "text-critical"}` }, [align.aligned ? `✓ Aligned with From domain (${align.mode})` : "✗ Not aligned with From domain"])
      : null;
    return el("div", { class: "auth-mech" }, [
      el("div", { class: "auth-mech-badge" }, [pill(entry.result || "n/a", toneClass(sev))]),
      el("div", { class: "auth-mech-body" }, [...rows.map((r) => el("div", { class: "auth-mech-detail" }, [r])), alignNode].filter(Boolean)),
    ]);
  }

  function mechCard(title, desc, entries, propsFn, getAlignFn) {
    const body = entries.length
      ? entries.map((e, i) => mechRow(e, propsFn, getAlignFn ? getAlignFn(e, i) : null))
      : [el("div", { class: "empty-state" }, ["Not present in these headers."])];
    return el("div", { class: "card" }, [el("div", { class: "card-title" }, [el("h3", {}, [title])]), el("p", { class: "card-desc" }, [desc]), ...body]);
  }

  function dkimSignatureCard(sigs) {
    if (!sigs.length) {
      return el("div", { class: "card" }, [el("div", { class: "card-title" }, [el("h3", {}, ["DKIM-Signature Headers"])]), el("div", { class: "empty-state" }, ["No DKIM-Signature header present."])]);
    }
    const trunc = (s, n) => (s ? (s.length > n ? s.slice(0, n) + "…" : s) : "—");
    const rows = sigs.map((s, i) => el("div", { class: "auth-mech" }, [
      el("div", { class: "auth-mech-badge" }, [el("span", { class: "tag" }, [`#${i + 1}`])]),
      el("div", { class: "auth-mech-body" }, [
        el("div", { class: "auth-mech-detail" }, [`d=${s.domain || "—"}  s=${s.selector || "—"}  a=${s.algorithm || "—"}  c=${s.canonicalization || "—"}`]),
        el("div", { class: "auth-mech-detail" }, [`h=${s.headerList.join(":") || "—"}`]),
        el("div", { class: "auth-mech-detail" }, [`bh=${trunc(s.bodyHash, 28)}`]),
        el("div", { class: "auth-mech-detail" }, [`b=${trunc(s.signature, 28)}`]),
      ]),
    ]));
    return el("div", { class: "card" }, [
      el("div", { class: "card-title" }, [el("h3", {}, ["DKIM-Signature Headers"])]),
      el("p", { class: "card-desc" }, ["Raw signature tags as sent. This tool reports the signature's claims but does not recompute the cryptographic signature itself."]),
      ...rows,
    ]);
  }

  function mxPlaceholder(command) {
    return el("div", { class: "mx-subcard", id: `mx-card-${command}` }, [
      el("div", { class: "mx-card-head" }, [el("h4", {}, [EHA.mxtoolbox.COMMAND_LABELS[command] || command])]),
      el("div", { id: `mx-body-${command}` }, [el("div", { class: "empty-state" }, ["Not run. Enable live lookups and an API key in Settings."])]),
    ]);
  }

  function liveDnsCard(a) {
    const commands = ["spf", "dkim", "dmarc", "mx", "txt"];
    const grid = el("div", { class: "grid-3" }, commands.map(mxPlaceholder));
    return el("div", { class: "card", id: "card-live-dns" }, [
      el("div", { class: "card-title" }, [el("h3", {}, ["Live DNS Validation"]), el("span", { class: "muted" }, ["via MxToolbox API"])]),
      el("p", { class: "card-desc" }, ["Independent DNS lookups, separate from what the headers claim. SPF checks the envelope-sender (Return-Path) domain — the domain SPF actually authenticates; DKIM/DMARC/MX/TXT check the visible From domain. Each card shows exactly what it queried."]),
      grid,
    ]);
  }

  function blacklistTargetSubcard(target) {
    const safeId = EHA.parser.safeDomId(target.value);
    return el("div", { class: "mx-subcard", id: `mx-card-blacklist-${safeId}` }, [
      el("div", { class: "mx-card-head" }, [el("h4", {}, [target.value]), el("span", { class: "muted" }, [target.label])]),
      el("div", { id: `mx-body-blacklist-${safeId}` }, [el("div", { class: "empty-state" }, ["Not run. Enable live lookups and an API key in Settings."])]),
    ]);
  }

  function liveBlacklistCard(a) {
    const targets = EHA.parser.collectBlacklistTargets(a.hops, a.originatingIP, [
      { value: a.fromDomain, label: "From domain" },
      { value: a.authAnalysis.returnPathDomain, label: "Return-Path domain" },
    ]);
    const body = targets.length
      ? el("div", { class: "grid-2" }, targets.map(blacklistTargetSubcard))
      : el("div", { class: "empty-state" }, ["No public IP address or sender domain detected to check."]);
    return el("div", { class: "card", id: "card-blacklist" }, [
      el("div", { class: "card-title" }, [el("h3", {}, ["Blacklist Check"]), el("span", { class: "muted" }, ["via MxToolbox API"])]),
      el("p", { class: "card-desc" }, ["Checks every public relay IP in the chain, plus the sender's domain(s), against DNS blacklists. Note: this is MxToolbox's \"Network\" quota — free accounts typically get 0 Network requests/day, so this needs a paid plan."]),
      body,
    ]);
  }

  function renderAuth(a) {
    const root = document.getElementById("sec-auth");
    const auth = a.authAnalysis;
    const spfCard = mechCard(
      "SPF (Sender Policy Framework)",
      "Verifies the sending server's IP is authorized to send for the envelope-from domain.",
      auth.spfEntries,
      (e) => [propRow("Result", e.result), propRow("MAIL FROM", e.props["smtp.mailfrom"]), propRow("HELO", e.props["smtp.helo"]), propRow("Source", e.source), propRow("Detail", e.comment)],
      () => auth.spfAlign
    );
    const dkimCard = mechCard(
      "DKIM (DomainKeys Identified Mail)",
      "Verifies a cryptographic signature added by the sending domain, as evaluated by the receiving server.",
      auth.dkimEntries,
      (e) => [propRow("Result", e.result), propRow("Signing Domain (d=)", e.props["header.d"]), propRow("Identity (i=)", e.props["header.i"]), propRow("Selector (s=)", e.props["header.s"]), propRow("Source", e.source), propRow("Detail", e.comment)],
      (e, i) => auth.dkimAlignResults[i]
    );
    const dmarcCard = mechCard(
      "DMARC (Domain-based Message Authentication)",
      "Policy check tying SPF/DKIM results to the visible From domain, as evaluated by the receiving server.",
      auth.dmarcEntries,
      (e) => [propRow("Result", e.result), propRow("From Domain", e.props["header.from"]), propRow("Source", e.source), propRow("Detail", e.comment)],
      null
    );
    root.replaceChildren(spfCard, dkimCard, dmarcCard, dkimSignatureCard(auth.dkimSigHeaders), liveDnsCard(a), liveBlacklistCard(a));
  }

  // ---------- security ----------
  function renderSecurity(a) {
    const root = document.getElementById("sec-security");
    const espCard = el("div", { class: "card" }, [
      el("div", { class: "card-title" }, [el("h3", {}, ["Detected Sending Platform"])]),
      el("p", { class: "card-desc" }, ["Best-effort fingerprinting from known header/hostname signatures. No match doesn't imply anything is wrong."]),
      a.espMatches.length
        ? el("div", { class: "badge-row" }, a.espMatches.map((name) => el("span", { class: "tag" }, [name])))
        : el("div", { class: "empty-state" }, ["No known ESP/mailbox provider signature matched."]),
    ]);
    const sorted = EHA.heuristics.sortFlags(a.flags);
    const flagsCard = el("div", { class: "card" }, [
      el("div", { class: "card-title" }, [el("h3", {}, ["Red Flags & Signals"]), el("span", { class: "muted" }, [`${a.flags.length} found`])]),
      el("p", { class: "card-desc" }, ["Heuristic analysis of header contents only. These are signals to investigate, not a verdict."]),
      sorted.length ? el("div", {}, sorted.map(flagItemNode)) : el("div", { class: "empty-state good" }, ["No red flags detected from header analysis."]),
    ]);
    root.replaceChildren(espCard, flagsCard);
  }

  // ---------- headers table ----------
  function headerRow(h, idx) {
    const tr = el("tr", {}, [el("td", {}, [String(idx + 1)]), el("td", { class: "col-name" }, [h.name]), el("td", { class: "col-value" }, [h.value])]);
    tr.dataset.search = (h.name + " " + h.value).toLowerCase();
    return tr;
  }

  function filterHeadersTable(total, query) {
    const q = query.trim().toLowerCase();
    const tbody = document.getElementById("headers-tbody");
    if (!tbody) return;
    let visible = 0;
    Array.from(tbody.children).forEach((tr) => {
      const match = !q || (tr.dataset.search || "").includes(q);
      tr.style.display = match ? "" : "none";
      if (match) visible++;
    });
    const countEl = document.getElementById("headers-count");
    if (countEl) countEl.textContent = q ? `${visible} / ${total} headers` : `${total} headers`;
  }

  function renderHeadersTable(a) {
    const root = document.getElementById("sec-headers");
    const total = a.parsed.headers.length;
    const toolbar = el("div", { class: "headers-toolbar" }, [
      el("input", { type: "text", id: "headers-filter", placeholder: "Filter headers…" }),
      el("span", { class: "muted", id: "headers-count" }, [`${total} headers`]),
      el("button", { class: "btn btn-ghost btn-sm", type: "button", onclick: () => EHA.util.copyToClipboard(a.parsed.headers.map((h) => `${h.name}: ${h.value}`).join("\n")).then(() => EHA.util.toast("Copied all headers")) }, ["Copy All"]),
      el("button", { class: "btn btn-ghost btn-sm", type: "button", onclick: () => downloadAnalysisJSON(a) }, ["Download JSON"]),
    ]);
    const tbody = el("tbody", { id: "headers-tbody" }, a.parsed.headers.map(headerRow));
    const table = el("div", { class: "table-scroll" }, [
      el("table", { class: "data-table" }, [
        el("thead", {}, [el("tr", {}, [el("th", {}, ["#"]), el("th", {}, ["Header"]), el("th", {}, ["Value"])])]),
        tbody,
      ]),
    ]);
    root.replaceChildren(toolbar, table);
    document.getElementById("headers-filter").addEventListener("input", EHA.util.debounce((e) => filterHeadersTable(total, e.target.value), 120));
  }

  function downloadAnalysisJSON(a) {
    const exportObj = {
      generatedAt: new Date().toISOString(),
      subject: a.subject,
      from: a.fromAddress, to: a.toAddresses, replyTo: a.replyToAddress,
      messageId: a.messageId, dateHeader: a.dateHeader,
      originatingIP: a.originatingIP,
      hops: a.hops.map((h) => ({
        hopNumber: h.hopNumber, fromHost: h.fromHost, fromIP: h.fromIP, byHost: h.byHost,
        protocol: h.protocol, delaySeconds: h.delaySeconds, timestamp: h.timestamp ? h.timestamp.toISOString() : null,
      })),
      totalSeconds: a.totalSeconds,
      authentication: { spf: a.authAnalysis.primarySpf, dkim: a.authAnalysis.primaryDkim, dmarc: a.authAnalysis.primaryDmarc },
      espMatches: a.espMatches,
      riskScore: a.risk,
      flags: a.flags,
      headers: a.parsed.headers.map((h) => ({ name: h.name, value: h.value })),
    };
    triggerDownload("email-header-analysis.json", JSON.stringify(exportObj, null, 2), "application/json");
  }

  // ---------- raw ----------
  function renderRaw(a) {
    const root = document.getElementById("sec-raw");
    const headerText = a.parsed.headers.map((h) => h.raw).join("\n");
    const card = el("div", { class: "card" }, [
      el("div", { class: "card-title" }, [el("h3", {}, ["Raw Header Source"]), el("div", {}, [copyBtn(() => headerText), downloadBtn("email-headers.txt", () => headerText)])]),
      el("pre", { class: "raw-pre" }, [headerText]),
    ]);
    const nodes = [card];
    if (a.parsed.hasBody) {
      const body = a.parsed.body;
      const preview = body.length > 4000 ? body.slice(0, 4000) + "\n… (truncated)" : body;
      nodes.push(el("details", { class: "card" }, [
        el("summary", { class: "link-btn" }, [`Message Body Preview (${body.length.toLocaleString()} chars, not analyzed)`]),
        el("pre", { class: "raw-pre" }, [preview]),
      ]));
    }
    root.replaceChildren(...nodes);
  }

  // ---------- async update hooks (MxToolbox / GeoIP) ----------
  function checkRow(tone, item, fallbackLabel) {
    const name = (item && item.Name) || fallbackLabel || "Check";
    const info = (item && item.Info) || "";
    const nameLine = [el("span", { class: "name" }, [name])];
    if (item && item.Url) {
      nameLine.push(el("a", { class: "detail-link", href: item.Url, target: "_blank", rel: "noopener noreferrer" }, ["Details ↗"]));
    }
    return el("div", { class: "check-row" }, [
      el("span", { class: `dot ${tone}` }),
      el("span", {}, [el("div", {}, nameLine), info ? el("span", { class: "info" }, [info]) : null].filter(Boolean)),
    ]);
  }

  function rawResponseDetails(data) {
    return el("details", { class: "mx-raw-details" }, [
      el("summary", {}, ["View raw API response"]),
      el("pre", {}, [JSON.stringify(data, null, 2)]),
    ]);
  }

  function renderMxResult(key, state) {
    const body = document.getElementById(`mx-body-${key}`);
    if (!body) return;
    const argNote = state.argument ? el("div", { class: "mx-meta" }, [`Checked: ${state.argument}`]) : null;
    if (state.status === "loading") {
      body.replaceChildren(el("div", { class: "loading-row" }, [el("span", { class: "spinner" }), state.argument ? `Looking up ${state.argument}…` : "Looking up…"]));
      return;
    }
    if (state.status === "disabled") {
      body.replaceChildren(...[el("div", { class: "empty-state" }, [state.message || "Not run."]), argNote].filter(Boolean));
      return;
    }
    if (state.status === "error") {
      body.replaceChildren(...[el("p", { class: "error-text" }, [state.message]), argNote].filter(Boolean));
      return;
    }
    const summary = EHA.mxtoolbox.summarizeResult(state.data);
    const rows = [];
    (summary.failed || []).forEach((i) => rows.push(checkRow("critical", i)));
    (summary.timeouts || []).forEach((i) => rows.push(checkRow("warning", i, "Timed out")));
    (summary.warnings || []).forEach((i) => rows.push(checkRow("warning", i)));
    (summary.passed || []).forEach((i) => rows.push(checkRow("good", i)));
    if (!rows.length) rows.push(el("div", { class: "empty-state" }, ["No records returned."]));
    if (state.data) rows.push(rawResponseDetails(state.data));
    if (state.data && state.data._cached) rows.push(el("div", { class: "mx-meta" }, ["(cached result, refresh to re-check)"]));
    if (state.data && state.data._keyLabel) rows.push(el("div", { class: "mx-meta" }, [`Checked via key "${state.data._keyLabel}"`]));
    if (argNote) rows.push(argNote);
    body.replaceChildren(...rows);
  }

  function renderGeoForHop(hopNumber, geo) {
    const node = document.getElementById(`hop-geo-${hopNumber}`);
    if (!node) return;
    if (!geo) return;
    const flag = EHA.geoip.flagEmoji(geo.countryCode);
    const parts = [geo.city, geo.region, geo.country].filter(Boolean).join(", ");
    if (!parts && !geo.isp) return;
    node.textContent = `${flag ? flag + " " : ""}${parts}${geo.isp ? " · " + geo.isp : ""}`.trim();
  }

  function renderOriginatingIPGeo(geo) {
    const node = document.getElementById("summary-origip-geo");
    if (!node || !geo) return;
    const flag = EHA.geoip.flagEmoji(geo.countryCode);
    const parts = [geo.city, geo.region, geo.country].filter(Boolean).join(", ");
    if (parts) node.textContent = `${flag ? flag + " " : ""}${parts}`;
  }

  function updateTabCounts(a) {
    const hopCountEl = document.getElementById("tab-hop-count");
    if (hopCountEl) hopCountEl.textContent = a.hops.length ? String(a.hops.length) : "";
    const flagCountEl = document.getElementById("tab-flag-count");
    if (flagCountEl) {
      flagCountEl.textContent = a.flags.length ? String(a.flags.length) : "";
      flagCountEl.classList.toggle("has-flags", a.flags.some((f) => f.severity === "critical" || f.severity === "serious"));
    }
  }

  function renderReport(a) {
    renderSummaryBanner(a);
    renderOverview(a);
    renderHops(a);
    renderAuth(a);
    renderSecurity(a);
    renderHeadersTable(a);
    renderRaw(a);
    updateTabCounts(a);
  }

  EHA.render = { renderReport, renderMxResult, renderGeoForHop, renderOriginatingIPGeo, setTabSwitcher };
})(window);
