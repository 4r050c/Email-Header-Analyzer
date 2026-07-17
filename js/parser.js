/* Structural email-header parsing: RFC 5322 tolerant unfolding, header
   extraction, Received-chain hop reconstruction, address parsing. Pure
   functions, no DOM access, so this module is independently testable. */
(function (global) {
  "use strict";
  const EHA = global.EHA || (global.EHA = {});

  const FIELD_NAME_RE = /^([\x21-\x39\x3B-\x7E]+):[ \t]?([\s\S]*)$/;

  function unfold(headerText) {
    const lines = headerText.replace(/\r\n/g, "\n").split("\n");
    const logical = [];
    for (const line of lines) {
      if (/^[ \t]/.test(line) && logical.length) {
        logical[logical.length - 1] += line;
      } else {
        logical.push(line);
      }
    }
    return logical;
  }

  function splitHeadersAndBody(input) {
    let text = String(input || "").replace(/\r\n/g, "\n").replace(/\r/g, "\n");
    text = text.replace(/^﻿/, "");
    text = text.replace(/^\n+/, "");
    // strip a leading mbox "From " delimiter line, if present
    text = text.replace(/^From [^\n]*\n/, "");
    const blankIdx = text.indexOf("\n\n");
    if (blankIdx === -1) return { headerText: text, body: null };
    return { headerText: text.slice(0, blankIdx), body: text.slice(blankIdx + 2) || null };
  }

  function parseHeaderBlock(headerText) {
    const logicalLines = unfold(headerText);
    const headers = [];
    for (const line of logicalLines) {
      if (!line.trim()) continue;
      const m = FIELD_NAME_RE.exec(line);
      if (m) {
        headers.push({ name: m[1], value: m[2].trim(), raw: line });
      }
    }
    return headers;
  }

  function toHeaderMap(headers) {
    const map = new Map();
    headers.forEach((h) => {
      const key = h.name.toLowerCase();
      if (!map.has(key)) map.set(key, []);
      map.get(key).push(h);
    });
    return map;
  }

  function firstValue(headerMap, name) {
    const arr = headerMap.get(name.toLowerCase());
    return arr && arr.length ? arr[0].value : null;
  }

  function allValues(headerMap, name) {
    const arr = headerMap.get(name.toLowerCase());
    return arr ? arr.map((h) => h.value) : [];
  }

  function parseRaw(input) {
    if (!input || !String(input).trim()) {
      throw new Error("No header text provided.");
    }
    const { headerText, body } = splitHeadersAndBody(input);
    const headers = parseHeaderBlock(headerText);
    if (!headers.length) {
      throw new Error(
        "Couldn't find any valid \"Name: value\" header lines. Paste raw headers " +
        "(e.g. from \"Show original\" / \"View source\") rather than the rendered email."
      );
    }
    const headerMap = toHeaderMap(headers);
    return { headers, headerMap, body, hasBody: !!body, rawInput: input };
  }

  // ---------- Received: header parsing ----------

  const CLAUSE_KEYWORDS = ["from", "by", "via", "with", "id", "for"];

  function extractClauseParts(clause) {
    const result = { fromRaw: null, byRaw: null, viaRaw: null, withProto: null, id: null, forAddr: null };
    const kwRe = /\b(from|by|via|with|id|for)\b/gi;
    const positions = [];
    let m;
    while ((m = kwRe.exec(clause))) {
      positions.push({ kw: m[1].toLowerCase(), idx: m.index, end: kwRe.lastIndex });
    }
    for (let i = 0; i < positions.length; i++) {
      const cur = positions[i];
      const next = positions[i + 1];
      const segment = clause.slice(cur.end, next ? next.idx : clause.length).trim();
      if (!segment) continue;
      switch (cur.kw) {
        case "from": if (!result.fromRaw) result.fromRaw = segment; break;
        case "by": if (!result.byRaw) result.byRaw = segment; break;
        case "via": if (!result.viaRaw) result.viaRaw = segment; break;
        case "with": if (!result.withProto) result.withProto = segment.split(/\s+/)[0]; break;
        case "id": if (!result.id) result.id = segment.split(/\s+/)[0].replace(/[<>;,]/g, ""); break;
        case "for": if (!result.forAddr) result.forAddr = segment.split(/\s+/)[0].replace(/[<>;,]/g, ""); break;
      }
    }
    return result;
  }

  const IPV4_RE = /\b(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\b/;
  const IPV6_RE = /([0-9a-fA-F]{1,4}:[0-9a-fA-F:]{2,}(?::[0-9a-fA-F]{1,4})?)/;

  function extractHostIP(segment) {
    if (!segment) return { host: null, ip: null, helo: null };
    let ip = null;
    const bracketMatch = segment.match(/\[([^\]]+)\]/);
    if (bracketMatch) {
      const inner = bracketMatch[1].replace(/^IPv6:/i, "");
      if (IPV4_RE.test(inner)) ip = inner.match(IPV4_RE)[1];
      else if (inner.includes(":")) ip = inner;
    }
    if (!ip) {
      const v4 = segment.match(IPV4_RE);
      if (v4) ip = v4[1];
      else {
        const v6 = segment.match(IPV6_RE);
        if (v6 && v6[1].split(":").length > 2) ip = v6[1];
      }
    }
    const heloMatch = segment.match(/^([^\s(\[]+)/);
    const helo = heloMatch ? heloMatch[1].replace(/[.,;]+$/, "") : null;
    const parenMatch = segment.match(/\(([^)]*)\)/);
    let host = null;
    if (parenMatch) {
      const inParen = parenMatch[1].split(/\s+/)[0].replace(/[[\].]*$/, "");
      if (inParen && /[a-zA-Z]/.test(inParen)) host = inParen.replace(/\.$/, "");
    }
    if (!host && helo && /[a-zA-Z]/.test(helo)) host = helo;
    return { host, ip, helo };
  }

  function parseHeaderDate(str) {
    if (!str) return null;
    const cleaned = str.trim().replace(/\s*\([^)]*\)\s*$/, "").trim();
    if (!cleaned) return null;
    const d = new Date(cleaned);
    if (isNaN(d.getTime())) return null;
    return d;
  }

  function isPrivateIP(ip) {
    if (!ip) return false;
    if (ip.includes(":")) {
      return /^::1$/i.test(ip) || /^f[cd]/i.test(ip) || /^fe80/i.test(ip);
    }
    const parts = ip.split(".").map(Number);
    if (parts.length !== 4 || parts.some((n) => isNaN(n) || n < 0 || n > 255)) return false;
    const [a, b] = parts;
    if (a === 10) return true;
    if (a === 172 && b >= 16 && b <= 31) return true;
    if (a === 192 && b === 168) return true;
    if (a === 127) return true;
    if (a === 169 && b === 254) return true;
    if (a === 100 && b >= 64 && b <= 127) return true; // carrier-grade NAT
    return false;
  }

  function parseReceivedValue(raw, index) {
    const lastSemi = raw.lastIndexOf(";");
    let clause = raw, dateStr = null;
    if (lastSemi !== -1) {
      clause = raw.slice(0, lastSemi);
      dateStr = raw.slice(lastSemi + 1).trim();
    }
    const parts = extractClauseParts(clause);
    const fromInfo = extractHostIP(parts.fromRaw);
    const byInfo = extractHostIP(parts.byRaw);
    const timestamp = parseHeaderDate(dateStr);
    return {
      rawIndex: index,
      raw,
      fromRaw: parts.fromRaw,
      byRaw: parts.byRaw,
      fromHost: fromInfo.host,
      fromIP: fromInfo.ip,
      fromHelo: fromInfo.helo,
      byHost: byInfo.host || (parts.byRaw ? parts.byRaw.split(/\s+/)[0] : null),
      byIP: byInfo.ip,
      protocol: parts.withProto || null,
      id: parts.id || null,
      forAddr: parts.forAddr || null,
      dateStr,
      timestamp,
    };
  }

  function parseReceivedChain(headerMap) {
    const receivedHeaders = headerMap.get("received") || [];
    const raw = receivedHeaders.map((h, idx) => parseReceivedValue(h.value, idx));
    // Header order is newest-first (each relay prepends); reverse for chronological (sender -> recipient).
    const chronological = raw.slice().reverse();
    chronological.forEach((hop, i) => {
      hop.hopNumber = i + 1;
      if (i === 0) {
        hop.delaySeconds = null;
      } else {
        const t0 = chronological[i - 1].timestamp;
        const t1 = hop.timestamp;
        hop.delaySeconds = t0 && t1 ? Math.round((t1 - t0) / 1000) : null;
      }
      hop.fromPrivate = isPrivateIP(hop.fromIP);
    });
    const withTimestamps = chronological.filter((h) => h.timestamp);
    const totalSeconds = withTimestamps.length >= 2
      ? Math.round((withTimestamps[withTimestamps.length - 1].timestamp - withTimestamps[0].timestamp) / 1000)
      : null;
    return { hops: chronological, count: chronological.length, totalSeconds };
  }

  function findOriginatingIP(chronoHops, headerMap) {
    const xOrig = firstValue(headerMap, "x-originating-ip") || firstValue(headerMap, "x-sender-ip");
    if (xOrig) {
      const m = xOrig.match(IPV4_RE) || xOrig.match(IPV6_RE);
      if (m) return { ip: m[1], source: "X-Originating-IP header" };
    }
    for (const hop of chronoHops) {
      if (hop.fromIP && !isPrivateIP(hop.fromIP)) {
        return { ip: hop.fromIP, source: `Received hop #${hop.hopNumber} ("from")` };
      }
    }
    const withIp = chronoHops.find((h) => h.fromIP);
    if (withIp) return { ip: withIp.fromIP, source: `Received hop #${withIp.hopNumber} ("from", private/internal range)` };
    return null;
  }

  // ---------- address parsing ----------

  function splitAddressList(value) {
    if (!value) return [];
    const results = [];
    let depth = 0, inQuotes = false, cur = "";
    for (const ch of value) {
      if (ch === '"') inQuotes = !inQuotes;
      if (!inQuotes) {
        if (ch === "<") depth++;
        if (ch === ">") depth = Math.max(0, depth - 1);
      }
      if (ch === "," && depth === 0 && !inQuotes) {
        results.push(cur);
        cur = "";
      } else {
        cur += ch;
      }
    }
    if (cur.trim()) results.push(cur);
    return results;
  }

  function parseSingleAddress(token) {
    token = (token || "").trim();
    if (!token) return null;
    const angleMatch = token.match(/<([^>]*)>/);
    let email, name;
    if (angleMatch) {
      email = angleMatch[1].trim();
      name = token.slice(0, angleMatch.index).trim().replace(/^"(.*)"$/, "$1").trim();
    } else {
      email = token.replace(/^"(.*)"$/, "$1").trim();
      name = "";
    }
    email = email.replace(/^mailto:/i, "");
    const domainMatch = email.match(/@([^@\s>]+)$/);
    return { raw: token, name, email, domain: domainMatch ? domainMatch[1].toLowerCase().replace(/\.$/, "") : null };
  }

  function parseAddressList(value) {
    return splitAddressList(value).map(parseSingleAddress).filter(Boolean);
  }

  // simplified org-domain heuristic: handles common two-part public suffixes.
  const TWO_PART_TLDS = new Set([
    "co.uk", "org.uk", "ac.uk", "gov.uk", "co.jp", "co.in", "co.nz", "co.za",
    "com.au", "net.au", "org.au", "com.br", "com.cn", "com.mx", "com.sg",
    "co.kr", "com.tw", "co.id", "com.hk",
  ]);

  function organizationalDomain(domain) {
    if (!domain) return null;
    const parts = domain.toLowerCase().replace(/\.$/, "").split(".");
    if (parts.length <= 2) return parts.join(".");
    const lastTwo = parts.slice(-2).join(".");
    if (TWO_PART_TLDS.has(lastTwo)) return parts.slice(-3).join(".");
    return lastTwo;
  }

  // ---------- shared helper: what should the blacklist check run against? ----------
  // Every public relay IP in the chain (not just the originating one) plus any
  // sender domains the caller supplies (MxToolbox's "blacklist" command accepts
  // either an IP or a domain). Used by both render.js (to build one subcard per
  // target) and app.js (to know what to fetch) so the two stay in sync.
  function collectBlacklistTargets(hops, originatingIP, domains) {
    const targets = [];
    const seen = new Set();
    function add(value, label, kind) {
      if (!value) return;
      const key = value.toLowerCase();
      if (seen.has(key)) return;
      seen.add(key);
      targets.push({ value, label, kind });
    }
    if (originatingIP && !isPrivateIP(originatingIP.ip)) add(originatingIP.ip, "Originating IP", "ip");
    hops.forEach((h) => { if (h.fromIP && !h.fromPrivate) add(h.fromIP, `Hop #${h.hopNumber} IP`, "ip"); });
    (domains || []).forEach((d) => { if (d && d.value) add(d.value, d.label, "domain"); });
    return targets;
  }

  function safeDomId(value) {
    return String(value).replace(/[^a-zA-Z0-9]/g, "-");
  }

  EHA.parser = {
    unfold,
    splitHeadersAndBody,
    parseHeaderBlock,
    toHeaderMap,
    firstValue,
    allValues,
    parseRaw,
    parseReceivedChain,
    parseReceivedValue,
    findOriginatingIP,
    isPrivateIP,
    parseHeaderDate,
    parseAddressList,
    parseSingleAddress,
    organizationalDomain,
    collectBlacklistTargets,
    safeDomId,
    IPV4_RE,
    IPV6_RE,
  };
})(window);
