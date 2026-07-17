/* Authentication analysis: Authentication-Results (RFC 8601), legacy
   Received-SPF, DKIM-Signature tag parsing, and DMARC identifier alignment. */
(function (global) {
  "use strict";
  const EHA = global.EHA || (global.EHA = {});

  function stripComments(str) {
    let result = "";
    let depth = 0;
    for (const ch of str) {
      if (ch === "(") { depth++; continue; }
      if (ch === ")") { if (depth > 0) depth--; continue; }
      if (depth === 0) result += ch;
    }
    return result;
  }

  function parseAuthResultsSegment(segment) {
    const cleaned = stripComments(segment).trim();
    const m = cleaned.match(/^([a-zA-Z][\w-]*)\s*=\s*(\S+)/);
    if (!m) return null;
    const method = m[1].toLowerCase();
    const result = m[2].toLowerCase().replace(/[.,;]+$/, "");
    const rest = cleaned.slice(m[0].length);
    const props = {};
    const propRe = /([a-zA-Z][\w.-]*)=([^\s;]+)/g;
    let pm;
    while ((pm = propRe.exec(rest))) props[pm[1].toLowerCase()] = pm[2].replace(/[;,]+$/, "");
    const commentMatch = segment.match(/\(([^)]*)\)/);
    return { method, result, props, comment: commentMatch ? commentMatch[1].trim() : null, raw: segment.trim() };
  }

  function parseAuthenticationResultsValue(value) {
    const segments = value.split(";").map((s) => s.trim()).filter(Boolean);
    if (!segments.length) return { authservId: null, results: [], raw: value };
    let authservId = segments[0];
    let rest = segments.slice(1);
    if (/^[a-zA-Z][\w-]*\s*=/.test(authservId)) {
      rest = segments;
      authservId = null;
    }
    const results = rest.map(parseAuthResultsSegment).filter(Boolean);
    return { authservId, results, raw: value };
  }

  function parseReceivedSPFValue(value) {
    const m = value.match(/^(\S+)/);
    const result = m ? m[1].toLowerCase().replace(/[.,;]+$/, "") : null;
    const commentMatch = value.match(/\(([^)]*)\)/);
    const afterComment = value.replace(/\([^)]*\)/, "");
    const props = {};
    const propRe = /([a-zA-Z][\w.-]*)=([^\s;]+)/g;
    let pm;
    while ((pm = propRe.exec(afterComment))) props[pm[1].toLowerCase()] = pm[2].replace(/[;,]+$/, "");
    return { result, comment: commentMatch ? commentMatch[1].trim() : null, props, raw: value };
  }

  function parseDKIMSignatureValue(value) {
    const tags = {};
    value.split(";").forEach((seg) => {
      const m = seg.trim().match(/^([a-zA-Z0-9]+)\s*=\s*([\s\S]*)$/);
      if (m) {
        const tag = m[1].toLowerCase();
        let val = m[2].trim();
        if (tag === "b" || tag === "bh") val = val.replace(/\s+/g, "");
        tags[tag] = val;
      }
    });
    return {
      version: tags.v || null,
      algorithm: tags.a || null,
      domain: tags.d || null,
      selector: tags.s || null,
      headerList: tags.h ? tags.h.split(":").map((s) => s.trim()) : [],
      bodyHash: tags.bh || null,
      signature: tags.b || null,
      canonicalization: tags.c || null,
      timestamp: tags.t || null,
      expiration: tags.x || null,
      identity: tags.i || null,
      raw: value,
      tags,
    };
  }

  function checkAlignment(fromDomain, otherDomain) {
    if (!fromDomain || !otherDomain) return { aligned: null, mode: null };
    const f = fromDomain.toLowerCase().replace(/\.$/, "");
    const o = otherDomain.toLowerCase().replace(/\.$/, "");
    if (f === o) return { aligned: true, mode: "strict" };
    if (EHA.parser.organizationalDomain(f) === EHA.parser.organizationalDomain(o)) {
      return { aligned: true, mode: "relaxed" };
    }
    return { aligned: false, mode: null };
  }

  function severityFor(result) {
    if (!result) return "neutral";
    switch (result) {
      case "pass": return "good";
      case "fail":
      case "permerror":
        return "critical";
      case "softfail":
      case "temperror":
        return "serious";
      case "neutral":
      case "none":
      case "policy":
      default:
        return "warning";
    }
  }

  function analyze(headerMap, fromAddress) {
    const arHeaders = EHA.parser.allValues(headerMap, "authentication-results").map(parseAuthenticationResultsValue);
    const receivedSpfHeaders = EHA.parser.allValues(headerMap, "received-spf").map(parseReceivedSPFValue);
    const dkimSigHeaders = EHA.parser.allValues(headerMap, "dkim-signature").map(parseDKIMSignatureValue);
    const fromDomain = fromAddress ? fromAddress.domain : null;

    function collect(method) {
      const found = [];
      arHeaders.forEach((ar, hi) => {
        ar.results
          .filter((r) => r.method === method)
          .forEach((r) => found.push({ ...r, source: `Authentication-Results #${hi + 1}`, authservId: ar.authservId }));
      });
      return found;
    }

    const spfEntries = collect("spf");
    const dkimEntries = collect("dkim");
    const dmarcEntries = collect("dmarc");

    if (!spfEntries.length && receivedSpfHeaders.length) {
      receivedSpfHeaders.forEach((rs, i) =>
        spfEntries.push({ method: "spf", result: rs.result, props: rs.props, comment: rs.comment, source: `Received-SPF #${i + 1}`, raw: rs.raw })
      );
    }

    const primarySpf = spfEntries[0] || null;
    const primaryDkim = dkimEntries[0] || null;
    const primaryDmarc = dmarcEntries[0] || null;

    let spfAlign = { aligned: null, mode: null };
    if (primarySpf) {
      const mailfromDomain = primarySpf.props["smtp.mailfrom"] ? primarySpf.props["smtp.mailfrom"].split("@").pop() : null;
      const heloDomain = primarySpf.props["smtp.helo"] || null;
      spfAlign = mailfromDomain ? checkAlignment(fromDomain, mailfromDomain) : checkAlignment(fromDomain, heloDomain);
    }

    const dkimAlignResults = dkimEntries.map((d) => {
      const domain = d.props["header.i"]
        ? (d.props["header.i"].split("@").pop() || d.props["header.i"])
        : (d.props["header.d"] || null);
      return domain ? checkAlignment(fromDomain, domain) : { aligned: null, mode: null };
    });
    const dkimAligned = dkimAlignResults.length ? dkimAlignResults.some((a) => a.aligned) : null;

    const dkimSigDomains = dkimSigHeaders.map((d) => d.domain).filter(Boolean);

    const returnPathAddr = EHA.parser.firstValue(headerMap, "return-path");
    const returnPathDomain = returnPathAddr ? (EHA.parser.parseSingleAddress(returnPathAddr) || {}).domain : null;

    return {
      arHeaders, receivedSpfHeaders, dkimSigHeaders,
      spfEntries, dkimEntries, dmarcEntries,
      primarySpf, primaryDkim, primaryDmarc,
      spfAlign, dkimAligned, dkimAlignResults, dkimSigDomains,
      fromDomain, returnPathDomain,
    };
  }

  EHA.auth = {
    parseAuthenticationResultsValue,
    parseReceivedSPFValue,
    parseDKIMSignatureValue,
    checkAlignment,
    severityFor,
    analyze,
  };
})(window);
