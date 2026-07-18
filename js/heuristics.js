/* ESP fingerprinting and phishing/spoofing red-flag heuristics.
   Every rule is a best-effort signal, not a verdict -- descriptions say so. */
(function (global) {
  "use strict";
  const EHA = global.EHA || (global.EHA = {});

  function hasHeader(headerMap, name) { return headerMap.has(name.toLowerCase()); }
  function headerValueMatches(headerMap, name, re) {
    const v = EHA.parser.firstValue(headerMap, name);
    return v ? re.test(v) : false;
  }
  function anyHopHostMatches(hops, re) {
    return hops.some((h) => (h.fromHost && re.test(h.fromHost)) || (h.byHost && re.test(h.byHost)) || (h.fromHelo && re.test(h.fromHelo)));
  }

  const ESP_SIGNATURES = [
    { name: "Amazon SES", test: (c) => hasHeader(c.headerMap, "x-ses-outgoing") || anyHopHostMatches(c.hops, /amazonses\.com$/i) },
    { name: "Google Workspace / Gmail", test: (c) => hasHeader(c.headerMap, "x-google-smtp-source") || hasHeader(c.headerMap, "x-gm-message-state") || anyHopHostMatches(c.hops, /(^|\.)google\.com$|(^|\.)gmail\.com$/i) },
    { name: "Microsoft 365 / Outlook", test: (c) => hasHeader(c.headerMap, "x-ms-exchange-organization-authsource") || hasHeader(c.headerMap, "x-microsoft-antispam") || anyHopHostMatches(c.hops, /protection\.outlook\.com$|(^|\.)outlook\.com$/i) },
    { name: "Mailgun", test: (c) => hasHeader(c.headerMap, "x-mailgun-sid") || anyHopHostMatches(c.hops, /mailgun\.(org|com)$/i) },
    { name: "SendGrid (Twilio)", test: (c) => hasHeader(c.headerMap, "x-sg-eid") || hasHeader(c.headerMap, "x-sg-id") || anyHopHostMatches(c.hops, /sendgrid\.net$/i) },
    { name: "Mandrill (Mailchimp Transactional)", test: (c) => hasHeader(c.headerMap, "x-mandrill-user") },
    { name: "Mailchimp Marketing", test: (c) => hasHeader(c.headerMap, "x-mcda") || anyHopHostMatches(c.hops, /mcsv\.net$|mailchimp\.com$/i) },
    { name: "Postmark", test: (c) => hasHeader(c.headerMap, "x-pm-message-id") },
    { name: "SparkPost", test: (c) => anyHopHostMatches(c.hops, /sparkpostmail\.com$/i) || headerValueMatches(c.headerMap, "x-msfbl", /sparkpost/i) },
    { name: "Zoho Mail", test: (c) => anyHopHostMatches(c.hops, /zoho\.(com|eu|in)$/i) },
    { name: "Proton Mail", test: (c) => anyHopHostMatches(c.hops, /protonmail\.(ch|com)$/i) },
    { name: "Yahoo Mail", test: (c) => hasHeader(c.headerMap, "x-yahoo-newman-id") || anyHopHostMatches(c.hops, /(^|\.)yahoo\.com$/i) },
    { name: "Apple iCloud Mail", test: (c) => anyHopHostMatches(c.hops, /icloud\.com$|(^|\.)me\.com$/i) },
    { name: "Fastmail", test: (c) => anyHopHostMatches(c.hops, /messagingengine\.com$/i) },
    { name: "Salesforce Marketing Cloud", test: (c) => anyHopHostMatches(c.hops, /exacttarget\.com$/i) || hasHeader(c.headerMap, "x-sfmc-stack") },
    { name: "HubSpot", test: (c) => anyHopHostMatches(c.hops, /hubspotemail\.net$/i) || hasHeader(c.headerMap, "x-hsmid") },
    { name: "Constant Contact", test: (c) => anyHopHostMatches(c.hops, /constantcontact\.com$/i) },
    { name: "Campaign Monitor", test: (c) => anyHopHostMatches(c.hops, /createsend\.com$|^cmail\d*\./i) },
    { name: "Klaviyo", test: (c) => anyHopHostMatches(c.hops, /klaviyomail\.com$/i) },
    { name: "Braze", test: (c) => anyHopHostMatches(c.hops, /brazecloud\.com$/i) },
    { name: "Mailjet", test: (c) => anyHopHostMatches(c.hops, /mailjet\.com$/i) || hasHeader(c.headerMap, "x-mj-messagetype") },
    { name: "Zendesk", test: (c) => anyHopHostMatches(c.hops, /zendesk\.com$/i) },
    { name: "GoDaddy / Secureserver", test: (c) => anyHopHostMatches(c.hops, /secureserver\.net$/i) },
    { name: "Yandex Mail", test: (c) => anyHopHostMatches(c.hops, /yandex\.(ru|com|net)$/i) },
    { name: "NetEase (163 / 126 Mail)", test: (c) => anyHopHostMatches(c.hops, /163\.com$|126\.com$/i) },
    { name: "Tencent QQ Mail", test: (c) => anyHopHostMatches(c.hops, /qq\.com$/i) },
  ];

  function detectESPs(ctx) {
    return ESP_SIGNATURES.filter((sig) => {
      try { return sig.test(ctx); } catch (e) { return false; }
    }).map((s) => s.name);
  }

  // ---------- red-flag rules ----------
  const FLAG_RULES = [];
  const rule = (fn) => FLAG_RULES.push(fn);

  rule(function fromReturnPathMismatch(ctx) {
    const fromDomain = ctx.fromDomain;
    const rpDomain = ctx.authAnalysis.returnPathDomain;
    if (!fromDomain || !rpDomain) return null;
    if (EHA.parser.organizationalDomain(fromDomain) === EHA.parser.organizationalDomain(rpDomain)) return null;
    return {
      id: "from-returnpath-mismatch", severity: "warning",
      title: "From address and Return-Path use different domains",
      description: `The visible sender is on "${fromDomain}" but the envelope/bounce address (Return-Path) is on "${rpDomain}". Normal for mailing lists and many bulk senders (ESPs), but also used to spoof a trusted brand while routing bounces elsewhere.`,
      evidence: `From: ${fromDomain}  |  Return-Path: ${rpDomain}`,
    };
  });

  rule(function fromReplyToMismatch(ctx) {
    if (!ctx.replyToAddress || !ctx.replyToAddress.domain || !ctx.fromDomain) return null;
    if (EHA.parser.organizationalDomain(ctx.fromDomain) === EHA.parser.organizationalDomain(ctx.replyToAddress.domain)) return null;
    return {
      id: "from-replyto-mismatch", severity: "warning",
      title: "Reply-To domain differs from From domain",
      description: `Replies go to "${ctx.replyToAddress.domain}", not the sending domain "${ctx.fromDomain}". Common in legitimate helpdesk/CRM setups, but also a classic redirection tactic in phishing.`,
      evidence: `From: ${ctx.fromDomain}  |  Reply-To: ${ctx.replyToAddress.domain}`,
    };
  });

  rule(function displayNameSpoof(ctx) {
    const from = ctx.fromAddress;
    if (!from || !from.name) return null;
    const emailInName = from.name.match(/[\w.+-]+@[\w-]+\.[\w.-]+/);
    if (!emailInName) return null;
    const namedEmailDomain = emailInName[0].split("@").pop().toLowerCase();
    if (from.domain && namedEmailDomain === from.domain.toLowerCase()) return null;
    return {
      id: "display-name-spoof", severity: "critical",
      title: "Display name contains a different email address than the actual sender",
      description: `The visible name is "${from.name}", which itself contains an email address on "${namedEmailDomain}" — but the message actually came from "${from.email}". This is a well-known trick to make a fake sender look trustworthy at a glance.`,
      evidence: `Display name: ${from.name}  |  Actual From: ${from.email}`,
    };
  });

  rule(function spfResult(ctx) {
    const spf = ctx.authAnalysis.primarySpf;
    if (!spf) {
      return { id: "spf-missing", severity: "warning", title: "No SPF result found",
        description: "Neither an Authentication-Results nor a Received-SPF header reported an SPF check, so SPF could not be verified from these headers alone.", evidence: null };
    }
    const sev = EHA.auth.severityFor(spf.result);
    if (sev === "good") return null;
    const titles = { fail: "SPF check failed", softfail: "SPF soft-failed", neutral: "SPF result is neutral", none: "No SPF record published", temperror: "SPF check hit a temporary DNS error", permerror: "SPF record is malformed" };
    return {
      id: "spf-" + spf.result, severity: sev,
      title: titles[spf.result] || `SPF result: ${spf.result}`,
      description: `The receiving server's own SPF check returned "${spf.result}"${spf.comment ? " — " + spf.comment : ""}.`,
      evidence: spf.raw || null,
    };
  });

  rule(function dkimResult(ctx) {
    const dkim = ctx.authAnalysis.primaryDkim;
    if (!dkim) {
      if (!ctx.authAnalysis.dkimSigHeaders.length) {
        return { id: "dkim-missing", severity: "warning", title: "No DKIM signature found",
          description: "This message carries no DKIM-Signature header at all, so its content and headers cannot be cryptographically tied to the sending domain.", evidence: null };
      }
      return null;
    }
    const sev = EHA.auth.severityFor(dkim.result);
    if (sev === "good") return null;
    return {
      id: "dkim-" + dkim.result, severity: sev,
      title: `DKIM result: ${dkim.result}`,
      description: `The receiving server's own DKIM check returned "${dkim.result}"${dkim.comment ? " — " + dkim.comment : ""}.`,
      evidence: dkim.raw || null,
    };
  });

  rule(function dmarcResult(ctx) {
    const dmarc = ctx.authAnalysis.primaryDmarc;
    if (!dmarc) {
      return { id: "dmarc-missing", severity: "warning", title: "No DMARC result found",
        description: "No Authentication-Results entry reported a DMARC evaluation. The receiving server may not check DMARC, or the domain may not publish a DMARC policy.", evidence: null };
    }
    const sev = EHA.auth.severityFor(dmarc.result);
    if (sev === "good") return null;
    return {
      id: "dmarc-" + dmarc.result, severity: sev,
      title: `DMARC result: ${dmarc.result}`,
      description: `The receiving server's own DMARC check returned "${dmarc.result}"${dmarc.comment ? " — " + dmarc.comment : ""}.`,
      evidence: dmarc.raw || null,
    };
  });

  rule(function privateIpMidChain(ctx) {
    const pubIdx = ctx.hops.findIndex((h) => h.fromIP && !h.fromPrivate);
    if (pubIdx === -1) return null;
    const flagged = ctx.hops.find((h, i) => h.fromPrivate && i > pubIdx);
    if (!flagged) return null;
    return {
      id: "private-ip-midchain", severity: "info",
      title: "Private/internal IP address appears after a public hop",
      description: `Hop #${flagged.hopNumber} reports a private-range "from" address (${flagged.fromIP}) occurring after the message had already traversed a public relay. Often explained by internal load balancers or mail gateways, but worth a second look if unexpected.`,
      evidence: flagged.raw,
    };
  });

  rule(function largeHopDelay(ctx) {
    const withDelay = ctx.hops.filter((h) => h.delaySeconds !== null && h.delaySeconds >= 0);
    if (!withDelay.length) return null;
    const worst = withDelay.slice().sort((a, b) => b.delaySeconds - a.delaySeconds)[0];
    if (worst.delaySeconds < 300) return null;
    const sev = worst.delaySeconds >= 3600 ? "serious" : "warning";
    return {
      id: "large-hop-delay", severity: sev,
      title: `Unusually long delay between hops (${EHA.util.formatDuration(worst.delaySeconds)})`,
      description: `Hop #${worst.hopNumber} (${worst.byHost || worst.byRaw || "unknown server"}) took ${EHA.util.formatDuration(worst.delaySeconds)} longer than the previous hop. Can indicate greylisting, spam-filter holds, queueing under load, or clock skew between servers.`,
      evidence: worst.raw,
    };
  });

  rule(function missingMessageId(ctx) {
    if (ctx.headerMap.has("message-id")) return null;
    return { id: "missing-message-id", severity: "warning", title: "No Message-ID header",
      description: "Legitimate mail almost always carries a Message-ID. Its absence is unusual and slightly more common in spoofed or hand-crafted messages.", evidence: null };
  });

  rule(function missingDate(ctx) {
    if (ctx.headerMap.has("date")) return null;
    return { id: "missing-date", severity: "warning", title: "No Date header", description: "No Date header was found in these headers.", evidence: null };
  });

  rule(function numericHelo(ctx) {
    const hop = ctx.hops.find((h) => h.fromHelo && /^\d{1,3}(\.\d{1,3}){3}$/.test(h.fromHelo.replace(/[[\]]/g, "")));
    if (!hop) return null;
    return {
      id: "numeric-helo", severity: "info",
      title: "Sending server identified itself with a raw IP address",
      description: `Hop #${hop.hopNumber} announced itself (HELO/EHLO) as "${hop.fromHelo}" instead of a hostname. Weak signal alone — many small mail servers do this — but also common in spam/botnet traffic.`,
      evidence: hop.raw,
    };
  });

  rule(function punycodeDomain(ctx) {
    if (!ctx.fromDomain || !/xn--/i.test(ctx.fromDomain)) return null;
    return {
      id: "punycode-domain", severity: "serious",
      title: "Sender domain uses Punycode (internationalized) encoding",
      description: `"${ctx.fromDomain}" is an IDN/punycode domain. Sometimes legitimate, but also a common way to register look-alike domains that visually mimic a trusted brand.`,
      evidence: ctx.fromDomain,
    };
  });

  rule(function multipleFrom(ctx) {
    if (!ctx.fromAddresses || ctx.fromAddresses.length < 2) return null;
    if (ctx.headerMap.has("sender")) return null;
    return {
      id: "multiple-from", severity: "warning",
      title: "Multiple addresses in From header without a Sender header",
      description: "RFC 5322 requires a Sender header when From lists more than one mailbox. Its absence here is a formatting irregularity some spoofing tools produce.",
      evidence: ctx.fromAddresses.map((a) => a.email).join(", "),
    };
  });

  rule(function noReceivedHeaders(ctx) {
    if (ctx.hops.length > 0) return null;
    return {
      id: "no-received", severity: "warning", title: "No Received headers found",
      description: "No delivery hops could be reconstructed. Either this is a locally-composed/test message, or the relay chain was stripped — either way, the delivery path can't be independently verified from these headers.",
      evidence: null,
    };
  });

  rule(function dmarcAlignmentInconsistent(ctx) {
    const dmarc = ctx.authAnalysis.primaryDmarc;
    if (!dmarc || dmarc.result !== "pass") return null;
    const spfAligned = ctx.authAnalysis.spfAlign.aligned;
    const dkimAligned = ctx.authAnalysis.dkimAligned;
    if (spfAligned || dkimAligned) return null;
    if (spfAligned === null && dkimAligned === null) return null;
    return {
      id: "dmarc-alignment-inconsistent", severity: "info",
      title: "DMARC reported pass, but alignment couldn't be confirmed locally",
      description: "The receiving server reported a DMARC pass, but this tool could not independently confirm SPF or DKIM identifier alignment from the available header data.",
      evidence: null,
    };
  });

  rule(function arcChainBroken(ctx) {
    const arc = ctx.authAnalysis.arc;
    if (!arc || !arc.present) return null;
    if (arc.chainValidation !== "fail") return null;
    return {
      id: "arc-chain-fail", severity: "serious",
      title: "ARC chain validation failed (cv=fail)",
      description: "This message passed through a forwarder/mailing list that added an Authenticated Received Chain, but the topmost ARC-Seal reports the chain as broken (cv=fail). The original authentication results it carries can't be trusted.",
      evidence: `ARC instances: ${arc.instances.length}, chain validation: ${arc.chainValidation}`,
    };
  });

  rule(function plaintextPublicHop(ctx) {
    // A hop between two public servers that explicitly used un-encrypted
    // SMTP (no TLS version, non-S protocol). Internal/private hops are
    // ignored -- plaintext inside one operator's network is normal.
    const hop = ctx.hops.find((h) => h.tls === false && h.fromIP && !h.fromPrivate && !EHA.parser.isPrivateIP(h.byIP));
    if (!hop) return null;
    return {
      id: "plaintext-public-hop", severity: "warning",
      title: "A public relay hop was not encrypted (no TLS)",
      description: `Hop #${hop.hopNumber} handed the message between public servers over plain ${hop.protocol || "SMTP"} with no TLS indicated. Mail in transit on that hop could have been read or altered by a network observer.`,
      evidence: hop.raw,
    };
  });

  function evaluateFlags(ctx) {
    return FLAG_RULES.map((fn) => {
      try { return fn(ctx); } catch (e) { return null; }
    }).filter(Boolean);
  }

  // ---------- non-flag descriptive metadata (mailing list, spam filter, bulk) ----------
  function extractMailMeta(headerMap) {
    const fv = (n) => EHA.parser.firstValue(headerMap, n);
    const meta = { list: null, spam: [], precedence: null, autoSubmitted: null, priority: null };

    const listId = fv("list-id");
    const listUnsub = fv("list-unsubscribe");
    if (listId || listUnsub) {
      const oneClick = /One-Click/i.test(fv("list-unsubscribe-post") || "");
      meta.list = {
        id: listId ? EHA.parser.decodeRFC2047(listId) : null,
        unsubscribe: listUnsub,
        oneClick,
        post: fv("list-post"),
        owner: fv("list-owner"),
      };
    }

    // Spam-filter verdicts stamped by intermediate servers.
    const sa = fv("x-spam-status") || fv("x-spam-flag") || fv("x-spam-score") || fv("x-spam-level");
    if (sa) {
      const scoreMatch = sa.match(/score=(-?\d+(?:\.\d+)?)/i);
      meta.spam.push({ system: "SpamAssassin", value: sa, score: scoreMatch ? scoreMatch[1] : null });
    }
    const scl = fv("x-microsoft-antispam") || fv("x-forefront-antispam-report") || fv("x-ms-exchange-organization-scl");
    const sclScore = fv("x-ms-exchange-organization-scl");
    if (scl || sclScore) {
      meta.spam.push({ system: "Microsoft (SCL)", value: sclScore ? `SCL ${sclScore}` : scl, score: sclScore || null });
    }
    const barracuda = fv("x-barracuda-spam-score");
    if (barracuda) meta.spam.push({ system: "Barracuda", value: barracuda, score: barracuda });

    meta.precedence = fv("precedence");
    meta.autoSubmitted = fv("auto-submitted");
    meta.priority = fv("x-priority") || fv("importance") || fv("priority");
    return meta;
  }

  const SEVERITY_WEIGHT = { critical: 34, serious: 18, warning: 8, info: 2 };
  const SEVERITY_ORDER = { critical: 0, serious: 1, warning: 2, info: 3 };

  function computeRiskScore(flags) {
    const score = Math.min(100, flags.reduce((s, f) => s + (SEVERITY_WEIGHT[f.severity] || 0), 0));
    let band = "low";
    if (score >= 70) band = "critical";
    else if (score >= 40) band = "high";
    else if (score >= 18) band = "medium";
    return { score, band };
  }

  function sortFlags(flags) {
    return flags.slice().sort((a, b) => (SEVERITY_ORDER[a.severity] ?? 9) - (SEVERITY_ORDER[b.severity] ?? 9));
  }

  EHA.heuristics = { detectESPs, evaluateFlags, computeRiskScore, sortFlags, extractMailMeta, ESP_SIGNATURES };
})(window);
