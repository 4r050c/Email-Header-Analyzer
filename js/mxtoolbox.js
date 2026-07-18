/* MxToolbox API client (https://mxtoolbox.com/api/api-reference).
   Base: https://api.mxtoolbox.com/api/v1 -- GET /Lookup/{command}/?argument=...
   Auth: `Authorization: <uuid api key>` header (no Bearer prefix).
   The API does not document CORS support for browser use, so network-level
   failures are surfaced with an actionable hint about configuring a proxy.

   Supports multiple API keys with automatic rotation: if a key comes back
   401 (rejected) or 429 (quota exceeded), the next configured key is tried
   before giving up. A key that hits its quota is marked with a reset time
   (next UTC midnight, matching MxToolbox's documented daily reset) so
   future calls can skip it without spending another request to find out. */
(function (global) {
  "use strict";
  const EHA = global.EHA || (global.EHA = {});

  const DEFAULT_BASE = "https://api.mxtoolbox.com/api/v1";
  const CACHE_TTL_MS = 60 * 60 * 1000;
  const CACHE_KEY = "eha:mx:cache:v1";

  // Per the API reference, "DNS" quota covers spf/dkim/dmarc/mx/txt; "Network"
  // quota covers blacklist. Free accounts get 64 DNS/day but 0 Network/day, so a
  // blacklist 429 almost always means "needs a paid plan", not "used them all up".
  const NETWORK_COMMANDS = new Set(["blacklist"]);
  // Error kinds worth trying the next key for. A CORS/network failure or a
  // malformed-response error won't be fixed by a different key, so those
  // still fail fast instead of burning through the whole key list.
  const ROTATE_ON_KINDS = new Set(["quota", "auth"]);

  function readCache() {
    try { return JSON.parse(localStorage.getItem(CACHE_KEY) || "{}"); } catch (e) { return {}; }
  }
  function writeCache(cache) {
    try { localStorage.setItem(CACHE_KEY, JSON.stringify(cache)); } catch (e) { /* storage full/unavailable: skip caching */ }
  }
  function cacheGet(key) {
    const entry = readCache()[key];
    if (!entry || Date.now() - entry.t > CACHE_TTL_MS) return null;
    return entry.v;
  }
  function cacheSet(key, value) {
    const cache = readCache();
    cache[key] = { t: Date.now(), v: value };
    const keys = Object.keys(cache);
    if (keys.length > 200) {
      keys.sort((a, b) => cache[a].t - cache[b].t)
        .slice(0, keys.length - 200)
        .forEach((k) => delete cache[k]);
    }
    writeCache(cache);
  }

  function MxError(message, opts) {
    const err = new Error(message);
    err.name = "MxError";
    err.kind = (opts && opts.kind) || "unknown";
    err.status = opts && opts.status;
    return err;
  }

  function nextUtcMidnight() {
    const d = new Date();
    return Date.UTC(d.getUTCFullYear(), d.getUTCMonth(), d.getUTCDate() + 1, 0, 0, 0, 0);
  }

  function isKeyExhausted(keyEntry, quotaKind, now) {
    const until = keyEntry.exhaustedUntil && keyEntry.exhaustedUntil[quotaKind];
    return typeof until === "number" && until > now;
  }

  async function rawRequest(apiKey, proxyBase, path, quotaKind) {
    const base = proxyBase && proxyBase.trim() ? proxyBase.trim().replace(/\/$/, "") : DEFAULT_BASE;
    const url = base + path;
    let res;
    try {
      res = await fetch(url, {
        method: "GET",
        headers: { Authorization: apiKey, Accept: "application/json" },
      });
    } catch (networkErr) {
      throw MxError(
        "Request to the MxToolbox API failed before receiving a response — most likely blocked as a cross-origin (CORS) request, since MxToolbox's API does not publish CORS headers for direct browser use. Configure a CORS proxy under Settings → MxToolbox API, or treat this as a server-side-only feature for now.",
        { kind: "network" }
      );
    }
    if (res.status === 401 || res.status === 400) {
      // Confirmed against the live API: 401/400 here is AMBIGUOUS. MxToolbox
      // returns 401 not only for a rejected key but also when the queried
      // domain/host doesn't exist or the command (dkim, blacklist) isn't
      // served for this key's plan -- and 400 ("The AlertGroup for ApiKey ...
      // could not be loaded") for an unrecognized key. requestWithRotation
      // disambiguates via a /Usage probe before blaming the key.
      throw MxError(`MxToolbox returned HTTP ${res.status} for this request.`, { kind: "auth", status: res.status });
    }
    if (res.status === 429) {
      const message = quotaKind === "network"
        ? "MxToolbox Network-request quota exceeded for this key (429). Free accounts get 0 Network requests/day — blacklist checks need a paid MxToolbox plan."
        : "MxToolbox DNS-request quota exceeded for this key (429). Free accounts get 64 DNS lookups/day, resetting at 00:00 UTC.";
      throw MxError(message, { kind: "quota", status: 429 });
    }
    if (!res.ok) {
      let bodyText = "";
      try { bodyText = (await res.text()).slice(0, 200); } catch (e) { /* ignore */ }
      throw MxError(`MxToolbox API returned HTTP ${res.status}. ${bodyText}`, { kind: "http", status: res.status });
    }
    try {
      return await res.json();
    } catch (e) {
      throw MxError("MxToolbox API returned a response that wasn't valid JSON.", { kind: "parse" });
    }
  }

  // Session cache of "/Usage says this key is real" verdicts so a burst of
  // 401s (e.g. five lookups against a nonexistent domain) costs one probe,
  // not one per lookup.
  const keyValidityCache = new Map();

  async function checkKeyValidity(apiKey, proxyBase) {
    if (keyValidityCache.has(apiKey)) return keyValidityCache.get(apiKey);
    let valid;
    try {
      await rawRequest(apiKey, proxyBase, "/Usage", "dns");
      valid = true;
    } catch (err) {
      if (err.kind === "auth") valid = false;
      else return true; // network/server hiccup: inconclusive, don't blame the key (and don't cache)
    }
    keyValidityCache.set(apiKey, valid);
    return valid;
  }

  // Tries each non-exhausted key in order until one succeeds. On a
  // quota/auth failure it marks the key (quota gets a reset timestamp,
  // handing the mutated entry to config.onKeyExhausted so the caller can
  // persist it) and moves to the next.
  async function requestWithRotation(config, path, quotaKind) {
    const keys = (config.keys || []).filter((k) => k && k.key && k.key.trim());
    if (!keys.length) throw MxError("No MxToolbox API key configured. Add one in Settings.", { kind: "no-key" });
    const now = Date.now();
    const candidates = keys.filter((k) => !isKeyExhausted(k, quotaKind, now));
    if (!candidates.length) {
      const label = quotaKind === "network" ? "Network" : "DNS";
      throw MxError(
        `All ${keys.length} configured API key${keys.length === 1 ? "" : "s"} have hit their ${label} quota for today. Add another key in Settings, or wait for the daily reset at 00:00 UTC.`,
        { kind: "quota-all", status: 429 }
      );
    }

    let lastErr;
    const attempted = [];
    for (const keyEntry of candidates) {
      try {
        const data = await rawRequest(keyEntry.key.trim(), config.proxyBase, path, quotaKind);
        return { data, keyEntry };
      } catch (err) {
        lastErr = err;
        if (err.kind === "auth") {
          // A 401/400 might mean "bad key" OR "MxToolbox refused this
          // particular lookup" (nonexistent domain, or a command the plan
          // doesn't include). Probe /Usage with the same key: if it answers,
          // the key is fine and rotating would be pointless -- surface the
          // real cause instead of burning through the key list.
          const keyIsValid = await checkKeyValidity(keyEntry.key.trim(), config.proxyBase);
          if (keyIsValid) {
            throw MxError(
              `MxToolbox refused this lookup (HTTP ${err.status}) even though your API key is valid. Their API responds this way when the queried domain/host doesn't exist or can't be resolved${quotaKind === "network" ? ", or when blacklist (Network) lookups aren't included in your plan" : ""}.`,
              { kind: "refused", status: err.status }
            );
          }
        }
        attempted.push({ label: keyEntry.label || "key", kind: err.kind });
        if (ROTATE_ON_KINDS.has(err.kind)) {
          if (err.kind === "quota") {
            keyEntry.exhaustedUntil = keyEntry.exhaustedUntil || {};
            keyEntry.exhaustedUntil[quotaKind] = nextUtcMidnight();
          }
          if (config.onKeyExhausted) {
            try { config.onKeyExhausted(keyEntry, err.kind, quotaKind); } catch (cbErr) { /* ignore callback errors */ }
          }
          continue;
        }
        throw err;
      }
    }
    if (attempted.length > 1) {
      throw MxError(
        `Tried ${attempted.length} API keys, all failed (${attempted.map((a) => `${a.label}: ${a.kind}`).join(", ")}). ${lastErr.message}`,
        { kind: lastErr.kind, status: lastErr.status }
      );
    }
    if (lastErr.kind === "auth") {
      throw MxError("MxToolbox rejected this API key — /Usage doesn't recognize it either. Check the key under Settings.", { kind: "auth", status: lastErr.status });
    }
    throw lastErr;
  }

  async function lookup(config, command, argument, opts) {
    const useCache = !opts || opts.useCache !== false;
    const cacheKey = `lookup:${command}:${argument.toLowerCase()}`;
    if (useCache) {
      const cached = cacheGet(cacheKey);
      if (cached) return Object.assign({}, cached, { _cached: true });
    }
    const quotaKind = NETWORK_COMMANDS.has(command) ? "network" : "dns";
    const path = `/Lookup/${encodeURIComponent(command)}/?argument=${encodeURIComponent(argument)}`;
    const { data, keyEntry } = await requestWithRotation(config, path, quotaKind);
    cacheSet(cacheKey, data);
    const extra = (config.keys || []).length > 1 && keyEntry.label ? { _keyLabel: keyEntry.label } : {};
    return Object.assign({}, data, extra);
  }

  function usageForKey(apiKey, proxyBase) {
    return rawRequest(apiKey, proxyBase, "/Usage", "dns");
  }

  function summarizeResult(data) {
    if (!data) return null;
    const passed = data.Passed || [];
    const warnings = data.Warnings || [];
    const failed = data.Failed || [];
    const timeouts = data.Timeouts || [];
    let status = "neutral";
    if (failed.length) status = "critical";
    else if (timeouts.length || warnings.length) status = "warning";
    else if (passed.length) status = "good";
    return { passed, warnings, failed, timeouts, status };
  }

  const COMMAND_LABELS = {
    spf: "SPF Record", dkim: "DKIM Record", dmarc: "DMARC Record",
    mx: "MX Records", txt: "TXT Records", blacklist: "Blacklist Status",
  };

  EHA.mxtoolbox = { lookup, usageForKey, summarizeResult, MxError, DEFAULT_BASE, COMMAND_LABELS, nextUtcMidnight };
})(window);
