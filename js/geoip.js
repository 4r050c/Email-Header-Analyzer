/* Optional, keyless IP geolocation enrichment for relay hops via ipwho.is
   (free, CORS-enabled, no API key). Entirely separate from the MxToolbox
   integration -- purely a client-side convenience, toggleable in Settings. */
(function (global) {
  "use strict";
  const EHA = global.EHA || (global.EHA = {});

  const CACHE_KEY = "eha:geoip:cache:v1";
  const CACHE_TTL_MS = 24 * 60 * 60 * 1000;

  function readCache() {
    try { return JSON.parse(localStorage.getItem(CACHE_KEY) || "{}"); } catch (e) { return {}; }
  }
  function writeCache(c) {
    try { localStorage.setItem(CACHE_KEY, JSON.stringify(c)); } catch (e) { /* ignore */ }
  }
  function cacheGet(ip) {
    const entry = readCache()[ip];
    if (!entry || Date.now() - entry.t > CACHE_TTL_MS) return null;
    return entry.v;
  }
  function cacheSet(ip, v) {
    const c = readCache();
    c[ip] = { t: Date.now(), v };
    const keys = Object.keys(c);
    if (keys.length > 300) {
      keys.sort((a, b) => c[a].t - c[b].t).slice(0, keys.length - 300).forEach((k) => delete c[k]);
    }
    writeCache(c);
  }

  async function lookupOne(ip) {
    const cached = cacheGet(ip);
    if (cached !== null) return cached;
    try {
      const res = await fetch(`https://ipwho.is/${encodeURIComponent(ip)}`);
      if (!res.ok) return null;
      const data = await res.json();
      if (!data || data.success === false) { cacheSet(ip, null); return null; }
      const result = {
        ip,
        country: data.country || null,
        countryCode: data.country_code || null,
        region: data.region || null,
        city: data.city || null,
        isp: (data.connection && (data.connection.isp || data.connection.org)) || data.isp || null,
        asn: (data.connection && data.connection.asn) || null,
      };
      cacheSet(ip, result);
      return result;
    } catch (e) {
      return null;
    }
  }

  async function lookupMany(ips, opts) {
    const concurrency = (opts && opts.concurrency) || 4;
    const unique = Array.from(new Set(ips.filter(Boolean)));
    const results = new Map();
    let cursor = 0;
    async function worker() {
      while (cursor < unique.length) {
        const ip = unique[cursor++];
        results.set(ip, await lookupOne(ip));
      }
    }
    const workerCount = Math.max(1, Math.min(concurrency, unique.length));
    await Promise.all(Array.from({ length: workerCount }, worker));
    return results;
  }

  function flagEmoji(countryCode) {
    if (!countryCode || countryCode.length !== 2) return "";
    const chars = countryCode.toUpperCase().split("").map((c) => 127397 + c.charCodeAt(0));
    return String.fromCodePoint(...chars);
  }

  EHA.geoip = { lookupOne, lookupMany, flagEmoji };
})(window);
