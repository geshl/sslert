/**
 * Domain expiry (RDAP) lookup.
 *
 * RDAP (Registration Data Access Protocol) is the modern, structured successor
 * to WHOIS — HTTPS-based with JSON responses. We hit the IANA bootstrap to
 * discover the authoritative server for the TLD, then query it for the
 * domain. If RDAP isn't available (some ccTLDs still don't have it), we
 * fall back to a TCP WHOIS query against the IANA-referred server.
 *
 * No external dependencies — only Node's built-in `fetch` (Node 18+) and `net` modules.
 */

import { createConnection } from "node:net";
import { isPrivateAddress } from "./ssrf-guard.js";

export interface DomainExpiryResult {
  expiresAt: string | null; // ISO 8601
  daysRemaining: number | null;
  registrar: string | null;
  error: string | null;
}

interface RdapBootstrap {
  services: Array<[string[], string[]]>; // [[tlds], [rdapEndpoints]]
}

const RDAP_BOOTSTRAP_URL = "https://data.iana.org/rdap/dns.json";
const WHOIS_PORT = 43;
const WHOIS_TIMEOUT_MS = 8000;
const RDAP_TIMEOUT_MS = 8000;

let _bootstrapCache: { fetchedAt: number; data: RdapBootstrap } | null = null;
const BOOTSTRAP_TTL_MS = 24 * 60 * 60 * 1000;

const MULTIPART_TLDS = new Set([
  "co.uk", "org.uk", "me.uk", "net.uk", "ltd.uk", "plc.uk",
  "com.au", "net.au", "org.au", "edu.au", "gov.au",
  "co.nz", "net.nz", "org.nz",
  "co.jp", "ne.jp", "or.jp", "ac.jp",
  "com.br", "net.br", "org.br",
  "co.za", "net.za", "org.za",
  "com.tr", "org.tr",
  "com.mx", "org.mx",
  "co.il", "org.il",
  "com.sg", "org.sg",
  "com.hk", "org.hk",
  "com.tw", "org.tw",
]);

/**
 * Extract the apex/registered domain from a hostname (e.g. "www.example.com" -> "example.com",
 * "sub.domain.co.uk" -> "domain.co.uk", "example.bg" -> "example.bg").
 * TLD registries only maintain records for apex domains, so querying RDAP or WHOIS with
 * subdomains yields 404 or no match.
 */
export function apexDomainOf(hostname: string): string {
  const cleaned = hostname.toLowerCase().trim().replace(/\.$/, "");
  const parts = cleaned.split(".");
  if (parts.length <= 2) return cleaned;

  // Check if last two parts form a multi-part TLD (e.g. co.uk)
  const lastTwo = parts.slice(-2).join(".");
  if (MULTIPART_TLDS.has(lastTwo)) {
    return parts.slice(-3).join(".");
  }

  // Otherwise, take the last two labels (e.g. example.com from sub.example.com)
  return parts.slice(-2).join(".");
}

export function tldOf(hostname: string): string {
  const apex = apexDomainOf(hostname);
  const parts = apex.toLowerCase().split(".");
  const lastTwo = parts.slice(-2).join(".");
  if (MULTIPART_TLDS.has(lastTwo)) {
    return lastTwo;
  }
  return parts[parts.length - 1] ?? "";
}

async function fetchBootstrap(): Promise<RdapBootstrap | null> {
  if (_bootstrapCache && Date.now() - _bootstrapCache.fetchedAt < BOOTSTRAP_TTL_MS) {
    return _bootstrapCache.data;
  }
  try {
    const res = await fetchWithTimeout(RDAP_BOOTSTRAP_URL, RDAP_TIMEOUT_MS);
    if (!res.ok) return null;
    const data = (await res.json()) as RdapBootstrap;
    _bootstrapCache = { fetchedAt: Date.now(), data };
    return data;
  } catch {
    return null;
  }
}

function fetchWithTimeout(url: string, timeoutMs: number): Promise<Response> {
  return new Promise((resolve, reject) => {
    const ac = new AbortController();
    const timer = setTimeout(() => ac.abort(), timeoutMs);
    fetch(url, { signal: ac.signal })
      .then((r) => {
        clearTimeout(timer);
        resolve(r);
      })
      .catch((e) => {
        clearTimeout(timer);
        reject(e);
      });
  });
}

function rdapEndpointFor(tld: string, bootstrap: RdapBootstrap): string | null {
  for (const [tlds, endpoints] of bootstrap.services) {
    if (tlds.includes(tld)) return endpoints[0] ?? null;
  }
  // If multi-part (e.g. co.uk), also check the base TLD (e.g. uk)
  if (tld.includes(".")) {
    const mainTld = tld.split(".").pop();
    if (mainTld) {
      for (const [tlds, endpoints] of bootstrap.services) {
        if (tlds.includes(mainTld)) return endpoints[0] ?? null;
      }
    }
  }
  return null;
}


function computeDaysRemaining(expiresAt: string): number | null {
  const d = new Date(expiresAt);
  if (Number.isNaN(d.getTime())) return null;
  const diff = d.getTime() - Date.now();
  return Math.ceil(diff / 86400000);
}

interface RdapDomainResponse {
  events?: Array<{ eventAction?: string; eventDate?: string }>;
  entities?: Array<{
    // RFC 7483 §5.1: roles is an array. Some servers still emit a singular
    // `role` string for back-compat, so accept both.
    role?: string;
    roles?: string[];
    vcardArray?: [
      string,
      Array<Array<string | Record<string, string> | string[]>> | undefined,
    ];
  }>;
  status?: string[];
}

function extractRegistrar(rdap: RdapDomainResponse): string | null {
  if (!Array.isArray(rdap.entities)) return null;
  for (const e of rdap.entities) {
    // Per RFC 7483 §5.1, RDAP entity objects expose `roles` as an array
    // (e.g. ["registrar", "sponsor"]). Some servers may still emit the
    // singular `role` for back-compat, so check both.
    const roles: string[] = Array.isArray(e.roles)
      ? e.roles
      : typeof e.role === "string"
        ? [e.role]
        : [];
    if (!roles.includes("registrar")) continue;
    const vcard = e.vcardArray?.[1];
    if (!Array.isArray(vcard)) continue;
    for (const entry of vcard) {
      if (!Array.isArray(entry)) continue;
      const field = entry[0];
      const value = entry[3];
      if (field === "fn" && typeof value === "string") return value;
    }
  }
  return null;
}

function extractExpiry(rdap: RdapDomainResponse): string | null {
  if (!Array.isArray(rdap.events)) return null;
  for (const ev of rdap.events) {
    if (ev.eventAction === "expiration" && ev.eventDate) return ev.eventDate;
  }
  return null;
}

async function lookupRdap(hostname: string): Promise<DomainExpiryResult> {
  const bootstrap = await fetchBootstrap();
  if (!bootstrap) {
    return { expiresAt: null, daysRemaining: null, registrar: null, error: "RDAP bootstrap unavailable" };
  }
  const apex = apexDomainOf(hostname);
  const tld = tldOf(apex);
  const endpoint = rdapEndpointFor(tld, bootstrap);
  if (!endpoint) {
    return { expiresAt: null, daysRemaining: null, registrar: null, error: `No RDAP server for .${tld}` };
  }
  try {
    const url = `${endpoint.replace(/\/$/, "")}/domain/${encodeURIComponent(apex)}`;
    const res = await fetchWithTimeout(url, RDAP_TIMEOUT_MS);
    if (res.status === 404) {
      return { expiresAt: null, daysRemaining: null, registrar: null, error: "Domain not found in RDAP" };
    }
    if (!res.ok) {
      return { expiresAt: null, daysRemaining: null, registrar: null, error: `RDAP HTTP ${res.status}` };
    }
    const data = (await res.json()) as RdapDomainResponse;
    const expiresAt = extractExpiry(data);
    const registrar = extractRegistrar(data);
    if (!expiresAt) {
      return { expiresAt: null, daysRemaining: null, registrar, error: "No expiry event in RDAP response" };
    }
    return {
      expiresAt,
      daysRemaining: computeDaysRemaining(expiresAt),
      registrar,
      error: null,
    };
  } catch (err) {
    return {
      expiresAt: null,
      daysRemaining: null,
      registrar: null,
      error: err instanceof Error ? err.message : String(err),
    };
  }
}

function queryWhoisServer(server: string, query: string, timeoutMs: number): Promise<string> {
  return new Promise((resolve, reject) => {
    const socket = createConnection({ host: server, port: WHOIS_PORT });
    let buffer = "";
    let settled = false;
    const finish = (err: Error | null, data?: string) => {
      if (settled) return;
      settled = true;
      socket.destroy();
      if (err) reject(err);
      else resolve(data ?? "");
    };
    socket.setTimeout(timeoutMs, () => finish(new Error("WHOIS timeout")));
    socket.on("data", (chunk: Buffer) => {
      buffer += chunk.toString("utf-8");
    });
    socket.on("error", (err: Error) => finish(err));
    socket.on("end", () => finish(null, buffer));
    socket.write(`${query}\r\n`);
  });
}

export function parseFlexibleDate(candidate: string): Date | null {
  const trimmed = candidate.trim();
  // 1. Try native Date parse (handles ISO 8601, RFC 2822, YYYY-MM-DD, etc.)
  let d = new Date(trimmed);
  if (!Number.isNaN(d.getTime())) return d;

  // 2. Try DD.MM.YYYY or DD/MM/YYYY (common in EU ccTLDs e.g. .bg, .de, .fr)
  const dmyMatch = trimmed.match(/^(\d{1,2})[\.\/](\d{1,2})[\.\/](\d{4})/);
  if (dmyMatch) {
    const day = parseInt(dmyMatch[1]!, 10);
    const month = parseInt(dmyMatch[2]!, 10) - 1;
    const year = parseInt(dmyMatch[3]!, 10);
    d = new Date(Date.UTC(year, month, day));
    if (!Number.isNaN(d.getTime())) return d;
  }

  // 3. Try YYYY.MM.DD
  const ymdMatch = trimmed.match(/^(\d{4})[\.](\d{1,2})[\.](\d{1,2})/);
  if (ymdMatch) {
    const year = parseInt(ymdMatch[1]!, 10);
    const month = parseInt(ymdMatch[2]!, 10) - 1;
    const day = parseInt(ymdMatch[3]!, 10);
    d = new Date(Date.UTC(year, month, day));
    if (!Number.isNaN(d.getTime())) return d;
  }

  return null;
}

export function extractWhoisExpiry(text: string): { expiresAt: string | null; registrar: string | null } {
  // Permissive pattern: many registrars use different field names for the
  // expiry date. We try the most common variants in order; first parseable
  // match wins.
  const expiryPatterns: RegExp[] = [
    /(?:registry expiry date|registrar registration expiration date|expiration-date|expires on|expiration date|expiry date|renewal date|valid until|paid-till|expires)\s*[:=]\s*([0-9A-Za-zT:\-\.\/Z+\s]+)/i,
  ];
  const registrarPatterns: RegExp[] = [
    /registrar\s*[:=]\s*([^\r\n]+)/i,
    /sponsoring registrar\s*[:=]\s*([^\r\n]+)/i,
  ];
  let expiresAt: string | null = null;
  let registrar: string | null = null;
  for (const p of expiryPatterns) {
    const m = text.match(p);
    if (m?.[1]) {
      const candidate = m[1].trim();
      const d = parseFlexibleDate(candidate);
      if (d) {
        expiresAt = d.toISOString();
        break;
      }
    }
  }
  for (const p of registrarPatterns) {
    const m = text.match(p);
    if (m?.[1]) {
      registrar = m[1].trim();
      break;
    }
  }
  return { expiresAt, registrar };
}

async function lookupWhoisFallback(hostname: string): Promise<DomainExpiryResult> {
  // IANA WHOIS server. Querying it with the TLD (e.g. "com") returns the
  // authoritative whois server for that TLD. Querying with a full hostname
  // like "example.com" usually yields no useful referral.
  const apex = apexDomainOf(hostname);
  const tld = tldOf(apex);
  if (!tld) {
    return { expiresAt: null, daysRemaining: null, registrar: null, error: "No TLD" };
  }
  try {
    const referral = await queryWhoisServer("whois.iana.org", tld, WHOIS_TIMEOUT_MS);
    const referMatch = referral.match(/(?:refer|whois)\s*[:=]\s*([a-z0-9.-]+\.[a-z]{2,})/i);
    const whoisServer = referMatch?.[1] ?? "whois.iana.org";
    // SSRF defence: a compromised or hostile IANA response could redirect
    // us to `refer: 169.254.169.254` (cloud metadata) or another
    // private target. The same guard the checker uses for TLS handshakes
    // runs here before we open a TCP socket. (v0.4.1 code-review
    // CRITICAL.)
    if (process.env.ALLOW_PRIVATE_HOSTS !== "1" && (await isPrivateAddress(whoisServer))) {
      return {
        expiresAt: null,
        daysRemaining: null,
        registrar: null,
        error: "WHOIS referral target is a private address",
      };
    }
    const response = await queryWhoisServer(whoisServer, apex, WHOIS_TIMEOUT_MS);
    const { expiresAt, registrar } = extractWhoisExpiry(response);
    if (!expiresAt) {
      return { expiresAt: null, daysRemaining: null, registrar, error: "No expiry found in WHOIS" };
    }
    return {
      expiresAt,
      daysRemaining: computeDaysRemaining(expiresAt),
      registrar,
      error: null,
    };
  } catch (err) {
    return {
      expiresAt: null,
      daysRemaining: null,
      registrar: null,
      error: err instanceof Error ? err.message : String(err),
    };
  }
}

/**
 * Resolve a domain's registration expiry. RDAP first, plain WHOIS fallback.
 * Always returns a result — failures populate `error` rather than throwing.
 */
export async function lookupDomainExpiry(hostname: string): Promise<DomainExpiryResult> {
  const rdap = await lookupRdap(hostname);
  if (rdap.expiresAt) return rdap;
  const whois = await lookupWhoisFallback(hostname);
  if (whois.expiresAt) return whois;
  return {
    expiresAt: rdap.expiresAt ?? whois.expiresAt,
    daysRemaining: null,
    registrar: rdap.registrar ?? whois.registrar,
    error: rdap.error && whois.error
      ? `RDAP: ${rdap.error}; WHOIS: ${whois.error}`
      : rdap.error ?? whois.error ?? "unknown",
  };
}
