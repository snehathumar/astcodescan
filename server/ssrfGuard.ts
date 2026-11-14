import dns from 'node:dns/promises';
import net from 'node:net';

const BLOCKED_HOSTNAMES = new Set([
  'localhost',
  'localhost.localdomain',
  'ip6-localhost',
  'ip6-loopback',
  'metadata.google.internal',
  'metadata',
]);

export function isPrivateOrReservedIp(ip: string): boolean {
  const normalized = ip.trim().toLowerCase();
  if (!normalized) return true;

  // Handle IPv4-mapped IPv6 like ::ffff:127.0.0.1
  if (normalized.startsWith('::ffff:')) {
    const v4 = normalized.slice(7);
    if (net.isIPv4(v4)) {
      return isPrivateOrReservedIp(v4);
    }
  }

  if (net.isIPv4(normalized)) {
    const parts = normalized.split('.').map((n) => Number.parseInt(n, 10));
    if (parts.length !== 4 || parts.some((n) => Number.isNaN(n) || n < 0 || n > 255)) {
      return true;
    }
    const [a, b] = parts;
    if (a === 0) return true; // 0.0.0.0/8
    if (a === 10) return true; // 10.0.0.0/8
    if (a === 100 && b >= 64 && b <= 127) return true; // CGNAT 100.64.0.0/10
    if (a === 127) return true; // Loopback 127.0.0.0/8
    if (a === 169 && b === 254) return true; // Link-local / Cloud Metadata 169.254.0.0/16
    if (a === 172 && b >= 16 && b <= 31) return true; // Private 172.16.0.0/12
    if (a === 192 && b === 168) return true; // Private 192.168.0.0/16
    if (a === 192 && b === 0 && parts[2] === 0) return true; // 192.0.0.0/24
    if (a === 198 && (b === 18 || b === 19)) return true; // Benchmark 198.18.0.0/15
    if (a >= 224) return true; // Multicast / Reserved
    return false;
  }

  if (net.isIPv6(normalized)) {
    if (normalized === '::' || normalized === '::1') return true;
    if (normalized.startsWith('fe80:') || normalized.startsWith('fe9') || normalized.startsWith('fea') || normalized.startsWith('feb')) {
      return true; // Link-local fe80::/10
    }
    if (normalized.startsWith('fc') || normalized.startsWith('fd')) {
      return true; // ULA fc00::/7
    }
    if (normalized.startsWith('ff')) {
      return true; // Multicast
    }
    return false;
  }

  return true;
}

export interface ValidatedTarget {
  parsedUrl: URL;
  hostname: string;
  resolvedIps: string[];
}

export async function validatePublicTargetUrl(rawInput: string): Promise<ValidatedTarget> {
  const trimmed = rawInput.trim();
  if (!trimmed) {
    throw new Error('URL cannot be empty.');
  }

  const hasScheme = /^[a-zA-Z][a-zA-Z0-9+.-]*:/.test(trimmed);
  const withScheme = hasScheme ? trimmed : `https://${trimmed}`;
  let parsed: URL;
  try {
    parsed = new URL(withScheme);
  } catch {
    throw new Error('Invalid URL format. Provide a valid http:// or https:// URL.');
  }

  if (parsed.protocol !== 'http:' && parsed.protocol !== 'https:') {
    throw new Error('Only http:// and https:// URLs are permitted.');
  }

  const hostname = parsed.hostname.replace(/^\[|\]$/g, '').toLowerCase();
  if (
    !hostname ||
    BLOCKED_HOSTNAMES.has(hostname) ||
    hostname.endsWith('.local') ||
    hostname.endsWith('.internal') ||
    hostname.endsWith('.localhost')
  ) {
    throw new Error('Scanning local, internal, or metadata hostnames is blocked for security.');
  }

  if (net.isIP(hostname)) {
    if (isPrivateOrReservedIp(hostname)) {
      throw new Error('Scanning private, loopback, or reserved IP ranges is blocked.');
    }
    return { parsedUrl: parsed, hostname, resolvedIps: [hostname] };
  }

  let records: { address: string; family: number }[];
  try {
    records = await dns.lookup(hostname, { all: true });
  } catch {
    // Domain may not exist (e.g., typo/non-existent phishing domain) — allow heuristic inspection without network fetch
    return { parsedUrl: parsed, hostname, resolvedIps: [] };
  }

  const ips = records.map((r) => r.address);
  if (ips.some((ip) => isPrivateOrReservedIp(ip))) {
    throw new Error('Target domain resolved to a private or reserved IP address and was blocked.');
  }

  return { parsedUrl: parsed, hostname, resolvedIps: ips };
}
