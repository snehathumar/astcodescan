import dns from 'node:dns/promises';
import tls from 'node:tls';
import { validatePublicTargetUrl } from './ssrfGuard.ts';

export interface TlsCertificateInfo {
  available: boolean;
  subjectCN: string | null;
  issuer: string | null;
  validFrom: string | null;
  validTo: string | null;
  daysRemaining: number | null;
  authorized: boolean | null;
  error?: string;
}

export interface DnsRecordsInfo {
  aRecords: string[];
  mxRecords: string[];
  spfRecord: string | null;
  dmarcRecord: string | null;
}

export interface UrlSignal {
  id: string;
  severity: 'High' | 'Medium' | 'Low' | 'Info';
  title: string;
  detail: string;
}

export interface RedirectHop {
  url: string;
  status: number;
}

export interface LiveUrlAnalysisResult {
  normalizedUrl: string;
  hostname: string;
  protocol: string;
  riskScore: number;
  verdict: 'Low Risk' | 'Suspicious' | 'High Phishing Risk';
  resolvedIps: string[];
  dns: DnsRecordsInfo;
  tls: TlsCertificateInfo;
  redirects: RedirectHop[];
  httpStatus: number | null;
  signals: UrlSignal[];
  analyzedAt: string;
}

export interface EmailHeaderSignal {
  severity: 'High' | 'Medium' | 'Info';
  title: string;
  detail: string;
}

export interface LiveEmailAnalysisResult {
  fromDisplay: string;
  fromAddress: string;
  fromDomain: string;
  replyToAddress: string | null;
  replyToDomain: string | null;
  returnPathAddress: string | null;
  returnPathDomain: string | null;
  dkimDomain: string | null;
  subject: string;
  authResults: {
    spf: string;
    dkim: string;
    dmarc: string;
  };
  liveDns: {
    spfRecord: string | null;
    dmarcRecord: string | null;
    mxRecords: string[];
  };
  extractedUrls: string[];
  receivedHops: string[];
  riskScore: number;
  verdict: 'Authenticated / Low Risk' | 'Suspicious Indicators' | 'High Spoofing Risk';
  signals: EmailHeaderSignal[];
  analyzedAt: string;
}

const BRAND_KEYWORDS = [
  'paypal',
  'microsoft',
  'microsoftonline',
  'office365',
  'google',
  'gmail',
  'apple',
  'icloud',
  'amazon',
  'github',
  'netflix',
  'chase',
  'citibank',
  'hdfc',
  'icici',
  'sbi',
  'binance',
  'coinbase',
];

const SUSPICIOUS_TLDS = new Set([
  'top',
  'xyz',
  'click',
  'tk',
  'ml',
  'ga',
  'cf',
  'gq',
  'zip',
  'mov',
  'work',
  'support',
  'info',
  'rest',
]);

async function fetchDnsRecords(domain: string): Promise<DnsRecordsInfo> {
  const cleanDomain = domain.toLowerCase();
  const [aRes, mxRes, txtRes, dmarcRes] = await Promise.allSettled([
    dns.resolve4(cleanDomain),
    dns.resolveMx(cleanDomain),
    dns.resolveTxt(cleanDomain),
    dns.resolveTxt(`_dmarc.${cleanDomain}`),
  ]);

  const aRecords = aRes.status === 'fulfilled' ? aRes.value : [];
  const mxRecords =
    mxRes.status === 'fulfilled'
      ? mxRes.value.sort((a, b) => a.priority - b.priority).map((m) => `${m.exchange} (pri ${m.priority})`)
      : [];

  let spfRecord: string | null = null;
  if (txtRes.status === 'fulfilled') {
    const flattened = txtRes.value.map((chunks) => chunks.join(''));
    spfRecord = flattened.find((txt) => txt.toLowerCase().startsWith('v=spf1')) ?? null;
  }

  let dmarcRecord: string | null = null;
  if (dmarcRes.status === 'fulfilled') {
    const flattened = dmarcRes.value.map((chunks) => chunks.join(''));
    dmarcRecord = flattened.find((txt) => txt.toLowerCase().startsWith('v=dmarc1')) ?? null;
  }

  return { aRecords, mxRecords, spfRecord, dmarcRecord };
}

function inspectTlsCertificate(hostname: string, port = 443): Promise<TlsCertificateInfo> {
  return new Promise((resolve) => {
    const socket = tls.connect(
      {
        host: hostname,
        port,
        servername: hostname,
        rejectUnauthorized: false,
        timeout: 4500,
      },
      () => {
        try {
          const cert = socket.getPeerCertificate();
          if (!cert || Object.keys(cert).length === 0) {
            socket.destroy();
            resolve({
              available: false,
              subjectCN: null,
              issuer: null,
              validFrom: null,
              validTo: null,
              daysRemaining: null,
              authorized: null,
              error: 'No TLS certificate presented by server.',
            });
            return;
          }

          const validToDate = cert.valid_to ? new Date(cert.valid_to) : null;
          const daysRemaining = validToDate
            ? Math.round((validToDate.getTime() - Date.now()) / (1000 * 60 * 60 * 24))
            : null;
          const rawCn = cert.subject?.CN;
          const subjectCN = Array.isArray(rawCn) ? rawCn[0] ?? null : rawCn ?? null;
          const issuerParts = [cert.issuer?.O, cert.issuer?.CN]
            .flat()
            .filter((v): v is string => typeof v === 'string' && v.length > 0);

          const result: TlsCertificateInfo = {
            available: true,
            subjectCN,
            issuer: issuerParts.join(' · ') || null,
            validFrom: cert.valid_from ?? null,
            validTo: cert.valid_to ?? null,
            daysRemaining,
            authorized: socket.authorized,
          };
          socket.destroy();
          resolve(result);
        } catch (err) {
          socket.destroy();
          resolve({
            available: false,
            subjectCN: null,
            issuer: null,
            validFrom: null,
            validTo: null,
            daysRemaining: null,
            authorized: null,
            error: err instanceof Error ? err.message : 'TLS inspection error',
          });
        }
      }
    );

    socket.on('timeout', () => {
      socket.destroy();
      resolve({
        available: false,
        subjectCN: null,
        issuer: null,
        validFrom: null,
        validTo: null,
        daysRemaining: null,
        authorized: null,
        error: 'TLS handshake timed out.',
      });
    });

    socket.on('error', (err) => {
      socket.destroy();
      resolve({
        available: false,
        subjectCN: null,
        issuer: null,
        validFrom: null,
        validTo: null,
        daysRemaining: null,
        authorized: null,
        error: err.message,
      });
    });
  });
}

async function traceRedirects(startUrl: URL): Promise<{ hops: RedirectHop[]; finalStatus: number | null }> {
  const hops: RedirectHop[] = [];
  let currentUrl = startUrl;
  let finalStatus: number | null = null;

  for (let i = 0; i < 4; i += 1) {
    try {
      const response = await fetch(currentUrl.toString(), {
        method: 'GET',
        redirect: 'manual',
        signal: AbortSignal.timeout(4500),
        headers: {
          'User-Agent': 'SecureCode-Security-Inspector/1.0',
        },
      });
      finalStatus = response.status;
      hops.push({ url: currentUrl.toString(), status: response.status });
      await response.body?.cancel();

      if (response.status >= 300 && response.status < 400) {
        const location = response.headers.get('location');
        if (!location) break;
        const resolvedNext = new URL(location, currentUrl).toString();
        const validated = await validatePublicTargetUrl(resolvedNext);
        if (validated.resolvedIps.length === 0) break;
        currentUrl = validated.parsedUrl;
      } else {
        break;
      }
    } catch {
      break;
    }
  }

  return { hops, finalStatus };
}

export async function analyzeLiveUrl(rawUrl: string): Promise<LiveUrlAnalysisResult> {
  const validated = await validatePublicTargetUrl(rawUrl);
  const { parsedUrl, hostname, resolvedIps } = validated;
  const signals: UrlSignal[] = [];
  let riskScore = 0;

  // Heuristic 1: Plain HTTP
  if (parsedUrl.protocol === 'http:') {
    riskScore += 25;
    signals.push({
      id: 'http-cleartext',
      severity: 'High',
      title: 'Unencrypted HTTP Scheme',
      detail: 'URL uses cleartext http:// instead of HTTPS; credentials sent over this link can be intercepted.',
    });
  }

  // Heuristic 2: @ userinfo credential trap
  if (parsedUrl.username || parsedUrl.password || rawUrl.includes('@')) {
    riskScore += 35;
    signals.push({
      id: 'userinfo-trap',
      severity: 'High',
      title: 'URL Contains "@" Credential / Obfuscation Syntax',
      detail: 'Browsers ignore text before "@" and navigate to the host after "@", a classic phishing redirect trick.',
    });
  }

  // Heuristic 3: Punycode / IDN Homograph
  if (hostname.includes('xn--')) {
    riskScore += 35;
    signals.push({
      id: 'punycode',
      severity: 'High',
      title: 'IDN Punycode Domain Detected (xn--)',
      detail: 'Punycode domains can visually impersonate trusted brands using non-ASCII lookalike characters.',
    });
  }

  // Heuristic 4: Suspicious TLD & Subdomain Brand Masquerading
  const labels = hostname.split('.').filter(Boolean);
  const tld = labels[labels.length - 1] ?? '';
  const rootDomain = labels.length >= 2 ? `${labels[labels.length - 2]}.${tld}` : hostname;
  const subdomainPart = labels.slice(0, -2).join('.');

  if (SUSPICIOUS_TLDS.has(tld)) {
    riskScore += 20;
    signals.push({
      id: 'suspicious-tld',
      severity: 'Medium',
      title: `High-Abuse Top-Level Domain (.${tld})`,
      detail: `The .${tld} TLD is frequently observed in disposable credential-harvesting campaigns.`,
    });
  }

  const matchedSubBrand = BRAND_KEYWORDS.find((b) => subdomainPart.includes(b));
  if (matchedSubBrand && !rootDomain.includes(matchedSubBrand)) {
    riskScore += 45;
    signals.push({
      id: 'subdomain-masquerade',
      severity: 'High',
      title: `Brand Name "${matchedSubBrand}" Hidden in Subdomain`,
      detail: `The true registrable domain is "${rootDomain}", while "${matchedSubBrand}" appears only as a subdomain prefix.`,
    });
  }

  // Heuristic 5: Lookalike digit substitution in root domain (e.g. paypa1, micros0ft)
  if (/paypa1|micr0soft|micros0ft|g00gle|arnazon|app1e|faceb00k/i.test(hostname)) {
    riskScore += 45;
    signals.push({
      id: 'typosquat',
      severity: 'High',
      title: 'Typosquatting / Character Substitution Detected',
      detail: `Hostname "${hostname}" uses visually similar digits/letters to mimic a well-known brand.`,
    });
  }

  if (labels.length >= 4) {
    riskScore += 15;
    signals.push({
      id: 'deep-subdomain',
      severity: 'Medium',
      title: 'Excessive Subdomain Depth',
      detail: `Domain contains ${labels.length} dot-separated labels, often used to push the true root domain off-screen.`,
    });
  }

  // Live DNS + TLS + HTTP Redirect Trace
  const [dnsInfo, tlsInfo, traceInfo] = await Promise.all([
    fetchDnsRecords(rootDomain),
    resolvedIps.length > 0 && parsedUrl.protocol === 'https:'
      ? inspectTlsCertificate(hostname, parsedUrl.port ? Number(parsedUrl.port) : 443)
      : Promise.resolve<TlsCertificateInfo>({
          available: false,
          subjectCN: null,
          issuer: null,
          validFrom: null,
          validTo: null,
          daysRemaining: null,
          authorized: null,
          error: resolvedIps.length === 0 ? 'Domain failed DNS resolution.' : 'HTTP URL has no TLS.',
        }),
    resolvedIps.length > 0
      ? traceRedirects(parsedUrl)
      : Promise.resolve<{ hops: RedirectHop[]; finalStatus: number | null }>({
          hops: [],
          finalStatus: null,
        }),
  ]);

  if (resolvedIps.length === 0) {
    riskScore += 25;
    signals.push({
      id: 'nxdomain',
      severity: 'Medium',
      title: 'Domain Did Not Resolve in Live DNS (NXDOMAIN)',
      detail: `No public A/AAAA DNS records resolved for "${hostname}". Phishing domains are often taken down or unregistered.`,
    });
  }

  if (tlsInfo.available && tlsInfo.authorized === false) {
    riskScore += 25;
    signals.push({
      id: 'tls-untrusted',
      severity: 'High',
      title: 'Untrusted or Mismatched TLS Certificate',
      detail: `Certificate CN "${tlsInfo.subjectCN ?? 'unknown'}" failed standard CA trust validation.`,
    });
  }

  if (traceInfo.hops.length > 1) {
    const firstHost = new URL(traceInfo.hops[0].url).hostname;
    const lastHost = new URL(traceInfo.hops[traceInfo.hops.length - 1].url).hostname;
    if (firstHost !== lastHost) {
      riskScore += 20;
      signals.push({
        id: 'cross-domain-redirect',
        severity: 'Medium',
        title: 'Cross-Domain HTTP Redirect Chain',
        detail: `Initial URL on "${firstHost}" redirects externally to "${lastHost}".`,
      });
    }
  }

  if (signals.length === 0) {
    signals.push({
      id: 'clean-checks',
      severity: 'Info',
      title: 'No Phishing Heuristics Triggered',
      detail: `Live DNS resolved (${resolvedIps[0]}), TLS certificate validated cleanly, and domain structure looks consistent.`,
    });
  }

  const clampedScore = Math.min(100, riskScore);
  let verdict: LiveUrlAnalysisResult['verdict'] = 'Low Risk';
  if (clampedScore >= 55) {
    verdict = 'High Phishing Risk';
  } else if (clampedScore >= 25) {
    verdict = 'Suspicious';
  }

  return {
    normalizedUrl: parsedUrl.toString(),
    hostname,
    protocol: parsedUrl.protocol.replace(':', '').toUpperCase(),
    riskScore: clampedScore,
    verdict,
    resolvedIps,
    dns: dnsInfo,
    tls: tlsInfo,
    redirects: traceInfo.hops,
    httpStatus: traceInfo.finalStatus,
    signals,
    analyzedAt: new Date().toISOString(),
  };
}

function extractEmailAddress(rawHeader: string): string {
  const angleMatch = rawHeader.match(/<([^>\s]+@[^>\s]+)>/);
  if (angleMatch) return angleMatch[1].trim().toLowerCase();
  const plainMatch = rawHeader.match(/([a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,})/);
  return plainMatch ? plainMatch[1].trim().toLowerCase() : '';
}

function domainOfEmail(email: string): string {
  const atIdx = email.lastIndexOf('@');
  return atIdx >= 0 ? email.slice(atIdx + 1).toLowerCase() : '';
}

export async function analyzeRawEmailHeaders(rawEmail: string): Promise<LiveEmailAnalysisResult> {
  const normalized = rawEmail.replace(/\r\n/g, '\n');
  const splitIdx = normalized.indexOf('\n\n');
  const headerBlock = splitIdx >= 0 ? normalized.slice(0, splitIdx) : normalized;
  const bodyBlock = splitIdx >= 0 ? normalized.slice(splitIdx + 2) : '';

  // Unfold folded RFC-5322 headers
  const unfolded = headerBlock.replace(/\n[ \t]+/g, ' ');
  const headerLines = unfolded.split('\n');

  const headers = new Map<string, string[]>();
  for (const line of headerLines) {
    const colon = line.indexOf(':');
    if (colon <= 0) continue;
    const key = line.slice(0, colon).trim().toLowerCase();
    const val = line.slice(colon + 1).trim();
    const list = headers.get(key) ?? [];
    list.push(val);
    headers.set(key, list);
  }

  const fromRaw = headers.get('from')?.[0] ?? '';
  const replyToRaw = headers.get('reply-to')?.[0] ?? '';
  const returnPathRaw = headers.get('return-path')?.[0] ?? '';
  const subject = headers.get('subject')?.[0] ?? '(No Subject Header Found)';
  const authResRaw = (headers.get('authentication-results') ?? []).join(' ; ');
  const dkimSigRaw = headers.get('dkim-signature')?.[0] ?? '';
  const receivedHops = headers.get('received') ?? [];

  const fromAddress = extractEmailAddress(fromRaw);
  const fromDomain = domainOfEmail(fromAddress);
  const replyToAddress = replyToRaw ? extractEmailAddress(replyToRaw) : null;
  const replyToDomain = replyToAddress ? domainOfEmail(replyToAddress) : null;
  const returnPathAddress = returnPathRaw ? extractEmailAddress(returnPathRaw) : null;
  const returnPathDomain = returnPathAddress ? domainOfEmail(returnPathAddress) : null;

  const dkimDomainMatch = dkimSigRaw.match(/\bd=([^;\s]+)/i);
  const dkimDomain = dkimDomainMatch ? dkimDomainMatch[1].toLowerCase() : null;

  const spfMatch = authResRaw.match(/\bspf=(pass|fail|softfail|neutral|none|temperror|permerror)/i);
  const dkimMatch = authResRaw.match(/\bdkim=(pass|fail|neutral|none|temperror|permerror)/i);
  const dmarcMatch = authResRaw.match(/\bdmarc=(pass|fail|bestguesspass|none)/i);

  const authResults = {
    spf: spfMatch ? spfMatch[1].toLowerCase() : 'not-present',
    dkim: dkimMatch ? dkimMatch[1].toLowerCase() : 'not-present',
    dmarc: dmarcMatch ? dmarcMatch[1].toLowerCase() : 'not-present',
  };

  const urlMatches = normalized.match(/https?:\/\/[^\s<>"')]+/gi) ?? [];
  const extractedUrls = Array.from(new Set(urlMatches)).slice(0, 12);

  const signals: EmailHeaderSignal[] = [];
  let riskScore = 0;

  if (!fromAddress) {
    riskScore += 20;
    signals.push({
      severity: 'Medium',
      title: 'Missing or Unparseable From Address',
      detail: 'Paste the full RFC-5322 header block (including From:, Subject:, and Authentication-Results:) for complete forensics.',
    });
  }

  if (replyToDomain && fromDomain && replyToDomain !== fromDomain) {
    riskScore += 35;
    signals.push({
      severity: 'High',
      title: 'Reply-To Domain Mismatch',
      detail: `Visible From domain is "${fromDomain}", but replies route to "${replyToDomain}".`,
    });
  }

  if (returnPathDomain && fromDomain && !returnPathDomain.endsWith(fromDomain) && !fromDomain.endsWith(returnPathDomain)) {
    riskScore += 25;
    signals.push({
      severity: 'Medium',
      title: 'Return-Path / Envelope Sender Divergence',
      detail: `Envelope Return-Path "${returnPathDomain}" differs from From domain "${fromDomain}".`,
    });
  }

  if (authResults.spf === 'fail' || authResults.spf === 'softfail') {
    riskScore += 30;
    signals.push({
      severity: 'High',
      title: `SPF Verification Failed (${authResults.spf.toUpperCase()})`,
      detail: 'Sending server IP was not authorized by the domain’s SPF policy.',
    });
  }

  if (authResults.dkim === 'fail') {
    riskScore += 30;
    signals.push({
      severity: 'High',
      title: 'DKIM Signature Failed',
      detail: 'Cryptographic DKIM signature failed validation or message was altered in transit.',
    });
  }

  if (authResults.dmarc === 'fail') {
    riskScore += 35;
    signals.push({
      severity: 'High',
      title: 'DMARC Alignment Failed',
      detail: 'Message failed DMARC domain alignment against SPF/DKIM.',
    });
  }

  if (/urgent|suspend|verify within|wire transfer|confidential|gift card|expired/i.test(subject + '\n' + bodyBlock)) {
    riskScore += 15;
    signals.push({
      severity: 'Medium',
      title: 'Urgency / Coercive Social Engineering Language',
      detail: 'Subject or body contains high-pressure keywords frequently used in phishing or BEC.',
    });
  }

  const liveDns = fromDomain
    ? await fetchDnsRecords(fromDomain)
    : { aRecords: [], mxRecords: [], spfRecord: null, dmarcRecord: null };

  if (fromDomain && !liveDns.dmarcRecord) {
    riskScore += 15;
    signals.push({
      severity: 'Medium',
      title: `No Live DMARC Record Found for "${fromDomain}"`,
      detail: 'Live DNS lookup for _dmarc.' + fromDomain + ' returned no DMARC policy, making the domain easier to spoof.',
    });
  }

  if (signals.length === 0) {
    signals.push({
      severity: 'Info',
      title: 'Headers & Domain Alignment Look Consistent',
      detail: 'From, Reply-To, and live DNS SPF/DMARC checks showed no obvious spoofing anomalies.',
    });
  }

  const clampedScore = Math.min(100, riskScore);
  let verdict: LiveEmailAnalysisResult['verdict'] = 'Authenticated / Low Risk';
  if (clampedScore >= 50) {
    verdict = 'High Spoofing Risk';
  } else if (clampedScore >= 20) {
    verdict = 'Suspicious Indicators';
  }

  return {
    fromDisplay: fromRaw || '(Not Provided)',
    fromAddress,
    fromDomain,
    replyToAddress,
    replyToDomain,
    returnPathAddress,
    returnPathDomain,
    dkimDomain,
    subject,
    authResults,
    liveDns: {
      spfRecord: liveDns.spfRecord,
      dmarcRecord: liveDns.dmarcRecord,
      mxRecords: liveDns.mxRecords,
    },
    extractedUrls,
    receivedHops: receivedHops.slice(0, 6),
    riskScore: clampedScore,
    verdict,
    signals,
    analyzedAt: new Date().toISOString(),
  };
}
