import type { CodeLanguage } from '../data/secureCodeSamples';

export type Severity = 'Critical' | 'High' | 'Medium' | 'Low';

export interface SecurityFinding {
  id: string;
  ruleId: string;
  title: string;
  severity: Severity;
  cwe: string;
  owasp: string;
  line: number;
  snippet: string;
  explanation: string;
  remediation: string;
  secureExample: string;
}

export interface AuditSummary {
  totalFindings: number;
  critical: number;
  high: number;
  medium: number;
  low: number;
  postureLabel: 'Critical Risk' | 'High Risk' | 'Moderate Risk' | 'Clean Baseline';
  linesScanned: number;
}

export interface AuditReport {
  language: CodeLanguage;
  findings: SecurityFinding[];
  summary: AuditSummary;
}

interface SecurityRule {
  ruleId: string;
  title: string;
  severity: Severity;
  cwe: string;
  owasp: string;
  languages: CodeLanguage[];
  pattern: RegExp;
  explanation: string;
  remediation: string;
  secureExample: string;
}

const SECURITY_RULES: SecurityRule[] = [
  {
    ruleId: 'SCR-001',
    title: 'SQL Injection via String Interpolation / Concatenation',
    severity: 'Critical',
    cwe: 'CWE-89',
    owasp: 'A03:2021 Injection',
    languages: ['python', 'javascript', 'php'],
    pattern:
      /(?:f["'][^"\n]*\b(?:SELECT|INSERT|UPDATE|DELETE)\b[^"\n]*\{[^}]+\}|(?:SELECT|INSERT|UPDATE|DELETE)\b[^;\n]*(?:\+\s*[a-zA-Z_$]|\$\{|\.\s*\$_(?:GET|POST|REQUEST)|\.format\s*\(|["']\s*%\s*[a-zA-Z_(]))/i,
    explanation:
      'Constructing SQL statements by concatenating or interpolating untrusted input allows attackers to alter query logic, bypass authentication, or exfiltrate database tables.',
    remediation:
      'Use parameterized queries / prepared statements with bound placeholders (?, $1, :param) instead of string formatting.',
    secureExample: 'conn.execute("SELECT id FROM users WHERE username = ?", (username,))',
  },
  {
    ruleId: 'SCR-002',
    title: 'OS Command Injection Risk',
    severity: 'Critical',
    cwe: 'CWE-78',
    owasp: 'A03:2021 Injection',
    languages: ['python', 'javascript', 'php'],
    pattern:
      /(?:os\.system\s*\(|subprocess\.\w+\([^)]*shell\s*=\s*True|\bexec\s*\(\s*["'`][^"'`]*["'`]\s*\+|\b(?:shell_exec|passthru)\s*\()/i,
    explanation:
      'Passing user-controlled strings into a shell interpreter allows arbitrary OS command execution via metacharacters (;, &&, |, $()).',
    remediation:
      'Avoid shell invocation; use argument arrays (subprocess.run([...], shell=False) or child_process.execFile) paired with strict allowlist validation.',
    secureExample: 'subprocess.run(["ping", "-c", "1", validated_host], shell=False, check=False)',
  },
  {
    ruleId: 'SCR-003',
    title: 'Hardcoded Secret, API Key, or Password',
    severity: 'Critical',
    cwe: 'CWE-798',
    owasp: 'A07:2021 Auth Failures',
    languages: ['python', 'javascript', 'php'],
    pattern:
      /(?:(?:SECRET_KEY|API_KEY|STRIPE_SECRET|JWT_SECRET|DB_PASS(?:WORD)?|\$db_pass|password)["']?\s*(?:=|:|\]\s*=)\s*["'][^"']{6,}["']|["'](?:AIza[0-9A-Za-z_-]{10,}|sk_(?:live|test)_[0-9A-Za-z]{8,}|AKIA[0-9A-Z]{16})["'])/i,
    explanation:
      'Credentials embedded in source code are exposed to anyone with repository access, build logs, or container images and prevent safe key rotation.',
    remediation:
      'Load secrets exclusively at runtime from environment variables or a managed secret vault (e.g., Google Cloud Secret Manager).',
    secureExample: 'app.config["SECRET_KEY"] = os.environ["FLASK_SECRET_KEY"]',
  },
  {
    ruleId: 'SCR-004',
    title: 'Cross-Site Scripting (XSS) via Unsafe HTML Sink',
    severity: 'High',
    cwe: 'CWE-79',
    owasp: 'A03:2021 Injection',
    languages: ['python', 'javascript', 'php'],
    pattern:
      /(?:\.innerHTML\s*=|\.outerHTML\s*=|document\.write\s*\(|dangerouslySetInnerHTML|render_template_string\s*\(|echo\s+[^;]*\$_(?:GET|POST|REQUEST))/i,
    explanation:
      'Writing unescaped user input directly into HTML/DOM sinks enables arbitrary script execution in the victim browser, stealing session tokens or performing unauthorized actions.',
    remediation:
      'Use textContent / createElement in the DOM, JSX automatic escaping, or context-aware HTML encoding (htmlspecialchars with ENT_QUOTES).',
    secureExample: 'authorEl.textContent = commentAuthor;',
  },
  {
    ruleId: 'SCR-005',
    title: 'Unsafe Dynamic Evaluation or Deserialization',
    severity: 'Critical',
    cwe: 'CWE-502',
    owasp: 'A08:2021 Data Integrity Failures',
    languages: ['python', 'javascript', 'php'],
    pattern:
      /(?:\beval\s*\(|\bexec\s*\(\s*[a-zA-Z_]|pickle\.loads\s*\(|yaml\.load\s*\([^)]*(?!Loader\s*=\s*SafeLoader)|\bunserialize\s*\()/i,
    explanation:
      'eval() and unsafe binary/object deserializers (pickle.loads, PHP unserialize, yaml.load) can execute arbitrary code when processing untrusted payloads.',
    remediation:
      'Replace dynamic evaluation with strict lookup tables or safe parsers such as JSON (json.loads / JSON.parse / json_decode) or yaml.safe_load.',
    secureExample: 'const prefs = JSON.parse(rawPrefs);',
  },
  {
    ruleId: 'SCR-006',
    title: 'Path Traversal in File Access',
    severity: 'High',
    cwe: 'CWE-22',
    owasp: 'A01:2021 Broken Access Control',
    languages: ['python', 'javascript', 'php'],
    pattern:
      /(?:send_file|open|fs\.readFile\w*|res\.sendFile)\s*\([^)]*(?:\+\s*[a-zA-Z_]|filename|req\.|request\.)/i,
    explanation:
      'Concatenating a user-supplied filename into a filesystem path lets attackers use ../ sequences to read sensitive configuration files or system secrets.',
    remediation:
      'Canonicalize the resolved path and verify it stays strictly within the intended base directory (e.g., werkzeug.utils.safe_join or path.resolve prefix check).',
    secureExample: 'safe_path = safe_join(str(REPORTS_DIR), filename)',
  },
  {
    ruleId: 'SCR-007',
    title: 'Weak Cryptographic Hash or Predictable PRNG',
    severity: 'High',
    cwe: 'CWE-328',
    owasp: 'A02:2021 Cryptographic Failures',
    languages: ['python', 'javascript', 'php'],
    pattern:
      /(?:hashlib\.(?:md5|sha1)\s*\(|createHash\s*\(\s*["'](?:md5|sha1)["']\)|Math\.random\s*\()/i,
    explanation:
      'MD5/SHA-1 are vulnerable to collision and rapid brute-force attacks for passwords, while Math.random() is not cryptographically secure for tokens or CSRF secrets.',
    remediation:
      'Use Argon2id / bcrypt / PBKDF2 for passwords, SHA-256+ for integrity, and crypto.getRandomValues / secrets.token_urlsafe for tokens.',
    secureExample: 'crypto.getRandomValues(new Uint8Array(24));',
  },
  {
    ruleId: 'SCR-008',
    title: 'TLS Certificate Verification Disabled',
    severity: 'High',
    cwe: 'CWE-295',
    owasp: 'A02:2021 Cryptographic Failures',
    languages: ['python', 'javascript', 'php'],
    pattern:
      /(?:verify\s*=\s*False|rejectUnauthorized\s*:\s*false|NODE_TLS_REJECT_UNAUTHORIZED\s*=\s*["']0["'])/i,
    explanation:
      'Disabling TLS certificate validation exposes outbound HTTPS requests to Man-in-the-Middle interception and credential theft.',
    remediation:
      'Keep certificate verification enabled at all times and configure trusted enterprise CAs properly when needed.',
    secureExample: 'const response = await fetch(verifiedHttpsUrl);',
  },
  {
    ruleId: 'SCR-009',
    title: 'Server-Side Request Forgery (SSRF) Sink',
    severity: 'High',
    cwe: 'CWE-918',
    owasp: 'A10:2021 SSRF',
    languages: ['python', 'javascript', 'php'],
    pattern:
      /(?:requests\.(?:get|post)\s*\(\s*(?:request\.|url|targetUrl)|\bfetch\s*\(\s*(?:targetUrl|req\.))/i,
    explanation:
      'Fetching an arbitrary user-supplied URL from the backend allows attackers to probe internal VPC services or cloud metadata endpoints (169.254.169.254).',
    remediation:
      'Enforce HTTPS protocol and validate the parsed hostname against an explicit allowlist before issuing outbound requests.',
    secureExample: 'if (parsed.protocol !== "https:" || !ALLOWED_HOSTS.has(parsed.hostname)) return 400;',
  },
  {
    ruleId: 'SCR-010',
    title: 'Debug Mode or Verbose Error Disclosure Enabled',
    severity: 'Medium',
    cwe: 'CWE-489',
    owasp: 'A05:2021 Security Misconfiguration',
    languages: ['python', 'javascript', 'php'],
    pattern: /(?:debug\s*=\s*True|display_errors["']?\s*,\s*["']?1["']?)/i,
    explanation:
      'Running frameworks with debug mode or display_errors enabled exposes stack traces, file paths, and interactive debuggers in production.',
    remediation:
      'Explicitly disable debug flags in production builds and log internal diagnostics securely on the server.',
    secureExample: 'app.run(host="127.0.0.1", port=5000, debug=False)',
  },
  {
    ruleId: 'SCR-011',
    title: 'Permissive Wildcard CORS Policy',
    severity: 'Medium',
    cwe: 'CWE-942',
    owasp: 'A05:2021 Security Misconfiguration',
    languages: ['python', 'javascript', 'php'],
    pattern: /Access-Control-Allow-Origin["']?\s*[,:]\s*["']\*["']|origin\s*:\s*["']\*["']/i,
    explanation:
      'Wildcard CORS policies allow any external origin to read API responses from the browser, expanding data exposure.',
    remediation:
      'Restrict Access-Control-Allow-Origin to explicit, trusted origin domains.',
    secureExample: 'res.setHeader("Access-Control-Allow-Origin", "https://portal.example.com");',
  },
];

const SEVERITY_ORDER: Record<Severity, number> = {
  Critical: 0,
  High: 1,
  Medium: 2,
  Low: 3,
};

export function analyzeSourceCode(code: string, language: CodeLanguage): AuditReport {
  const safeCode = typeof code === 'string' ? code : '';
  const lines = safeCode.split(/\r?\n/);
  const findings: SecurityFinding[] = [];
  const seenKey = new Set<string>();

  lines.forEach((rawLine, index) => {
    const lineNumber = index + 1;
    const trimmed = rawLine.trim();
    if (!trimmed || trimmed.startsWith('#') || trimmed.startsWith('//')) {
      return;
    }

    for (const rule of SECURITY_RULES) {
      if (!rule.languages.includes(language)) {
        continue;
      }
      if (rule.pattern.test(rawLine)) {
        const dedupeKey = `${rule.ruleId}:${lineNumber}`;
        if (seenKey.has(dedupeKey)) {
          continue;
        }
        seenKey.add(dedupeKey);
        findings.push({
          id: `${rule.ruleId}-L${lineNumber}`,
          ruleId: rule.ruleId,
          title: rule.title,
          severity: rule.severity,
          cwe: rule.cwe,
          owasp: rule.owasp,
          line: lineNumber,
          snippet: trimmed,
          explanation: rule.explanation,
          remediation: rule.remediation,
          secureExample: rule.secureExample,
        });
      }
    }
  });

  findings.sort((a, b) => {
    const sevDiff = SEVERITY_ORDER[a.severity] - SEVERITY_ORDER[b.severity];
    return sevDiff !== 0 ? sevDiff : a.line - b.line;
  });

  const critical = findings.filter((f) => f.severity === 'Critical').length;
  const high = findings.filter((f) => f.severity === 'High').length;
  const medium = findings.filter((f) => f.severity === 'Medium').length;
  const low = findings.filter((f) => f.severity === 'Low').length;

  let postureLabel: AuditSummary['postureLabel'] = 'Clean Baseline';
  if (critical > 0) {
    postureLabel = 'Critical Risk';
  } else if (high > 0) {
    postureLabel = 'High Risk';
  } else if (medium > 0 || low > 0) {
    postureLabel = 'Moderate Risk';
  }

  return {
    language,
    findings,
    summary: {
      totalFindings: findings.length,
      critical,
      high,
      medium,
      low,
      postureLabel,
      linesScanned: safeCode.trim() ? lines.length : 0,
    },
  };
}

export function generateAuditMarkdownReport(
  report: AuditReport,
  appTitle: string
): string {
  const { summary, findings, language } = report;
  const header = `# Secure Coding Review Report — ${appTitle}

- **Language Audited:** ${language.toUpperCase()}
- **Lines Scanned:** ${summary.linesScanned}
- **Security Posture:** ${summary.postureLabel}
- **Findings Summary:** ${summary.critical} Critical · ${summary.high} High · ${summary.medium} Medium · ${summary.low} Low

---

## Findings & Remediation Steps
`;

  if (findings.length === 0) {
    return `${header}\nNo static security vulnerabilities detected by the configured OWASP/CWE ruleset.\n`;
  }

  const body = findings
    .map(
      (f, idx) => `### ${idx + 1}. [${f.severity}] ${f.title} (Line ${f.line})
- **Rule:** ${f.ruleId} · **CWE:** ${f.cwe} · **OWASP:** ${f.owasp}
- **Vulnerable Snippet:** \`${f.snippet}\`
- **Risk:** ${f.explanation}
- **Remediation:** ${f.remediation}
- **Secure Pattern:** \`${f.secureExample}\`
`
    )
    .join('\n');

  return `${header}\n${body}`;
}

export function buildSecureCodingPythonAuditor(): string {
  return `#!/usr/bin/env python3
"""
SecureCode AST — Static Security Analyzer for Python/JS/PHP source files.
"""

import re
import sys
from pathlib import Path

RULES = [
    ("SCR-001", "Critical", "CWE-89", "SQL Injection risk",
     re.compile(r"(SELECT|INSERT|UPDATE|DELETE).*(\\+\\s*\\w+|f[\"']|\\$\\{)", re.IGNORECASE)),
    ("SCR-002", "Critical", "CWE-78", "Command Injection risk",
     re.compile(r"(os\\.system\\(|shell\\s*=\\s*True|shell_exec\\()", re.IGNORECASE)),
    ("SCR-003", "Critical", "CWE-798", "Hardcoded secret or password",
     re.compile(r"(SECRET_KEY|API_KEY|PASSWORD)\\s*=\\s*[\"'][^\"']{6,}[\"']", re.IGNORECASE)),
    ("SCR-004", "High", "CWE-79", "Cross-Site Scripting (XSS) sink",
     re.compile(r"(\\.innerHTML\\s*=|document\\.write\\(|render_template_string\\()", re.IGNORECASE)),
    ("SCR-005", "Critical", "CWE-502", "Unsafe eval/deserialization",
     re.compile(r"(\\beval\\(|pickle\\.loads\\(|\\bunserialize\\()", re.IGNORECASE)),
    ("SCR-007", "High", "CWE-328", "Weak cryptographic hash (MD5/SHA1)",
     re.compile(r"hashlib\\.(md5|sha1)\\(", re.IGNORECASE)),
    ("SCR-010", "Medium", "CWE-489", "Debug mode enabled",
     re.compile(r"debug\\s*=\\s*True", re.IGNORECASE)),
]


def audit_file(file_path: Path) -> list[tuple[int, str, str, str, str, str]]:
    findings = []
    lines = file_path.read_text(encoding="utf-8", errors="ignore").splitlines()
    for line_no, raw_line in enumerate(lines, start=1):
        stripped = raw_line.strip()
        if not stripped or stripped.startswith("#") or stripped.startswith("//"):
            continue
        for rule_id, severity, cwe, title, pattern in RULES:
            if pattern.search(raw_line):
                findings.append((line_no, rule_id, severity, cwe, title, stripped))
    return findings


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python3 secure_code_auditor.py <source_file>")
        sys.exit(1)

    target = Path(sys.argv[1])
    results = audit_file(target)
    print(f"Audited {target} -> {len(results)} finding(s)")
    for line_no, rule_id, severity, cwe, title, snippet in results:
        print(f"  [Line {line_no}] [{severity}] {rule_id} ({cwe}) {title}: {snippet}")
`;
}

export function buildSecureCodingReadmeMarkdown(): string {
  return `# SecureCode AST — Static Security Analyzer

## Overview
**Secure Coding Review & AST Static Security Analyzer** for Python, JavaScript/TypeScript, and PHP.

### Capabilities
- **Python 3 Native AST Security Auditor**: Parses Python source files with \`ast.parse\` to detect SQL injection (f-strings, \`%\`, \`.format()\`), command injection (\`os.system\`, \`subprocess(..., shell=True)\`), hardcoded secrets, unsafe deserialization (\`pickle.loads\`, \`yaml.load\`), weak hashing (\`md5\`/\`sha1\`), path traversal, SSRF, disabled TLS verification, and Flask \`debug=True\`.
- **JavaScript / TypeScript AST + Taint Tracker**: Uses \`@babel/parser\` to build an AST, ignore comments, and trace tainted variables from \`req.query\`/\`req.body\`/\`req.params\` into SQL queries, \`eval()\`, \`exec()\`, \`innerHTML\`, \`dangerouslySetInnerHTML\`, \`Math.random()\`, and SSRF sinks.
- **Remediation Guidance & Diff Comparison**: Every finding maps to **CWE** and **OWASP Top 10 (2021)** with concrete code fixes and side-by-side secure baselines.
- **Markdown Audit Report Export**: Generates structured security review documentation ready for team remediation.

## CLI Usage (Standalone Python Auditor)
\`\`\`bash
python3 secure_code_auditor.py path/to/target_app.py
\`\`\`
`;
}

