import { execFile } from 'node:child_process';
import fs from 'node:fs/promises';
import path from 'node:path';
import { parse } from '@babel/parser';
import type { CodeLanguage } from '../src/data/secureCodeSamples.ts';
import {
  analyzeSourceCode,
  type AuditReport,
  type SecurityFinding,
  type Severity,
} from '../src/utils/codeAnalyzer.ts';

export interface AstAuditReport extends AuditReport {
  engine: string;
  parseError: string | null;
  analyzedAt: string;
}

const SEVERITY_ORDER: Record<Severity, number> = {
  Critical: 0,
  High: 1,
  Medium: 2,
  Low: 3,
};

interface AstNodeLike {
  type: string;
  loc?: { start?: { line: number; column: number }; end?: { line: number } } | null;
  [key: string]: unknown;
}

function walkAst(node: unknown, visitor: (n: AstNodeLike) => void): void {
  if (!node || typeof node !== 'object') return;
  if (Array.isArray(node)) {
    for (const item of node) {
      walkAst(item, visitor);
    }
    return;
  }
  const obj = node as AstNodeLike;
  if (typeof obj.type === 'string') {
    visitor(obj);
  }
  for (const key of Object.keys(obj)) {
    if (key === 'loc' || key === 'start' || key === 'end' || key === 'extra' || key === 'comments' || key === 'tokens') {
      continue;
    }
    const val = obj[key];
    if (val && typeof val === 'object') {
      walkAst(val, visitor);
    }
  }
}

function memberPath(node: unknown): string {
  if (!node || typeof node !== 'object') return '';
  const n = node as AstNodeLike;
  if (n.type === 'Identifier' && typeof n.name === 'string') return n.name;
  if (n.type === 'ThisExpression') return 'this';
  if (n.type === 'MemberExpression') {
    const objName = memberPath(n.object);
    const prop = n.property as AstNodeLike | undefined;
    const propName =
      prop && prop.type === 'Identifier' && typeof prop.name === 'string'
        ? prop.name
        : prop && prop.type === 'StringLiteral' && typeof prop.value === 'string'
          ? prop.value
          : '';
    if (objName && propName) return `${objName}.${propName}`;
    return propName || objName;
  }
  return '';
}

function extractStringFragments(node: unknown): string {
  if (!node || typeof node !== 'object') return '';
  const n = node as AstNodeLike;
  if (n.type === 'StringLiteral' && typeof n.value === 'string') return n.value;
  if (n.type === 'TemplateLiteral' && Array.isArray(n.quasis)) {
    return n.quasis
      .map((q) => ((q as AstNodeLike).value as { raw?: string })?.raw ?? '')
      .join(' ');
  }
  if (n.type === 'BinaryExpression' && n.operator === '+') {
    return `${extractStringFragments(n.left)} ${extractStringFragments(n.right)}`;
  }
  return '';
}

function scanJavaScriptWithBabelAst(code: string): {
  findings: SecurityFinding[];
  parseError: string | null;
} {
  let ast: unknown;
  let parseError: string | null = null;
  try {
    ast = parse(code, {
      sourceType: 'unambiguous',
      plugins: ['typescript', 'jsx'],
      errorRecovery: true,
    });
  } catch (err) {
    parseError = err instanceof Error ? err.message : 'Unable to parse JavaScript/TypeScript AST.';
    const fallback = analyzeSourceCode(code, 'javascript');
    return { findings: fallback.findings, parseError };
  }

  const lines = code.split(/\r?\n/);
  const findings: SecurityFinding[] = [];
  const seen = new Set<string>();
  const taintedVars = new Set<string>();
  const taintedSqlVars = new Set<string>();

  const addFinding = (
    ruleId: string,
    title: string,
    severity: Severity,
    cwe: string,
    owasp: string,
    node: AstNodeLike,
    explanation: string,
    remediation: string,
    secureExample: string
  ) => {
    const line = node.loc?.start?.line ?? 1;
    const key = `${ruleId}:${line}`;
    if (seen.has(key)) return;
    seen.add(key);
    findings.push({
      id: `${ruleId}-L${line}`,
      ruleId,
      title,
      severity,
      cwe,
      owasp,
      line,
      snippet: (lines[line - 1] ?? '').trim(),
      explanation,
      remediation,
      secureExample,
    });
  };

  const nodeContainsTaint = (rootNode: unknown): boolean => {
    let found = false;
    walkAst(rootNode, (n) => {
      if (found) return;
      if (n.type === 'Identifier' && typeof n.name === 'string' && taintedVars.has(n.name)) {
        found = true;
      } else if (n.type === 'MemberExpression') {
        const pathStr = memberPath(n);
        if (/\b(?:req|request)\.(?:query|body|params|headers|cookies)\b/.test(pathStr)) {
          found = true;
        }
      }
    });
    return found;
  };

  const isSqlText = (txt: string) => /\b(SELECT|INSERT|UPDATE|DELETE)\b/i.test(txt);

  // Pass 1: track tainted variables from req.query / req.body / req.params and SQL strings
  walkAst(ast, (n) => {
    if (n.type === 'VariableDeclarator') {
      const id = n.id as AstNodeLike | undefined;
      if (id?.type === 'Identifier' && typeof id.name === 'string' && n.init) {
        if (nodeContainsTaint(n.init)) {
          taintedVars.add(id.name);
          const initNode = n.init as AstNodeLike;
          if (
            (initNode.type === 'TemplateLiteral' || initNode.type === 'BinaryExpression') &&
            isSqlText(extractStringFragments(initNode))
          ) {
            taintedSqlVars.add(id.name);
          }
        }
      }
    }
  });

  // Pass 2: inspect AST nodes
  walkAst(ast, (n) => {
    // 1. Hardcoded secrets in VariableDeclarator
    if (n.type === 'VariableDeclarator') {
      const id = n.id as AstNodeLike | undefined;
      const init = n.init as AstNodeLike | undefined;
      if (id?.type === 'Identifier' && typeof id.name === 'string' && init) {
        let strVal: string | null = null;
        if (init.type === 'StringLiteral' && typeof init.value === 'string') {
          strVal = init.value;
        } else if (
          init.type === 'TemplateLiteral' &&
          Array.isArray(init.expressions) &&
          init.expressions.length === 0
        ) {
          strVal = extractStringFragments(init).trim();
        }
        if (strVal !== null) {
          const looksLikeSecretName = /(?:secret|api_?key|jwt_?secret|token|password|stripe_?secret)/i.test(
            id.name
          );
          const looksLikeKnownKey =
            /^(?:AIza[0-9A-Za-z_-]{10,}|sk_(?:live|test)_[0-9A-Za-z]{8,}|AKIA[0-9A-Z]{16}|ghp_[0-9A-Za-z]{20,})$/.test(
              strVal
            );
          if ((looksLikeSecretName && strVal.length >= 6) || looksLikeKnownKey) {
            addFinding(
              'SCR-003',
              'Hardcoded Secret, API Key, or Credential',
              'Critical',
              'CWE-798',
              'A07:2021 Auth Failures',
              n,
              `Variable "${id.name}" stores a static secret literal in source code.`,
              'Read credentials from process.env or Google Cloud Secret Manager at runtime.',
              'const STRIPE_SECRET = process.env.STRIPE_SECRET_KEY;'
            );
          }
        }
      }
    }

    // 2. DOM XSS via .innerHTML / .outerHTML assignment
    if (n.type === 'AssignmentExpression' && n.operator === '=') {
      const leftPath = memberPath(n.left);
      if (leftPath.endsWith('.innerHTML') || leftPath.endsWith('.outerHTML')) {
        addFinding(
          'SCR-004',
          'DOM Cross-Site Scripting (XSS) via innerHTML/outerHTML',
          'High',
          'CWE-79',
          'A03:2021 Injection',
          n,
          'Assigning HTML strings directly to innerHTML/outerHTML executes embedded scripts in the browser.',
          'Use .textContent or DOM element construction (createElement / replaceChildren).',
          'element.textContent = untrustedText;'
        );
      }
    }

    // 3. React dangerouslySetInnerHTML
    if (n.type === 'JSXAttribute') {
      const attrName = n.name as AstNodeLike | undefined;
      if (attrName?.type === 'JSXIdentifier' && attrName.name === 'dangerouslySetInnerHTML') {
        addFinding(
          'SCR-004',
          'React dangerouslySetInnerHTML XSS Sink',
          'High',
          'CWE-79',
          'A03:2021 Injection',
          n,
          'dangerouslySetInnerHTML bypasses React automatic XSS escaping.',
          'Render plain text in JSX or sanitize strictly with DOMPurify before rendering.',
          '<div>{safeText}</div>'
        );
      }
    }

    // 4. Object properties: rejectUnauthorized: false, origin: '*'
    if (n.type === 'ObjectProperty') {
      const keyNode = n.key as AstNodeLike | undefined;
      const keyName =
        keyNode?.type === 'Identifier'
          ? String(keyNode.name ?? '')
          : keyNode?.type === 'StringLiteral'
            ? String(keyNode.value ?? '')
            : '';
      const valNode = n.value as AstNodeLike | undefined;

      if (keyName === 'rejectUnauthorized' && valNode?.type === 'BooleanLiteral' && valNode.value === false) {
        addFinding(
          'SCR-008',
          'TLS Certificate Verification Disabled (rejectUnauthorized: false)',
          'High',
          'CWE-295',
          'A02:2021 Cryptographic Failures',
          n,
          'Disabling TLS verification allows Man-in-the-Middle interception.',
          'Keep rejectUnauthorized set to true (default).',
          'new https.Agent({ rejectUnauthorized: true })'
        );
      }
      if (keyName === 'origin' && valNode?.type === 'StringLiteral' && valNode.value === '*') {
        addFinding(
          'SCR-011',
          'Permissive Wildcard CORS Origin (*)',
          'Medium',
          'CWE-942',
          'A05:2021 Security Misconfiguration',
          n,
          'Wildcard CORS allows any external site to read API responses.',
          'Restrict CORS origins to explicit trusted domains.',
          'cors({ origin: "https://portal.example.com" })'
        );
      }
    }

    // 5. Call expressions
    if (n.type === 'CallExpression') {
      const calleeName = memberPath(n.callee);
      const args = Array.isArray(n.arguments) ? (n.arguments as AstNodeLike[]) : [];
      const arg0 = args[0];

      if (calleeName === 'eval' || calleeName === 'Function') {
        addFinding(
          'SCR-005',
          `Unsafe Dynamic Code Execution (${calleeName})`,
          'Critical',
          'CWE-94',
          'A08:2021 Data Integrity Failures',
          n,
          `${calleeName}() executes arbitrary JavaScript strings with full runtime privileges.`,
          'Replace dynamic evaluation with JSON.parse() or explicit lookup tables.',
          'const value = RATES[tier] ?? 1.0;'
        );
      }

      if (
        calleeName === 'exec' ||
        calleeName.endsWith('.exec') ||
        calleeName === 'execSync' ||
        calleeName.endsWith('.execSync')
      ) {
        if (arg0 && (arg0.type !== 'StringLiteral' || nodeContainsTaint(arg0))) {
          addFinding(
            'SCR-002',
            'OS Command Injection via Shell exec()',
            'Critical',
            'CWE-78',
            'A03:2021 Injection',
            n,
            'Concatenating or interpolating variables into exec() allows arbitrary shell command execution.',
            'Use execFile() with an explicit argument array and allowlist validation.',
            'execFile("node", ["scripts/export.js", "--format", format], callback);'
          );
        }
      }

      if (/(?:^|\.)(?:query|execute|raw)$/.test(calleeName) && arg0) {
        if (
          (arg0.type === 'TemplateLiteral' &&
            Array.isArray(arg0.expressions) &&
            arg0.expressions.length > 0 &&
            isSqlText(extractStringFragments(arg0))) ||
          (arg0.type === 'BinaryExpression' && isSqlText(extractStringFragments(arg0)))
        ) {
          addFinding(
            'SCR-001',
            'SQL Injection via Dynamic Query Construction',
            'Critical',
            'CWE-89',
            'A03:2021 Injection',
            n,
            'Interpolating variables into SQL query strings lets attackers alter query structure.',
            'Use parameterized queries ($1, ?) with bound parameter arrays.',
            'await db.query("SELECT * FROM orders WHERE customer_id = $1", [customerId]);'
          );
        } else if (
          arg0.type === 'Identifier' &&
          typeof arg0.name === 'string' &&
          (taintedSqlVars.has(arg0.name) || taintedVars.has(arg0.name))
        ) {
          addFinding(
            'SCR-001',
            'SQL Injection via Tainted Query Variable',
            'Critical',
            'CWE-89',
            'A03:2021 Injection',
            n,
            `Tainted variable "${arg0.name}" flows into ${calleeName}().`,
            'Use parameterized queries ($1, ?) with bound parameter arrays.',
            'await db.query("SELECT * FROM orders WHERE customer_id = $1", [customerId]);'
          );
        }
      }

      if (calleeName === 'Math.random') {
        addFinding(
          'SCR-007',
          'Predictable PRNG (Math.random) Used in Code',
          'High',
          'CWE-338',
          'A02:2021 Cryptographic Failures',
          n,
          'Math.random() is not cryptographically secure and should never generate tokens, IDs, or secrets.',
          'Use crypto.getRandomValues() or Node crypto.randomBytes().',
          'crypto.getRandomValues(new Uint8Array(24));'
        );
      }

      if (calleeName === 'document.write' || calleeName === 'document.writeln') {
        addFinding(
          'SCR-004',
          'DOM XSS Risk via document.write()',
          'High',
          'CWE-79',
          'A03:2021 Injection',
          n,
          'document.write() injects raw HTML directly into the DOM stream.',
          'Use DOM node creation with textContent instead.',
          'container.textContent = message;'
        );
      }

      if (calleeName.endsWith('createHash') && arg0?.type === 'StringLiteral' && typeof arg0.value === 'string') {
        const algo = arg0.value.toLowerCase();
        if (algo === 'md5' || algo === 'sha1') {
          addFinding(
            'SCR-007',
            `Weak Cryptographic Hash (${algo.toUpperCase()})`,
            'High',
            'CWE-328',
            'A02:2021 Cryptographic Failures',
            n,
            `${algo.toUpperCase()} is collision-prone and weak for security digests.`,
            'Use SHA-256+ for integrity or Argon2/scrypt/PBKDF2 for passwords.',
            'crypto.createHash("sha256").update(data).digest("hex")'
          );
        }
      }

      if (calleeName === 'fetch' && arg0 && nodeContainsTaint(arg0)) {
        addFinding(
          'SCR-009',
          'Server-Side Request Forgery (SSRF) via Untrusted URL in fetch()',
          'High',
          'CWE-918',
          'A10:2021 SSRF',
          n,
          'Untrusted request input flows directly into outbound fetch().',
          'Validate URL protocol (HTTPS) and allowlisted hostnames before fetching.',
          'if (parsed.protocol !== "https:" || !ALLOWED_HOSTS.has(parsed.hostname)) return 400;'
        );
      }

      if (calleeName.endsWith('.setHeader') && args.length >= 2) {
        const hName = args[0]?.type === 'StringLiteral' ? String(args[0].value ?? '').toLowerCase() : '';
        const hVal = args[1]?.type === 'StringLiteral' ? String(args[1].value ?? '') : '';
        if (hName === 'access-control-allow-origin' && hVal === '*') {
          addFinding(
            'SCR-011',
            'Permissive Wildcard CORS Header (*)',
            'Medium',
            'CWE-942',
            'A05:2021 Security Misconfiguration',
            n,
            'Setting Access-Control-Allow-Origin to "*" permits arbitrary origins to read API responses.',
            'Specify an explicit trusted origin allowlist.',
            'res.setHeader("Access-Control-Allow-Origin", "https://portal.example.com");'
          );
        }
      }
    }
  });

  return { findings, parseError };
}

async function scanPythonWithPythonAst(code: string): Promise<{
  findings: SecurityFinding[];
  parseError: string | null;
}> {
  const scriptPath = path.resolve(process.cwd(), 'server/python_ast_auditor.py');
  return new Promise((resolve) => {
    const child = execFile(
      'python3',
      [scriptPath],
      { timeout: 4500, maxBuffer: 1024 * 1024 },
      (error, stdout) => {
        if (error) {
          const fallback = analyzeSourceCode(code, 'python');
          resolve({ findings: fallback.findings, parseError: null });
          return;
        }
        try {
          const parsed = JSON.parse(stdout) as {
            parseError: string | null;
            findings: SecurityFinding[];
          };
          resolve({
            findings: Array.isArray(parsed.findings) ? parsed.findings : [],
            parseError: parsed.parseError ?? null,
          });
        } catch {
          const fallback = analyzeSourceCode(code, 'python');
          resolve({ findings: fallback.findings, parseError: null });
        }
      }
    );
    child.stdin?.write(code);
    child.stdin?.end();
  });
}

export async function runRealAstSecurityScan(
  code: string,
  language: CodeLanguage
): Promise<AstAuditReport> {
  const safeCode = typeof code === 'string' ? code : '';
  const lineCount = safeCode.trim() ? safeCode.split(/\r?\n/).length : 0;

  let findings: SecurityFinding[] = [];
  let parseError: string | null = null;
  let engine = 'Pattern & Taint Analyzer';

  if (language === 'javascript') {
    const astResult = scanJavaScriptWithBabelAst(safeCode);
    findings = astResult.findings;
    parseError = astResult.parseError;
    engine = 'Babel JS/TS/JSX AST + Taint Tracker';
  } else if (language === 'python') {
    const pyResult = await scanPythonWithPythonAst(safeCode);
    findings = pyResult.findings;
    parseError = pyResult.parseError;
    engine = 'Python 3 Native AST Auditor';
  } else {
    const phpResult = analyzeSourceCode(safeCode, 'php');
    findings = phpResult.findings;
    engine = 'PHP Security Rule & Sink Scanner';
  }

  findings.sort((a, b) => {
    const sevDiff = SEVERITY_ORDER[a.severity] - SEVERITY_ORDER[b.severity];
    return sevDiff !== 0 ? sevDiff : a.line - b.line;
  });

  const critical = findings.filter((f) => f.severity === 'Critical').length;
  const high = findings.filter((f) => f.severity === 'High').length;
  const medium = findings.filter((f) => f.severity === 'Medium').length;
  const low = findings.filter((f) => f.severity === 'Low').length;

  let postureLabel: AstAuditReport['summary']['postureLabel'] = 'Clean Baseline';
  if (critical > 0) postureLabel = 'Critical Risk';
  else if (high > 0) postureLabel = 'High Risk';
  else if (medium > 0 || low > 0) postureLabel = 'Moderate Risk';

  return {
    language,
    findings,
    engine,
    parseError,
    analyzedAt: new Date().toISOString(),
    summary: {
      totalFindings: findings.length,
      critical,
      high,
      medium,
      low,
      postureLabel,
      linesScanned: lineCount,
    },
  };
}

export interface WorkspaceFileOption {
  path: string;
  language: CodeLanguage;
}

const ALLOWED_WORKSPACE_EXTENSIONS = new Set(['.ts', '.tsx', '.js', '.jsx', '.py', '.php']);

export async function listWorkspaceSourceFiles(): Promise<WorkspaceFileOption[]> {
  const root = process.cwd();
  const candidates: WorkspaceFileOption[] = [];

  const walk = async (relDir: string) => {
    const absDir = path.resolve(root, relDir);
    if (!absDir.startsWith(root)) return;
    let entries;
    try {
      entries = await fs.readdir(absDir, { withFileTypes: true });
    } catch {
      return;
    }
    for (const entry of entries) {
      if (entry.name.startsWith('.') || entry.name === 'node_modules' || entry.name === 'dist') {
        continue;
      }
      const relPath = relDir ? `${relDir}/${entry.name}` : entry.name;
      if (entry.isDirectory()) {
        await walk(relPath);
      } else {
        const ext = path.extname(entry.name).toLowerCase();
        if (ALLOWED_WORKSPACE_EXTENSIONS.has(ext) && !entry.name.endsWith('.test.ts')) {
          const language: CodeLanguage =
            ext === '.py' ? 'python' : ext === '.php' ? 'php' : 'javascript';
          candidates.push({ path: relPath, language });
        }
      }
    }
  };

  await walk('src');
  await walk('server');
  candidates.push({ path: 'server.ts', language: 'javascript' });
  return candidates.sort((a, b) => a.path.localeCompare(b.path));
}

export async function readAllowedWorkspaceFile(
  relPath: string
): Promise<{ code: string; language: CodeLanguage } | null> {
  const allowed = await listWorkspaceSourceFiles();
  const match = allowed.find((f) => f.path === relPath);
  if (!match) return null;

  const absPath = path.resolve(process.cwd(), match.path);
  if (!absPath.startsWith(process.cwd())) return null;

  const code = await fs.readFile(absPath, 'utf-8');
  return { code, language: match.language };
}
