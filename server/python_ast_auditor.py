#!/usr/bin/env python3
"""
Real Python AST Static Security Auditor.
Parses Python source from stdin using Python's built-in `ast` module (never executes code)
and emits JSON findings to stdout.
"""

import ast
import json
import re
import sys


SECRET_NAME_RE = re.compile(r"(secret|api_?key|token|password|passwd|jwt_?secret|private_?key)", re.I)
KNOWN_KEY_RE = re.compile(r"^(AIza[0-9A-Za-z_-]{10,}|sk_(?:live|test)_[0-9A-Za-z]{8,}|AKIA[0-9A-Z]{16}|ghp_[0-9A-Za-z]{20,})$")
SQL_KW_RE = re.compile(r"\b(SELECT|INSERT|UPDATE|DELETE)\b", re.I)


def get_call_name(node: ast.Call) -> str:
    func = node.func
    if isinstance(func, ast.Name):
        return func.id
    if isinstance(func, ast.Attribute):
        parts = [func.attr]
        curr = func.value
        while isinstance(curr, ast.Attribute):
            parts.append(curr.attr)
            curr = curr.value
        if isinstance(curr, ast.Name):
            parts.append(curr.id)
        return ".".join(reversed(parts))
    return ""


def is_tainted_sql_expr(expr: ast.AST, tainted_vars: set[str]) -> bool:
    if isinstance(expr, ast.JoinedStr):
        text = "".join(v.value for v in expr.values if isinstance(v, ast.Constant) and isinstance(v.value, str))
        return bool(SQL_KW_RE.search(text)) and any(isinstance(v, ast.FormattedValue) for v in expr.values)
    if isinstance(expr, ast.BinOp) and isinstance(expr.op, (ast.Add, ast.Mod)):
        if isinstance(expr.left, ast.Constant) and isinstance(expr.left.value, str):
            return bool(SQL_KW_RE.search(expr.left.value))
    if isinstance(expr, ast.Call) and isinstance(expr.func, ast.Attribute) and expr.func.attr == "format":
        if isinstance(expr.func.value, ast.Constant) and isinstance(expr.func.value.value, str):
            return bool(SQL_KW_RE.search(expr.func.value.value))
    if isinstance(expr, ast.Name) and expr.id in tainted_vars:
        return True
    return False


def expr_mentions_user_input(expr: ast.AST, tainted_vars: set[str]) -> bool:
    for child in ast.walk(expr):
        if isinstance(child, ast.Name) and child.id in tainted_vars:
            return True
        if isinstance(child, ast.Attribute) and child.attr in {"args", "form", "json", "data", "values", "cookies", "headers"}:
            return True
    return False


def scan_python(source: str) -> dict:
    lines = source.splitlines()
    try:
        tree = ast.parse(source)
    except SyntaxError as exc:
        return {
            "parseError": f"Python SyntaxError at line {exc.lineno}: {exc.msg}",
            "findings": [],
        }

    findings = []
    seen = set()
    tainted_vars: set[str] = set()
    tainted_sql_vars: set[str] = set()

    def add_finding(rule_id: str, title: str, severity: str, cwe: str, owasp: str, lineno: int, explanation: str, remediation: str, secure_example: str):
        key = (rule_id, lineno)
        if key in seen:
            return
        seen.add(key)
        snippet = lines[lineno - 1].strip() if 1 <= lineno <= len(lines) else ""
        findings.append({
            "id": f"{rule_id}-L{lineno}",
            "ruleId": rule_id,
            "title": title,
            "severity": severity,
            "cwe": cwe,
            "owasp": owasp,
            "line": lineno,
            "snippet": snippet,
            "explanation": explanation,
            "remediation": remediation,
            "secureExample": secure_example,
        })

    # Pass 1: collect tainted variables from request.* or SQL-interpolated variables
    for node in ast.walk(tree):
        if isinstance(node, ast.Assign):
            val = node.value
            if expr_mentions_user_input(val, tainted_vars):
                for tgt in node.targets:
                    if isinstance(tgt, ast.Name):
                        tainted_vars.add(tgt.id)
            if is_tainted_sql_expr(val, tainted_sql_vars):
                for tgt in node.targets:
                    if isinstance(tgt, ast.Name):
                        tainted_sql_vars.add(tgt.id)
                        add_finding(
                            "SCR-001",
                            "SQL Injection via String Interpolation / Concatenation",
                            "Critical",
                            "CWE-89",
                            "A03:2021 Injection",
                            node.lineno,
                            "Constructing SQL queries with f-strings, %, .format(), or concatenation allows attackers to manipulate query logic.",
                            "Use parameterized queries with bound placeholders (?, %s) passed as a tuple.",
                            'conn.execute("SELECT id FROM users WHERE username = ?", (username,))',
                        )

            # Check hardcoded secrets in assignments or dict subscripts like app.config["SECRET_KEY"] = "..."
            if isinstance(val, ast.Constant) and isinstance(val.value, str) and len(val.value) >= 6:
                is_secret_target = False
                for tgt in node.targets:
                    if isinstance(tgt, ast.Name) and SECRET_NAME_RE.search(tgt.id):
                        is_secret_target = True
                    elif isinstance(tgt, ast.Subscript) and isinstance(tgt.slice, ast.Constant) and isinstance(tgt.slice.value, str):
                        if SECRET_NAME_RE.search(tgt.slice.value):
                            is_secret_target = True
                if is_secret_target or KNOWN_KEY_RE.match(val.value):
                    add_finding(
                        "SCR-003",
                        "Hardcoded Secret, API Key, or Credential",
                        "Critical",
                        "CWE-798",
                        "A07:2021 Auth Failures",
                        node.lineno,
                        "Credentials embedded in Python source code can leak through Git history, logs, or container layers.",
                        "Load secrets at runtime from os.environ or Google Cloud Secret Manager.",
                        'app.config["SECRET_KEY"] = os.environ["FLASK_SECRET_KEY"]',
                    )

    # Pass 2: inspect AST Call nodes
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        call_name = get_call_name(node)

        # SQL execute with tainted SQL or inline formatting
        if call_name.endswith(".execute") or call_name == "execute":
            if node.args and is_tainted_sql_expr(node.args[0], tainted_sql_vars):
                add_finding(
                    "SCR-001",
                    "SQL Injection via String Interpolation / Concatenation",
                    "Critical",
                    "CWE-89",
                    "A03:2021 Injection",
                    node.lineno,
                    "Executing dynamically formatted SQL allows attackers to inject arbitrary SQL clauses.",
                    "Pass query parameters as a separate tuple argument to execute().",
                    'conn.execute("SELECT id FROM users WHERE username = ?", (username,))',
                )

        # OS Command Injection
        if call_name in {"os.system", "os.popen"} or (
            call_name.startswith("subprocess.") and any(kw.arg == "shell" and isinstance(kw.value, ast.Constant) and kw.value.value is True for kw in node.keywords)
        ):
            add_finding(
                "SCR-002",
                "OS Command Injection Risk",
                "Critical",
                "CWE-78",
                "A03:2021 Injection",
                node.lineno,
                "Invoking a shell interpreter (os.system or shell=True) enables command chaining when input reaches arguments.",
                "Use subprocess.run([...], shell=False) with an explicit argument list and allowlist validation.",
                'subprocess.run(["ping", "-c", "1", validated_host], shell=False, check=False)',
            )

        # XSS via render_template_string
        if call_name == "render_template_string" or call_name.endswith(".render_template_string"):
            add_finding(
                "SCR-004",
                "Server-Side Template Injection / XSS Risk",
                "High",
                "CWE-79",
                "A03:2021 Injection",
                node.lineno,
                "render_template_string with dynamic content can allow Jinja2 template injection or unescaped HTML output.",
                "Use static template files with render_template() so Jinja2 auto-escaping applies.",
                'return render_template("profile.html", username=username)',
            )

        # Unsafe eval / exec / pickle / yaml.load
        if call_name in {"eval", "exec", "pickle.loads", "pickle.load", "marshal.loads"}:
            add_finding(
                "SCR-005",
                "Unsafe Code Execution or Deserialization",
                "Critical",
                "CWE-502",
                "A08:2021 Data Integrity Failures",
                node.lineno,
                f"{call_name}() executes arbitrary Python code or reconstructs unsafe objects from untrusted input.",
                "Replace with json.loads() or ast.literal_eval() for safe data parsing.",
                "data = json.loads(raw_payload)",
            )
        if call_name == "yaml.load":
            has_safe_loader = any(
                kw.arg == "Loader" and isinstance(kw.value, ast.Attribute | ast.Name) and "SafeLoader" in ast.dump(kw.value)
                for kw in node.keywords
            )
            if not has_safe_loader:
                add_finding(
                    "SCR-005",
                    "Unsafe YAML Deserialization (yaml.load)",
                    "Critical",
                    "CWE-502",
                    "A08:2021 Data Integrity Failures",
                    node.lineno,
                    "yaml.load() without SafeLoader can instantiate arbitrary Python objects and execute code.",
                    "Use yaml.safe_load() instead of yaml.load().",
                    "config = yaml.safe_load(raw_yaml)",
                )

        # Path Traversal
        if call_name in {"send_file", "open"} or call_name.endswith(".send_file"):
            if node.args and expr_mentions_user_input(node.args[0], tainted_vars):
                add_finding(
                    "SCR-006",
                    "Path Traversal in File Access",
                    "High",
                    "CWE-22",
                    "A01:2021 Broken Access Control",
                    node.lineno,
                    "Passing user-controlled filenames directly into open() or send_file() allows ../ directory traversal.",
                    "Use werkzeug.utils.safe_join() or Path.resolve() prefix checks inside an allowlisted directory.",
                    "safe_path = safe_join(str(REPORTS_DIR), filename)",
                )

        # Weak Cryptography
        if call_name in {"hashlib.md5", "hashlib.sha1"}:
            add_finding(
                "SCR-007",
                "Weak Cryptographic Hash (MD5 / SHA-1)",
                "High",
                "CWE-328",
                "A02:2021 Cryptographic Failures",
                node.lineno,
                f"{call_name}() is cryptographically broken and unsuitable for passwords or security digests.",
                "Use Argon2, bcrypt, or werkzeug.security.generate_password_hash for passwords and SHA-256+ for digests.",
                "pwd_hash = generate_password_hash(password)",
            )

        # TLS verification disabled & SSRF
        if call_name.startswith("requests."):
            for kw in node.keywords:
                if kw.arg == "verify" and isinstance(kw.value, ast.Constant) and kw.value.value is False:
                    add_finding(
                        "SCR-008",
                        "TLS Certificate Verification Disabled (verify=False)",
                        "High",
                        "CWE-295",
                        "A02:2021 Cryptographic Failures",
                        node.lineno,
                        "Disabling TLS verification allows Man-in-the-Middle interception of HTTPS traffic.",
                        "Remove verify=False so requests verifies certificates against trusted CAs.",
                        "resp = requests.get(url, timeout=5)",
                    )
            if node.args and expr_mentions_user_input(node.args[0], tainted_vars):
                add_finding(
                    "SCR-009",
                    "Server-Side Request Forgery (SSRF) Sink",
                    "High",
                    "CWE-918",
                    "A10:2021 SSRF",
                    node.lineno,
                    "Making outbound HTTP requests to unvalidated user-supplied URLs exposes internal services and metadata endpoints.",
                    "Validate URL scheme (HTTPS only) and restrict hostnames against an allowlist.",
                    "if parsed.hostname not in ALLOWED_HOSTS: abort(400)",
                )

        # Flask debug=True
        if call_name.endswith(".run"):
            for kw in node.keywords:
                if kw.arg == "debug" and isinstance(kw.value, ast.Constant) and kw.value.value is True:
                    add_finding(
                        "SCR-010",
                        "Debug Mode Enabled in Server Run",
                        "Medium",
                        "CWE-489",
                        "A05:2021 Security Misconfiguration",
                        node.lineno,
                        "Flask debug=True exposes an interactive Werkzeug debugger and stack traces to clients.",
                        "Set debug=False in production and read debug flags strictly from development env config.",
                        'app.run(host="127.0.0.1", port=5000, debug=False)',
                    )

    return {"parseError": None, "findings": findings}


if __name__ == "__main__":
    source_code = sys.stdin.read()
    result = scan_python(source_code)
    print(json.dumps(result))
