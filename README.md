# SecureCode AST — Static Security Analyzer

A real full-stack **Secure Coding Review & AST Static Analysis Workbench** for Python, JavaScript/TypeScript, and PHP.

## Capabilities

- **Python 3 Native AST Auditor (`server/python_ast_auditor.py`)**: Parses `.py` source safely via `ast.parse` on `stdin` (zero code execution) with variable taint tracking for SQL/Command injection, `eval`/`exec`/`pickle`, hardcoded secrets, weak hashes (`md5`/`sha1`), disabled TLS (`verify=False`), Flask/Django `debug=True`, and SSRF sinks.
- **Babel JS/TS/JSX AST + Taint Tracker (`server/astCodeScanner.ts`)**: Uses `@babel/parser` to inspect JavaScript, TypeScript, JSX, and TSX AST nodes and track tainted variables across statements into SQL sinks, `child_process` shells, `eval`/`new Function`, `dangerouslySetInnerHTML`/`innerHTML`, and wildcard CORS headers.
- **PHP Security Rule & Sink Scanner**: Multi-rule static detection covering SQL concatenation, `shell_exec`/`exec`, `eval`, hardcoded secrets, and path traversal.
- **Live Workspace File Scanner & Local File Upload**: Enumerates and audits real `.py`, `.js`, `.ts`, `.tsx`, `.jsx`, and `.php` files in the project workspace via `/api/code-review/workspace-files` and `/api/code-review/scan-workspace`, or accepts local source uploads.
- **Interactive Inspector, Remediation Diff & Export Kit**: Line-highlighted findings inspector with OWASP Top 10 / CWE references, side-by-side vulnerable vs. remediated diff view, persistent server-side audit history (`/api/history`), downloadable Markdown Audit Reports (`.md`), and standalone Python CLI auditor (`secure_code_auditor.py`).

## Local Development & Verification

```bash
npm install
npx --yes tsx --test src/utils/codeAnalyzer.test.ts server/securityBackend.test.ts
npm run lint
npm run build
npm run dev
```

The unified Express + Vite server listens on `http://localhost:3000`.

## Security & Deployment Configuration (Google Cloud Run)

### 1. Prerequisites
Enable required Google Cloud APIs and authenticate with `gcloud`:
```bash
gcloud services enable run.googleapis.com secretmanager.googleapis.com firestore.googleapis.com
```

### 2. Secret Management (Zero-Hardcoding Hygiene)
Store any runtime secrets in Google Cloud Secret Manager rather than source files:
```bash
gcloud secrets create GEMINI_API_KEY --replication-policy="automatic"
echo -n "YOUR_API_KEY" | gcloud secrets versions add GEMINI_API_KEY --data-file=-

gcloud secrets add-iam-policy-binding GEMINI_API_KEY \
  --member="serviceAccount:YOUR_PROJECT_NUMBER-compute@developer.gserviceaccount.com" \
  --role="roles/secretmanager.secretAccessor"
```

### 3. Firestore Security Rules Reference
If persisting audit records in Cloud Firestore, enforce owner-bound access control (`firestore.rules`):
```javascript
rules_version = '2';
service cloud.firestore {
  match /databases/{database}/documents {
    match /users/{userId}/interactions/{interactionId} {
      allow read, write: if request.auth != null && request.auth.uid == userId;
    }
  }
}
```

### 4. Cloud Run Deployment & Verification Label
```bash
gcloud run deploy securecode-ast-analyzer \
  --source . \
  --region us-central1 \
  --allow-unauthenticated

gcloud run services update securecode-ast-analyzer \
  --update-labels=dev-tutorial=cloud-run-ai-challenge \
  --region=us-central1
```
