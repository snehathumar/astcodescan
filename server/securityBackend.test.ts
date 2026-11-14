import test from 'node:test';
import assert from 'node:assert/strict';
import { runRealAstSecurityScan } from './astCodeScanner.ts';
import { analyzeRawEmailHeaders } from './phishingLiveAnalyzer.ts';
import { isPrivateOrReservedIp, validatePublicTargetUrl } from './ssrfGuard.ts';

test('SSRF guard blocks private, loopback, metadata, and link-local IPs', () => {
  assert.equal(isPrivateOrReservedIp('127.0.0.1'), true);
  assert.equal(isPrivateOrReservedIp('10.0.0.5'), true);
  assert.equal(isPrivateOrReservedIp('172.16.4.2'), true);
  assert.equal(isPrivateOrReservedIp('192.168.1.10'), true);
  assert.equal(isPrivateOrReservedIp('169.254.169.254'), true);
  assert.equal(isPrivateOrReservedIp('::1'), true);
  assert.equal(isPrivateOrReservedIp('fe80::1'), true);
  assert.equal(isPrivateOrReservedIp('8.8.8.8'), false);
  assert.equal(isPrivateOrReservedIp('140.82.121.4'), false);
});

test('validatePublicTargetUrl rejects localhost, internal metadata, and non-http schemes', async () => {
  await assert.rejects(() => validatePublicTargetUrl('http://localhost:3000'), /blocked/i);
  await assert.rejects(() => validatePublicTargetUrl('http://169.254.169.254/latest/meta-data'), /blocked/i);
  await assert.rejects(() => validatePublicTargetUrl('ftp://example.com/file'), /http/i);
});

test('TypeScript Compiler AST scanner tracks multi-line variable taint and ignores comments', async () => {
  const code = `
    // const fakeSecret = "sk_live_1234567890";
    const userId = req.query.id;
    const sql = "SELECT * FROM users WHERE id = " + userId;
    await db.query(sql);
    const key = "sk_live_realSecret987654";
  `;
  const report = await runRealAstSecurityScan(code, 'javascript');
  assert.equal(report.engine, 'Babel JS/TS/JSX AST + Taint Tracker');
  const ruleIds = new Set(report.findings.map((f) => f.ruleId));
  assert.ok(ruleIds.has('SCR-001'), 'Should detect multi-line tainted SQLi via variable');
  assert.ok(ruleIds.has('SCR-003'), 'Should detect hardcoded secret on variable declaration');
  assert.equal(report.findings.some((f) => f.line === 2), false, 'Should ignore commented line');
});

test('Python 3 native AST scanner parses Python AST nodes accurately', async () => {
  const py = `
import os
import hashlib

API_KEY = "AIzaSyDemoHardcodedKey12345"

def run(username):
    q = f"SELECT * FROM users WHERE name = '{username}'"
    os.system("echo " + username)
    return hashlib.md5(username.encode()).hexdigest()
`;
  const report = await runRealAstSecurityScan(py, 'python');
  assert.equal(report.engine, 'Python 3 Native AST Auditor');
  const rules = new Set(report.findings.map((f) => f.ruleId));
  assert.ok(rules.has('SCR-001'), 'Python AST should detect SQLi f-string');
  assert.ok(rules.has('SCR-002'), 'Python AST should detect os.system');
  assert.ok(rules.has('SCR-003'), 'Python AST should detect hardcoded API_KEY');
  assert.ok(rules.has('SCR-007'), 'Python AST should detect hashlib.md5');
});

test('analyzeRawEmailHeaders detects Reply-To mismatch and SPF/DKIM/DMARC failures', async () => {
  const rawEmail = `From: PayPal Support <service@paypal.com>
Reply-To: attacker@mail-relay.invalid
Return-Path: <bounce@spoof-server.invalid>
Subject: Urgent: Verify your account within 24 hours
Authentication-Results: mx.google.com; spf=fail smtp.mailfrom=spoof-server.invalid; dkim=fail; dmarc=fail

Click https://paypa1-verify.invalid/login to restore access.
`;
  const result = await analyzeRawEmailHeaders(rawEmail);
  assert.equal(result.verdict, 'High Spoofing Risk');
  assert.equal(result.authResults.spf, 'fail');
  assert.equal(result.authResults.dkim, 'fail');
  assert.equal(result.authResults.dmarc, 'fail');
  assert.equal(result.replyToDomain, 'mail-relay.invalid');
  assert.ok(result.extractedUrls.includes('https://paypa1-verify.invalid/login'));
});
