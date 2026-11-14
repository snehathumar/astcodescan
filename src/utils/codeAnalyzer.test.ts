import test from 'node:test';
import assert from 'node:assert/strict';
import { SECURE_CODE_SAMPLES } from '../data/secureCodeSamples';
import {
  analyzeSourceCode,
  buildSecureCodingPythonAuditor,
  buildSecureCodingReadmeMarkdown,
  generateAuditMarkdownReport,
} from './codeAnalyzer';

test('analyzeSourceCode detects expected critical and high findings in vulnerable Python Flask sample', () => {
  const sample = SECURE_CODE_SAMPLES.find((s) => s.id === 'python-flask-portal');
  assert.ok(sample);

  const report = analyzeSourceCode(sample.vulnerableCode, sample.language);
  const rules = new Set(report.findings.map((f) => f.ruleId));

  assert.equal(report.summary.postureLabel, 'Critical Risk');
  assert.ok(rules.has('SCR-001'), 'Should detect SQL Injection');
  assert.ok(rules.has('SCR-002'), 'Should detect Command Injection');
  assert.ok(rules.has('SCR-003'), 'Should detect Hardcoded Secret');
  assert.ok(rules.has('SCR-006'), 'Should detect Path Traversal');
  assert.ok(rules.has('SCR-007'), 'Should detect Weak MD5 Hash');
  assert.ok(rules.has('SCR-010'), 'Should detect Debug Mode enabled');
});

test('analyzeSourceCode passes clean baseline when scanning remediated samples', () => {
  const cleanSample = SECURE_CODE_SAMPLES.find((s) => s.id === 'clean-python-service');
  assert.ok(cleanSample);

  const report = analyzeSourceCode(cleanSample.vulnerableCode, cleanSample.language);
  assert.equal(report.summary.totalFindings, 0);
  assert.equal(report.summary.postureLabel, 'Clean Baseline');

  const flaskSample = SECURE_CODE_SAMPLES.find((s) => s.id === 'python-flask-portal');
  assert.ok(flaskSample);
  const fixedFlask = analyzeSourceCode(flaskSample.remediatedCode, flaskSample.language);
  assert.equal(fixedFlask.summary.totalFindings, 0);
});

test('analyzeSourceCode detects DOM XSS, eval, and weak PRNG in JavaScript widget', () => {
  const jsSample = SECURE_CODE_SAMPLES.find((s) => s.id === 'frontend-dom-widget');
  assert.ok(jsSample);

  const report = analyzeSourceCode(jsSample.vulnerableCode, 'javascript');
  const rules = new Set(report.findings.map((f) => f.ruleId));
  assert.ok(rules.has('SCR-004'), 'Should detect innerHTML XSS');
  assert.ok(rules.has('SCR-005'), 'Should detect eval()');
  assert.ok(rules.has('SCR-007'), 'Should detect Math.random()');
});

test('analyzeSourceCode detects SQLi, XSS, unserialize, and shell_exec in PHP admin sample', () => {
  const phpSample = SECURE_CODE_SAMPLES.find((s) => s.id === 'php-admin-portal');
  assert.ok(phpSample);

  const report = analyzeSourceCode(phpSample.vulnerableCode, 'php');
  assert.ok(report.summary.totalFindings >= 5);
  assert.equal(report.summary.postureLabel, 'Critical Risk');
});

test('generateAuditMarkdownReport and Python auditor builder produce valid artifacts', () => {
  const report = analyzeSourceCode('const API_KEY = "sk_test_1234567890";', 'javascript');
  const md = generateAuditMarkdownReport(report, 'Demo Service');
  assert.match(md, /# Secure Coding Review Report — Demo Service/);
  assert.match(md, /CWE-798/);
  assert.match(buildSecureCodingPythonAuditor(), /def audit_file/);
  assert.match(buildSecureCodingReadmeMarkdown(), /SecureCode AST/);
});
