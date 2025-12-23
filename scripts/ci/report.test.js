#!/usr/bin/env node
// CI Report Generator Tests

const assert = require('assert');
const path = require('path');
const fs = require('fs');

const { generateReport, truncateHash, scrubSecrets, redactUri, groupBySeverity } = require('./report.js');

// Test helpers
let passed = 0;
let failed = 0;

function test(name, fn) {
    try {
        fn();
        console.log(`✅ ${name}`);
        passed++;
    } catch (err) {
        console.log(`❌ ${name}`);
        console.log(`   ${err.message}`);
        failed++;
    }
}

// Load fixtures
const fixturesDir = path.join(__dirname, '../../testdata/ci');

function loadFixture(name) {
    return JSON.parse(fs.readFileSync(path.join(fixturesDir, name), 'utf8'));
}

// truncateHash tests

test('truncateHash: shortens long hashes when redact=true', () => {
    const result = truncateHash('sha256:1a2b3c4d5e6f7890abcdef', true);
    assert.strictEqual(result, 'sha256:1a2b…');
});

test('truncateHash: shows full hash when redact=false', () => {
    const result = truncateHash('sha256:1a2b3c4d5e6f7890abcdef', false);
    assert.strictEqual(result, 'sha256:1a2b3c4d5e6f7890abcdef');
});

test('truncateHash: preserves short hashes', () => {
    const result = truncateHash('sha256:ab', true);
    assert.strictEqual(result, 'sha256:ab');
});

test('truncateHash: handles null/empty', () => {
    assert.strictEqual(truncateHash(null), null);
    assert.strictEqual(truncateHash(''), '');
});

// scrubSecrets tests

test('scrubSecrets: filters API keys', () => {
    const msg = 'Config: API_KEY=sk-secret-12345';
    const result = scrubSecrets(msg);
    assert.ok(!result.includes('sk-secret-12345'), 'Should not contain secret');
    assert.ok(result.includes('[REDACTED]'), 'Should contain redaction marker');
});

test('scrubSecrets: filters GitHub tokens', () => {
    const msg = 'Using token ghp_1234567890abcdefghijklmnopqrstuv1234';
    const result = scrubSecrets(msg);
    assert.ok(!result.includes('ghp_'), 'Should not contain GitHub token');
});

test('scrubSecrets: filters OpenAI keys', () => {
    const msg = 'Key is sk-proj-abcdefghijklmnopqrstuvwxyz123456';
    const result = scrubSecrets(msg);
    assert.ok(!result.includes('sk-proj-'), 'Should not contain OpenAI key');
});

test('scrubSecrets: preserves safe content', () => {
    const msg = 'Description changed from X to Y';
    const result = scrubSecrets(msg);
    assert.strictEqual(result, msg);
});

// redactUri tests

test('redactUri: preserves template URIs with placeholders', () => {
    const uri = 'file:///{path}/subdir';
    const result = redactUri(uri, true);
    assert.strictEqual(result, uri);
});

test('redactUri: redacts file paths when redact=true', () => {
    const uri = 'file:///home/user/sensitive/path/file.txt';
    const result = redactUri(uri, true);
    assert.ok(!result.includes('sensitive'), 'Should not contain path components');
    assert.ok(result.startsWith('file://'), 'Should keep scheme');
});

test('redactUri: shows full path when redact=false', () => {
    const uri = 'file:///home/user/sensitive/path/file.txt';
    const result = redactUri(uri, false);
    assert.strictEqual(result, uri);
});

// groupBySeverity tests

test('groupBySeverity: groups correctly', () => {
    const drifts = [
        { severity: 'CRITICAL', type: 'A' },
        { severity: 'MODERATE', type: 'B' },
        { severity: 'CRITICAL', type: 'C' },
        { severity: 'INFO', type: 'D' },
    ];
    const groups = groupBySeverity(drifts);
    assert.strictEqual(groups.CRITICAL.length, 2);
    assert.strictEqual(groups.MODERATE.length, 1);
    assert.strictEqual(groups.INFO.length, 1);
});

test('groupBySeverity: handles empty array', () => {
    const groups = groupBySeverity([]);
    assert.strictEqual(groups.CRITICAL.length, 0);
    assert.strictEqual(groups.MODERATE.length, 0);
    assert.strictEqual(groups.INFO.length, 0);
});

// generateReport tests

test('generateReport: PASS output contains PASS and no CRITICAL section', () => {
    const data = loadFixture('check_pass.json');
    const report = generateReport(data, true);
    assert.ok(report.includes('✅'), 'Should have success emoji');
    assert.ok(report.includes('PASS'), 'Should contain PASS');
    assert.ok(!report.includes('CRITICAL'), 'Should not have CRITICAL section');
    assert.ok(report.includes('No drift detected'), 'Should say no drift');
});

test('generateReport: FAIL drift groups CRITICAL/MODERATE correctly', () => {
    const data = loadFixture('check_fail_drift.json');
    const report = generateReport(data, true);
    assert.ok(report.includes('❌'), 'Should have failure emoji');
    assert.ok(report.includes('FAIL'), 'Should contain FAIL');
    assert.ok(report.includes('CRITICAL (2)'), 'Should have 2 critical');
    assert.ok(report.includes('MODERATE (1)'), 'Should have 1 moderate');
    assert.ok(report.includes('PROMPT_ADDED'), 'Should list drift types');
});

test('generateReport: FAIL policy shows denial reasons', () => {
    const data = loadFixture('check_fail_policy.json');
    const report = generateReport(data, true);
    assert.ok(report.includes('Policy:'), 'Should have policy section');
    assert.ok(report.includes('DENY'), 'Should show DENY');
    assert.ok(report.includes('no_file_scheme'), 'Should show rule name');
});

test('generateReport: redacts hashes when redact=true', () => {
    const data = loadFixture('check_fail_drift.json');
    const report = generateReport(data, true);
    // Full hash should not appear
    assert.ok(!report.includes('1a2b3c4d5e6f7890abcdef'), 'Should not contain full hash');
    // Truncated hash should appear
    assert.ok(report.includes('sha256:1a2b…'), 'Should contain truncated hash');
});

test('generateReport: shows full hashes when redact=false', () => {
    const data = loadFixture('check_fail_drift.json');
    const report = generateReport(data, false);
    // Full hash should appear when redaction disabled
    assert.ok(report.includes('sha256:1a2b3c4d5e6f7890abcdef'), 'Should contain full hash');
});

test('generateReport: ALWAYS scrubs secrets from messages (even with redact=false)', () => {
    const data = loadFixture('check_with_secrets.json');
    // Even with redact=false, secrets should be scrubbed
    const report = generateReport(data, false);
    assert.ok(!report.includes('sk-secret-12345'), 'Should not contain secret even with redact=false');
});

test('generateReport: scrubs secrets with redact=true', () => {
    const data = loadFixture('check_with_secrets.json');
    const report = generateReport(data, true);
    assert.ok(!report.includes('sk-secret-12345'), 'Should not contain secret');
    assert.ok(!report.includes('API_KEY='), 'Should not contain API_KEY pattern');
});

// Summary

console.log('\n' + '='.repeat(40));
console.log(`Tests: ${passed} passed, ${failed} failed`);
process.exit(failed > 0 ? 1 : 0);
