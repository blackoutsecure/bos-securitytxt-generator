// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
// Blackout Secure Security TXT Generator GitHub Action
// Copyright © 2025-2026 Blackout Secure
// Licensed under Apache License 2.0
// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
// RFC 9116 audit rule tests.
// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

const assert = require('assert');
const fs = require('fs');
const os = require('os');
const path = require('path');

const cfgMod = require('../../src/lib/config');
const { audit, shouldFail } = require('../../src/lib/audit');
const { parseSecurityTxt } = require('../../src/lib/security-parser');

const SITE = 'https://example.com';
const NOW = new Date('2026-01-01T00:00:00Z');
const FUTURE = '2026-06-01T00:00:00Z';
const PAST = '2025-06-01T00:00:00Z';

function configWith(overrides = {}) {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'bos-securitytxt-cfg-'));
  fs.writeFileSync(
    path.join(dir, '.bos-securitytxt.yml'),
    JSON.stringify({ security_txt: overrides }),
    'utf8',
  );
  const cfg = cfgMod.resolve(dir);
  fs.rmSync(dir, { recursive: true, force: true });
  return cfg;
}

function compliant(extra = '') {
  return [
    `Canonical: ${SITE}/.well-known/security.txt`,
    'Contact: mailto:security@example.com',
    'Contact: https://example.com/report',
    `Expires: ${FUTURE}`,
    'Encryption: https://example.com/pgp-key.txt',
    'Acknowledgments: https://example.com/thanks',
    'Preferred-Languages: en, es',
    'Policy: https://example.com/policy',
    'Hiring: https://example.com/jobs',
    extra,
  ]
    .filter(Boolean)
    .join('\n');
}

function run(content, { cfg = configWith(), filePath, siteUrl = SITE, publicDir = 'dist' } = {}) {
  return audit({
    cfg,
    content,
    filePath: filePath ?? path.join(publicDir, '.well-known', 'security.txt'),
    siteUrl,
    publicDir,
    now: NOW,
  });
}

function findingFor(result, ruleId) {
  return result.findings.find((f) => f.ruleId === ruleId);
}

describe('lib/security-parser parseSecurityTxt', () => {
  it('parses directives case-insensitively and groups repeats', () => {
    const parsed = parseSecurityTxt('CONTACT: mailto:a@example.com\ncontact: tel:+1234\n');
    assert.deepStrictEqual(parsed.fields.contact, ['mailto:a@example.com', 'tel:+1234']);
  });

  it('ignores comments, blank lines, and PGP framing', () => {
    const parsed = parseSecurityTxt(
      '-----BEGIN PGP SIGNED MESSAGE-----\nHash: SHA256\n\n# note\nContact: mailto:a@example.com\n',
    );
    assert.deepStrictEqual(Object.keys(parsed.fields), ['contact']);
    assert.strictEqual(parsed.signed, true);
  });

  it('collects unknown directives and malformed lines', () => {
    const parsed = parseSecurityTxt('Contact: mailto:a@example.com\nBogus: x\nnot-a-directive\n');
    assert.deepStrictEqual(parsed.unknownFields, ['bogus']);
    assert.strictEqual(parsed.malformedLines.length, 1);
  });

  it('detects and strips a byte-order mark', () => {
    const parsed = parseSecurityTxt('\uFEFFContact: mailto:a@example.com\n');
    assert.strictEqual(parsed.hasBom, true);
    assert.deepStrictEqual(parsed.fields.contact, ['mailto:a@example.com']);
  });
});

describe('lib/audit', () => {
  it('emits a finding for every known rule', () => {
    const result = run(compliant());
    assert.strictEqual(result.findings.length, Object.keys(cfgMod.RULE_DEFAULTS).length);
  });

  it('passes every non-skipped control for a compliant file', () => {
    const cfg = configWith({
      audit: {
        rules: {
          require_multiple_contacts: 'warn',
          recommend_encryption: 'warn',
          recommend_acknowledgments: 'warn',
          recommend_hiring: 'warn',
        },
      },
    });
    const result = run(compliant(), { cfg });
    const attention = result.findings.filter((f) => f.severity !== 'pass' && f.ruleId !== 'ST032');
    assert.deepStrictEqual(
      attention.map((f) => f.ruleId),
      [],
    );
  });

  it('records disabled controls as skip rather than dropping them', () => {
    const cfg = configWith({ audit: { rules: { require_contact: 'skip' } } });
    const finding = findingFor(run('Expires: ' + FUTURE, { cfg }), 'ST001');
    assert.strictEqual(finding.severity, 'skip');
    assert.match(finding.message, /Control disabled/);
  });

  it('flags a missing Contact and Expires', () => {
    const result = run('Policy: https://example.com/policy');
    assert.strictEqual(findingFor(result, 'ST001').severity, 'warn');
    assert.strictEqual(findingFor(result, 'ST002').severity, 'warn');
  });

  it('flags an expired file', () => {
    const result = run(`Contact: mailto:a@example.com\nExpires: ${PAST}`);
    const finding = findingFor(result, 'ST003');
    assert.strictEqual(finding.severity, 'warn');
    assert.match(finding.message, /in the past/);
  });

  it('flags an expiry beyond the configured maximum', () => {
    const cfg = configWith({ audit: { expires_max_days: 30 } });
    const result = run(`Contact: mailto:a@example.com\nExpires: ${FUTURE}`, { cfg });
    const finding = findingFor(result, 'ST004');
    assert.strictEqual(finding.severity, 'warn');
    assert.strictEqual(finding.evidence.max_days, 30);
  });

  it('checks Canonical against the declared site URL', () => {
    const matching = run(compliant());
    assert.strictEqual(findingFor(matching, 'ST006').severity, 'pass');

    const mismatched = run(`Canonical: ${SITE}/security.txt\nContact: mailto:a@example.com`);
    assert.strictEqual(findingFor(mismatched, 'ST006').severity, 'warn');
  });

  it('tolerates a site URL with a trailing slash', () => {
    const result = run(compliant(), { siteUrl: `${SITE}/` });
    assert.strictEqual(findingFor(result, 'ST006').severity, 'pass');
  });

  it('flags insecure http:// URIs', () => {
    const result = run('Contact: mailto:a@example.com\nPolicy: http://example.com/policy');
    const finding = findingFor(result, 'ST010');
    assert.strictEqual(finding.severity, 'warn');
    assert.deepStrictEqual(finding.evidence.samples, ['policy: http://example.com/policy']);
  });

  it('flags contact values that are not supported URIs', () => {
    const result = run('Contact: security@example.com');
    const finding = findingFor(result, 'ST011');
    assert.strictEqual(finding.severity, 'warn');
    assert.deepStrictEqual(finding.evidence.samples, ['security@example.com']);
  });

  it('accepts mailto, https, and tel contact schemes', () => {
    const result = run(
      'Contact: mailto:a@example.com\nContact: https://example.com/r\nContact: tel:+15550100',
    );
    assert.strictEqual(findingFor(result, 'ST011').severity, 'pass');
  });

  it('flags invalid Preferred-Languages tags', () => {
    const result = run('Contact: mailto:a@example.com\nPreferred-Languages: en, klingon-!!');
    assert.strictEqual(findingFor(result, 'ST013').severity, 'warn');
  });

  it('flags repeated single-valued directives', () => {
    const result = run(`Contact: mailto:a@example.com\nExpires: ${FUTURE}\nExpires: ${FUTURE}`);
    const finding = findingFor(result, 'ST014');
    assert.strictEqual(finding.severity, 'warn');
    assert.deepStrictEqual(finding.evidence.samples, ['expires']);
  });

  it('flags unknown directives and malformed lines', () => {
    const result = run('Contact: mailto:a@example.com\nBogus: value\nnonsense');
    const finding = findingFor(result, 'ST015');
    assert.strictEqual(finding.severity, 'warn');
    assert.deepStrictEqual(finding.evidence.samples, ['bogus']);
    assert.strictEqual(finding.evidence.malformed_lines.length, 1);
  });

  it('reports the recommended optional directives', () => {
    const cfg = configWith({
      audit: { rules: { recommend_encryption: 'warn', recommend_acknowledgments: 'warn' } },
    });
    const result = run('Contact: mailto:a@example.com', { cfg });
    assert.strictEqual(findingFor(result, 'ST020').severity, 'warn');
    assert.strictEqual(findingFor(result, 'ST021').severity, 'warn');
    assert.strictEqual(findingFor(result, 'ST022').severity, 'warn');
  });

  it('requires the well-known location', () => {
    const good = run(compliant());
    assert.strictEqual(findingFor(good, 'ST030').severity, 'pass');

    const bad = run(compliant(), { filePath: 'dist/security.txt' });
    assert.strictEqual(findingFor(bad, 'ST030').severity, 'warn');
  });

  it('enforces the configured size limit', () => {
    const cfg = configWith({ audit: { max_size_kb: 1 } });
    const result = run(`Contact: mailto:a@example.com\n# ${'x'.repeat(2048)}`, { cfg });
    assert.strictEqual(findingFor(result, 'ST031').severity, 'warn');
  });

  it('detects an inline OpenPGP signature', () => {
    const cfg = configWith({ audit: { rules: { require_signature: 'warn' } } });
    const unsigned = run(compliant(), { cfg });
    assert.strictEqual(findingFor(unsigned, 'ST032').severity, 'warn');

    const signed = run(`-----BEGIN PGP SIGNED MESSAGE-----\nHash: SHA256\n\n${compliant()}`, {
      cfg,
    });
    assert.strictEqual(findingFor(signed, 'ST032').severity, 'pass');
  });

  it('detects a detached signature on disk', () => {
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'bos-securitytxt-sig-'));
    try {
      const filePath = path.join(dir, '.well-known', 'security.txt');
      fs.mkdirSync(path.dirname(filePath), { recursive: true });
      fs.writeFileSync(filePath, compliant(), 'utf8');
      fs.writeFileSync(`${filePath}.sig`, 'signature', 'utf8');

      const cfg = configWith({ audit: { rules: { require_signature: 'warn' } } });
      const result = run(compliant(), { cfg, filePath, publicDir: dir });
      assert.strictEqual(findingFor(result, 'ST032').severity, 'pass');
    } finally {
      fs.rmSync(dir, { recursive: true, force: true });
    }
  });

  it('flags a byte-order mark', () => {
    const result = run(`\uFEFF${compliant()}`);
    assert.strictEqual(findingFor(result, 'ST040').severity, 'warn');
  });

  it('drives the exit disposition from fail_on', () => {
    const cfg = configWith({ audit: { rules: { require_contact: 'fail' } } });
    const result = run('Expires: ' + FUTURE, { cfg });
    assert.strictEqual(shouldFail(result, 'fail'), true);
    assert.strictEqual(shouldFail(result, 'never'), false);
  });

  it('exposes run context for reporting', () => {
    const result = run(compliant());
    assert.strictEqual(result.context.site_url, SITE);
    assert.strictEqual(result.context.contact_count, 2);
    assert.strictEqual(result.context.expires, FUTURE);
    assert.ok(result.context.size_bytes > 0);
  });
});
