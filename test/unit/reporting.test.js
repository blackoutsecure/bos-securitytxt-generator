// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
// Blackout Secure Security TXT Generator GitHub Action
// Copyright © 2025-2026 Blackout Secure
// Licensed under Apache License 2.0
// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
// Findings model, SARIF emission, and reporting surface tests.
// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

const assert = require('assert');
const fs = require('fs');
const os = require('os');
const path = require('path');

const { Finding, AuditResult, verdict, familyFor } = require('../../src/lib/findings');
const sarifMod = require('../../src/lib/sarif');
const reportMod = require('../../src/lib/report');

function finding(overrides = {}) {
  return new Finding({
    ruleId: 'ST001',
    severity: 'fail',
    message: 'No Contact directive found.',
    location: 'dist/.well-known/security.txt',
    ...overrides,
  });
}

function tmpDir() {
  return fs.mkdtempSync(path.join(os.tmpdir(), 'bos-securitytxt-report-'));
}

describe('lib/findings', () => {
  it('derives a title, remediation, and RFC help URI from the rule id', () => {
    const f = finding();
    assert.strictEqual(f.title, 'Contact field present');
    assert.match(f.remediation, /security_contact/);
    assert.match(f.helpUri, /rfc9116/);
  });

  it('produces a stable finding key independent of message wording', () => {
    assert.strictEqual(
      finding({ message: 'one' }).findingKey,
      finding({ message: 'two' }).findingKey,
    );
    assert.match(finding().findingKey, /^st001-[0-9a-f]{16}$/);
  });

  it('changes the finding key when the location changes', () => {
    assert.notStrictEqual(
      finding({ location: 'a' }).findingKey,
      finding({ location: 'b' }).findingKey,
    );
  });

  it('counts totals per severity', () => {
    const result = new AuditResult([
      finding({ severity: 'pass' }),
      finding({ ruleId: 'ST002', severity: 'warn' }),
      finding({ ruleId: 'ST003', severity: 'fail' }),
      finding({ ruleId: 'ST010', severity: 'error' }),
      finding({ ruleId: 'ST020', severity: 'skip' }),
    ]);
    assert.deepStrictEqual(result.totals(), { pass: 1, warn: 1, fail: 1, error: 1, skip: 1 });
  });

  it('escalates the verdict from pass through inconclusive', () => {
    assert.strictEqual(verdict({ pass: 1, warn: 0, fail: 0, error: 0, skip: 0 })[0], 'Pass');
    assert.strictEqual(
      verdict({ pass: 0, warn: 1, fail: 0, error: 0, skip: 0 })[0],
      'Review recommended',
    );
    assert.strictEqual(
      verdict({ pass: 0, warn: 0, fail: 1, error: 0, skip: 0 })[0],
      'Action required',
    );
    assert.strictEqual(
      verdict({ pass: 0, warn: 0, fail: 0, error: 1, skip: 0 })[0],
      'Inconclusive',
    );
    assert.strictEqual(
      verdict({ pass: 0, warn: 0, fail: 0, error: 0, skip: 0 })[0],
      'Not assessed',
    );
  });

  it('buckets rule ids into display families', () => {
    assert.strictEqual(familyFor('ST001'), 0);
    assert.strictEqual(familyFor('ST010'), 1);
    assert.strictEqual(familyFor('ST020'), 2);
    assert.strictEqual(familyFor('ST030'), 3);
    assert.strictEqual(familyFor('ST040'), 4);
    assert.strictEqual(familyFor('ZZ999'), -1);
  });

  it('excludes passing findings from recommendations', () => {
    const result = new AuditResult([
      finding({ severity: 'pass' }),
      finding({ ruleId: 'ST002', severity: 'warn' }),
    ]);
    const recommendations = result.recommendations();
    assert.strictEqual(recommendations.length, 1);
    assert.strictEqual(recommendations[0].rule_id, 'ST002');
    assert.strictEqual(recommendations[0].patch_status, 'unavailable');
  });

  it('renders a Markdown report with summary, recommendations, and details', () => {
    const md = new AuditResult([finding()], { site_url: 'https://example.com' }).summaryMarkdown();
    assert.match(md, /# Blackout Secure Security TXT Generator Audit Report/);
    assert.match(md, /\*\*Verdict:\*\* Action required/);
    assert.match(md, /## Run Context/);
    assert.match(md, /## Recommendations/);
    assert.match(md, /### Required fields/);
  });

  it('renders a report even with no findings', () => {
    const md = new AuditResult([]).summaryMarkdown();
    assert.match(md, /Not assessed/);
    assert.match(md, /_No findings were emitted/);
  });

  it('escapes pipes so table rows stay well-formed', () => {
    const md = new AuditResult([finding({ message: 'a | b', severity: 'warn' })]).summaryMarkdown();
    assert.match(md, /a \\\| b/);
  });
});

describe('lib/sarif', () => {
  it('drops skip findings and keeps the rest', () => {
    const run = sarifMod.auditRun([
      finding({ severity: 'fail' }),
      finding({ ruleId: 'ST002', severity: 'skip' }),
      finding({ ruleId: 'ST003', severity: 'warn' }),
    ]);
    assert.strictEqual(run.results.length, 2);
    assert.deepStrictEqual(
      run.results.map((r) => r.level),
      ['error', 'warning'],
    );
  });

  it('emits one rule descriptor per rule id', () => {
    const run = sarifMod.auditRun([finding({ location: 'a' }), finding({ location: 'b' })]);
    assert.strictEqual(run.tool.driver.rules.length, 1);
    assert.strictEqual(run.results.length, 2);
  });

  it('tags results for the security tab', () => {
    const run = sarifMod.auditRun([finding()]);
    assert.ok(run.tool.driver.rules[0].properties.tags.includes('rfc9116'));
  });

  it('carries the finding key as a partial fingerprint', () => {
    const f = finding();
    const run = sarifMod.auditRun([f]);
    assert.strictEqual(run.results[0].partialFingerprints.bosSecurityTxtFindingKey, f.findingKey);
  });

  it('relativises file locations against the base dir', () => {
    const run = sarifMod.auditRun([finding()], { baseDir: process.cwd() });
    assert.strictEqual(
      run.results[0].locations[0].physicalLocation.artifactLocation.uri,
      'dist/.well-known/security.txt',
    );
  });

  it('merges runs and round-trips through disk', () => {
    const dir = tmpDir();
    try {
      const merged = sarifMod.merge(
        { runs: [sarifMod.auditRun([finding()])] },
        { runs: [sarifMod.auditRun([finding({ ruleId: 'ST002' })])] },
      );
      assert.strictEqual(merged.runs.length, 2);
      assert.strictEqual(merged.version, '2.1.0');

      const file = path.join(dir, 'out.sarif');
      sarifMod.dump(merged, file);
      assert.strictEqual(sarifMod.load(file).runs.length, 2);
    } finally {
      fs.rmSync(dir, { recursive: true, force: true });
    }
  });

  it('rejects a malformed SARIF file', () => {
    const dir = tmpDir();
    try {
      const file = path.join(dir, 'bad.sarif');
      fs.writeFileSync(file, '{"nope": true}', 'utf8');
      assert.throws(() => sarifMod.load(file), /missing `runs` array/);
    } finally {
      fs.rmSync(dir, { recursive: true, force: true });
    }
  });
});

describe('lib/report', () => {
  function fakeCore() {
    const lines = [];
    return {
      lines,
      info: (m) => lines.push(['info', m]),
      warning: (m) => lines.push(['warning', m]),
      error: (m) => lines.push(['error', m]),
      setFailed: (m) => lines.push(['failed', m]),
    };
  }

  it('prints grouped families and a totals line', () => {
    const core = fakeCore();
    reportMod.printAuditTable(
      core,
      new AuditResult([
        finding({ ruleId: 'ST001', severity: 'pass' }),
        finding({ ruleId: 'ST010', severity: 'fail' }),
      ]),
    );
    const text = core.lines.map(([, m]) => m).join('\n');
    assert.match(text, /Required fields/);
    assert.match(text, /Field hygiene/);
    assert.match(text, /1 pass/);
    assert.match(text, /1 fail/);
  });

  it('handles an empty audit without throwing', () => {
    const core = fakeCore();
    reportMod.printAuditTable(core, new AuditResult([]));
    assert.match(core.lines.map(([, m]) => m).join('\n'), /no findings/);
  });

  it('fails the job only when the exit policy says so', () => {
    const failing = fakeCore();
    reportMod.annotate(failing, new AuditResult([finding()]), true);
    assert.ok(failing.lines.some(([kind]) => kind === 'failed'));

    const advisory = fakeCore();
    reportMod.annotate(advisory, new AuditResult([finding()]), false);
    assert.ok(advisory.lines.some(([kind]) => kind === 'error'));
    assert.ok(!advisory.lines.some(([kind]) => kind === 'failed'));
  });

  it('writes the step summary when the env var is present', () => {
    const dir = tmpDir();
    try {
      const file = path.join(dir, 'summary.md');
      const written = reportMod.writeStepSummary(new AuditResult([finding()]), {
        aiSummary: '- one bullet',
        aiProvider: 'local-heuristic',
        environ: { GITHUB_STEP_SUMMARY: file },
      });
      assert.strictEqual(written, true);
      const body = fs.readFileSync(file, 'utf8');
      assert.match(body, /Audit Report/);
      assert.match(body, /## Findings Summary/);
    } finally {
      fs.rmSync(dir, { recursive: true, force: true });
    }
  });

  it('is a no-op when the step summary env var is absent', () => {
    assert.strictEqual(
      reportMod.writeStepSummary(new AuditResult([finding()]), { environ: {} }),
      false,
    );
  });

  it('writes the JSON report, recommendations, and skips sidecars', () => {
    const dir = tmpDir();
    try {
      const result = new AuditResult([finding(), finding({ ruleId: 'ST002', severity: 'skip' })], {
        contact_count: 0,
      });

      const report = JSON.parse(
        fs.readFileSync(
          reportMod.writeJsonReport(result, path.join(dir, 'report.json'), {
            ai_provider: 'local-heuristic',
          }),
          'utf8',
        ),
      );
      assert.strictEqual(report.schema_version, 1);
      assert.strictEqual(report.verdict, 'Action required');
      assert.strictEqual(report.ai_provider, 'local-heuristic');

      const recommendations = JSON.parse(
        fs.readFileSync(reportMod.writeRecommendations(result, path.join(dir, 'rec.json')), 'utf8'),
      );
      assert.strictEqual(recommendations.length, 2);

      const skips = JSON.parse(
        fs.readFileSync(reportMod.writeSkips(result, path.join(dir, 'skips.json')), 'utf8'),
      );
      assert.strictEqual(skips.length, 1);
      assert.strictEqual(skips[0].rule_id, 'ST002');
    } finally {
      fs.rmSync(dir, { recursive: true, force: true });
    }
  });

  it('creates missing parent directories for sidecars', () => {
    const dir = tmpDir();
    try {
      const target = path.join(dir, 'nested', 'deep', 'report.json');
      reportMod.writeJsonReport(new AuditResult([]), target);
      assert.ok(fs.existsSync(target));
    } finally {
      fs.rmSync(dir, { recursive: true, force: true });
    }
  });
});
