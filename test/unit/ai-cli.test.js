// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
// Blackout Secure Security TXT Generator GitHub Action
// Copyright © 2025-2026 Blackout Secure
// Licensed under Apache License 2.0
// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
// AI provider detection, expiry parsing, metadata, and CLI tests.
// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

const assert = require('assert');
const fs = require('fs');
const os = require('os');
const path = require('path');

const aiMod = require('../../src/lib/ai');
const { Finding, AuditResult } = require('../../src/lib/findings');
const { packageMetadata } = require('../../src/lib/metadata');
const { parseExpiresDate } = require('../../src/lib/expires');
const { main, parseArgs, contentFromConfig } = require('../../src/cli');
const cfgMod = require('../../src/lib/config');
const sarifMod = require('../../src/lib/sarif');

const NOW = new Date('2026-01-01T00:00:00Z');

function result(severities = ['fail', 'warn']) {
  return new AuditResult(
    severities.map(
      (severity, index) =>
        new Finding({ ruleId: `ST00${index + 1}`, severity, message: `finding ${index}` }),
    ),
  );
}

function capture() {
  const chunks = { out: '', err: '' };
  const stdout = process.stdout.write.bind(process.stdout);
  const stderr = process.stderr.write.bind(process.stderr);
  process.stdout.write = (text) => {
    chunks.out += text;
    return true;
  };
  process.stderr.write = (text) => {
    chunks.err += text;
    return true;
  };
  return {
    chunks,
    restore: () => {
      process.stdout.write = stdout;
      process.stderr.write = stderr;
    },
  };
}

async function runCli(argv) {
  const { chunks, restore } = capture();
  try {
    const code = await main(argv);
    return { code, ...chunks };
  } finally {
    restore();
  }
}

describe('lib/expires', () => {
  it('defaults to 180 days', () => {
    const parsed = parseExpiresDate('', NOW);
    assert.strictEqual(parsed.daysFromNow, 180);
  });

  it('parses relative day, month, and year shorthands', () => {
    assert.strictEqual(parseExpiresDate('30d', NOW).daysFromNow, 30);
    assert.strictEqual(parseExpiresDate('1y', NOW).daysFromNow, 365);
    // Calendar-month arithmetic runs in local time, so the exact day count
    // shifts by one either side of UTC.
    const sixMonths = parseExpiresDate('6m', NOW).daysFromNow;
    assert.ok(sixMonths >= 180 && sixMonths <= 184, `6m resolved to ${sixMonths} days`);
  });

  it('preserves an explicit ISO 8601 value', () => {
    const parsed = parseExpiresDate('2026-06-01T00:00:00Z', NOW);
    assert.strictEqual(parsed.date, '2026-06-01T00:00:00Z');
    assert.strictEqual(parsed.daysFromNow, 151);
  });

  it('rejects an unparseable value', () => {
    assert.throws(() => parseExpiresDate('whenever', NOW), /Invalid expires date format/);
  });
});

describe('lib/ai', () => {
  it('selects GitHub Models when a token is exposed', () => {
    const provider = aiMod.detectProvider('auto', { GITHUB_TOKEN: 'ghs_example' });
    assert.strictEqual(provider.name, 'github-models');
    assert.strictEqual(provider.endpoint, aiMod.GITHUB_MODELS_ENDPOINT);
  });

  it('prefers the dedicated models token and model overrides', () => {
    const provider = aiMod.detectProvider('github', {
      GITHUB_TOKEN: 'ghs_ignored',
      GITHUB_MODELS_TOKEN: 'ghs_preferred',
      GITHUB_MODELS_MODEL_SECURITY_TXT: 'openai/gpt-4.1-mini',
    });
    assert.strictEqual(provider.token, 'ghs_preferred');
    assert.strictEqual(provider.model, 'openai/gpt-4.1-mini');
  });

  it('returns null when no credentials are present', () => {
    assert.strictEqual(aiMod.detectProvider('auto', {}), null);
  });

  it('returns null for explicitly disabled providers', () => {
    for (const name of ['none', 'disabled', 'false', 'off']) {
      assert.strictEqual(aiMod.detectProvider(name, { GITHUB_TOKEN: 'x' }), null, name);
    }
  });

  it('requires both a key and an endpoint for external providers', () => {
    assert.strictEqual(aiMod.detectProvider('acme', { ACME_API_KEY: 'k' }), null);
    const provider = aiMod.detectProvider('acme', {
      ACME_API_KEY: 'k',
      ACME_API_ENDPOINT: 'https://acme.test/v1/chat',
    });
    assert.strictEqual(provider.name, 'acme');
  });

  it('rejects non-HTTPS provider endpoints', () => {
    assert.strictEqual(
      aiMod.detectProvider('acme', {
        ACME_API_KEY: 'k',
        ACME_API_ENDPOINT: 'http://acme.test/v1/chat',
      }),
      null,
    );
  });

  it('produces a factual local summary', () => {
    const text = aiMod.localSummary(result());
    assert.match(text, /1 high, 1 warning/);
    assert.strictEqual(text.split('\n').length, 3);
  });

  it('reports a clean run in the local summary', () => {
    assert.match(aiMod.localSummary(result(['pass'])), /No RFC 9116 control requires attention/);
  });

  it('truncates long local summaries with a tail count', () => {
    assert.match(aiMod.localSummary(result(['fail', 'warn', 'warn', 'warn'])), /2 further finding/);
  });

  it('falls back to the local summary when no provider is available', async () => {
    const summary = await aiMod.buildSummary(
      result(),
      {
        enableAiFindingsSummary: true,
        aiFindingsSummaryProvider: 'auto',
        localHeuristicFallback: true,
      },
      { environ: {} },
    );
    assert.strictEqual(summary.provider, 'local-heuristic');
    assert.ok(summary.text);
  });

  it('returns an empty summary when both AI and fallback are disabled', async () => {
    const summary = await aiMod.buildSummary(result(), {
      enableAiFindingsSummary: false,
      aiFindingsSummaryProvider: 'auto',
      localHeuristicFallback: false,
    });
    assert.strictEqual(summary.text, '');
    assert.strictEqual(summary.provider, 'disabled');
  });

  it('treats a transport failure as ordinary unavailability', async () => {
    const summary = await aiMod.summarize([], {
      name: 'acme',
      endpoint: 'http://127.0.0.1:1/unreachable',
      model: 'x',
      token: 'k',
    });
    assert.strictEqual(summary, null);
  });

  it('never throws for a null provider', async () => {
    assert.strictEqual(await aiMod.summarize([], null), null);
  });
});

describe('lib/metadata', () => {
  it('reports package identity from package.json', () => {
    const pkg = packageMetadata();
    assert.strictEqual(pkg.name, 'bos-securitytxt-generator');
    assert.match(pkg.version, /^\d+\.\d+\.\d+/);
    assert.ok(pkg.description);
  });
});

describe('cli/parseArgs', () => {
  it('parses the command, flags, and repeated inputs', () => {
    const parsed = parseArgs([
      'sarif',
      '--input',
      'a.sarif',
      '--input',
      'b.sarif',
      '--output',
      'm.sarif',
    ]);
    assert.strictEqual(parsed.command, 'sarif');
    assert.deepStrictEqual(parsed.repeated.input, ['a.sarif', 'b.sarif']);
    assert.strictEqual(parsed.flags.output, 'm.sarif');
  });

  it('collects repeated contacts', () => {
    const parsed = parseArgs([
      'generate',
      '--contact',
      'mailto:a@example.com',
      '--contact',
      'tel:+15550100',
    ]);
    assert.deepStrictEqual(parsed.repeated.contact, ['mailto:a@example.com', 'tel:+15550100']);
  });

  it('camel-cases multi-word flags', () => {
    assert.strictEqual(
      parseArgs(['audit', '--site-url', 'https://example.com']).flags.siteUrl,
      'https://example.com',
    );
  });

  it('handles the tri-state global config switches', () => {
    assert.strictEqual(parseArgs(['validate', '--use-global-config']).flags.useGlobalConfig, true);
    assert.strictEqual(parseArgs(['validate', '--no-global-config']).flags.useGlobalConfig, false);
    assert.strictEqual(parseArgs(['validate']).flags.useGlobalConfig, undefined);
  });

  it('rejects a flag with a missing value', () => {
    assert.throws(() => parseArgs(['audit', '--site-url']), /requires a value/);
  });
});

describe('cli/contentFromConfig', () => {
  it('derives Canonical from the site URL when unset', () => {
    const cfg = cfgMod.resolve(os.tmpdir(), { useGlobalConfig: false });
    const content = contentFromConfig(cfg, 'https://example.com/', ['mailto:a@example.com']);
    assert.match(content, /Canonical: https:\/\/example\.com\/\.well-known\/security\.txt/);
    assert.match(content, /Contact: mailto:a@example\.com/);
    assert.match(content, /Expires: /);
  });

  it('raises when no contact is configured', () => {
    const cfg = cfgMod.resolve(os.tmpdir(), { useGlobalConfig: false });
    assert.throws(() => contentFromConfig(cfg, '', []), /no contact configured/);
  });
});

describe('cli/main', () => {
  it('prints the package version', async () => {
    const { code, out } = await runCli(['version']);
    assert.strictEqual(code, 0);
    assert.match(out.trim(), /^\d+\.\d+\.\d+/);
  });

  it('prints usage with no command', async () => {
    const { code, out } = await runCli([]);
    assert.strictEqual(code, 0);
    assert.match(out, /bos-securitytxt <command>/);
  });

  it('rejects an unknown command', async () => {
    const { code, err } = await runCli(['teleport']);
    assert.strictEqual(code, 2);
    assert.match(err, /unknown command/);
  });

  it('validates and prints the resolved configuration cascade', async () => {
    const { code, out } = await runCli(['validate']);
    assert.strictEqual(code, 0);
    assert.match(out, /Package metadata:/);
    assert.match(out, /bundled:marketplace-config\.json/);
    assert.match(out, /audit rules:/);
    assert.match(out, /require_contact/);
  });

  it('surfaces a config error as exit code 2', async () => {
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'bos-securitytxt-cli-'));
    try {
      fs.writeFileSync(path.join(dir, 'bad.yml'), 'audit:\n  fail_on: sometimes\n', 'utf8');
      const { code, err } = await runCli(['validate', '--root', dir, '--config', 'bad.yml']);
      assert.strictEqual(code, 2);
      assert.match(err, /audit\.fail_on/);
    } finally {
      fs.rmSync(dir, { recursive: true, force: true });
    }
  });

  it('generates and then audits a security.txt end to end', async () => {
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'bos-securitytxt-cli-'));
    try {
      const generated = await runCli([
        'generate',
        '--root',
        dir,
        '--public-dir',
        'site',
        '--site-url',
        'https://example.com',
        '--contact',
        'mailto:security@example.com',
      ]);
      assert.strictEqual(generated.code, 0);
      assert.ok(fs.existsSync(path.join(dir, 'site', '.well-known', 'security.txt')));

      const audited = await runCli([
        'audit',
        '--root',
        dir,
        '--public-dir',
        'site',
        '--site-url',
        'https://example.com',
        '--json',
        path.join(dir, 'report.json'),
        '--fail-on',
        'never',
        '--no-ai',
      ]);
      assert.strictEqual(audited.code, 0);
      const report = JSON.parse(fs.readFileSync(path.join(dir, 'report.json'), 'utf8'));
      assert.strictEqual(report.findings.length, Object.keys(cfgMod.RULE_DEFAULTS).length);
      assert.strictEqual(report.ai_provider, 'local-heuristic');
    } finally {
      fs.rmSync(dir, { recursive: true, force: true });
    }
  });

  it('reports a missing security.txt for audit', async () => {
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'bos-securitytxt-cli-'));
    try {
      const { code, err } = await runCli(['audit', '--root', dir]);
      assert.strictEqual(code, 2);
      assert.match(err, /security\.txt not found/);
    } finally {
      fs.rmSync(dir, { recursive: true, force: true });
    }
  });

  it('merges SARIF inputs and skips missing files', async () => {
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'bos-securitytxt-cli-'));
    try {
      const input = path.join(dir, 'a.sarif');
      sarifMod.dump(
        sarifMod.merge({
          runs: [
            sarifMod.auditRun([
              new Finding({ ruleId: 'ST001', severity: 'warn', message: 'example' }),
            ]),
          ],
        }),
        input,
      );

      const output = path.join(dir, 'merged.sarif');
      const { code, err } = await runCli([
        'sarif',
        '--input',
        input,
        '--input',
        path.join(dir, 'missing.sarif'),
        '--output',
        output,
      ]);
      assert.strictEqual(code, 0);
      assert.match(err, /skipping missing SARIF input/);
      assert.strictEqual(sarifMod.load(output).runs.length, 1);
    } finally {
      fs.rmSync(dir, { recursive: true, force: true });
    }
  });

  it('requires --output for the sarif command', async () => {
    const { code, err } = await runCli(['sarif']);
    assert.strictEqual(code, 2);
    assert.match(err, /--output is required/);
  });
});
