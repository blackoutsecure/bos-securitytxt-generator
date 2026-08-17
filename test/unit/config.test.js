// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
// Blackout Secure Security TXT Generator GitHub Action
// Copyright © 2025-2026 Blackout Secure
// Licensed under Apache License 2.0
// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
// Layered configuration loader tests.
// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

const assert = require('assert');
const fs = require('fs');
const os = require('os');
const path = require('path');

const cfgMod = require('../../src/lib/config');

function write(root, relative, contents) {
  const target = path.join(root, relative);
  fs.mkdirSync(path.dirname(target), { recursive: true });
  fs.writeFileSync(target, contents, 'utf8');
  return target;
}

describe('lib/config', () => {
  const roots = [];

  afterEach(() => {
    while (roots.length) {
      fs.rmSync(roots.pop(), { recursive: true, force: true });
    }
  });

  function root() {
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'bos-securitytxt-config-'));
    roots.push(dir);
    return dir;
  }

  it('falls back to the bundled marketplace baseline', () => {
    const cfg = cfgMod.resolve(root());
    assert.strictEqual(cfg.generate.includeComments, true);
    assert.strictEqual(cfg.generate.filename, 'security.txt');
    assert.strictEqual(cfg.fields.expires, '180d');
    assert.strictEqual(cfg.audit.failOn, 'fail');
    assert.strictEqual(cfg.audit.expiresMaxDays, 365);
    assert.strictEqual(cfg.audit.rules.require_contact, 'warn');
    assert.deepStrictEqual(cfg.sourcePaths, ['bundled:marketplace-config.json']);
  });

  it('starts from built-in defaults when the baseline is disabled', () => {
    const cfg = cfgMod.resolve(root(), { useMarketplaceConfig: false });
    assert.deepStrictEqual(cfg.sourcePaths, []);
    assert.strictEqual(cfg.audit.maxSizeKb, 32);
    assert.strictEqual(cfg.audit.rules.require_signature, 'skip');
  });

  it('discovers .github/bos-universal-config.json and merges it', () => {
    const dir = root();
    write(
      dir,
      '.github/bos-universal-config.json',
      JSON.stringify({
        security_txt: {
          owner: 'blackoutsecure',
          audit: { rules: { require_canonical: 'fail' } },
        },
      }),
    );

    const cfg = cfgMod.resolve(dir);
    assert.strictEqual(cfg.owner, 'blackoutsecure');
    assert.strictEqual(cfg.audit.rules.require_canonical, 'fail');
    assert.strictEqual(cfg.audit.rules.require_contact, 'warn');
  });

  it('applies global config beneath the repository config', () => {
    const dir = root();
    write(
      dir,
      '.github/blackout-secure-securitytxt-generator-global-config.yml',
      'security_txt:\n  audit:\n    rules:\n      require_contact: fail\n      recommend_policy: fail\n',
    );
    write(
      dir,
      '.bos-securitytxt.yml',
      'security_txt:\n  audit:\n    rules:\n      recommend_policy: skip\n',
    );

    const cfg = cfgMod.resolve(dir);
    assert.strictEqual(cfg.audit.rules.require_contact, 'fail');
    assert.strictEqual(cfg.audit.rules.recommend_policy, 'skip');
    assert.strictEqual(cfg.sourcePaths.length, 3);
  });

  it('honours the tri-state global config toggle', () => {
    const dir = root();
    assert.throws(() => cfgMod.resolve(dir, { useGlobalConfig: true }), cfgMod.ConfigError);
    assert.doesNotThrow(() => cfgMod.resolve(dir, { useGlobalConfig: false }));
  });

  it('accepts a bare document without the security_txt section', () => {
    const dir = root();
    write(dir, '.bos-securitytxt.yml', 'audit:\n  fail_on: never\n');
    assert.strictEqual(cfgMod.resolve(dir).audit.failOn, 'never');
  });

  it('accepts list fields as a comma-separated string or a list', () => {
    const dir = root();
    write(
      dir,
      '.bos-securitytxt.yml',
      'fields:\n  contact: "mailto:a@example.com, https://example.com/report"\n  policy:\n    - https://example.com/policy\n',
    );
    const cfg = cfgMod.resolve(dir);
    assert.deepStrictEqual(cfg.fields.contact, [
      'mailto:a@example.com',
      'https://example.com/report',
    ]);
    assert.deepStrictEqual(cfg.fields.policy, ['https://example.com/policy']);
  });

  it('defaults project_name to the repository name', () => {
    const cfg = cfgMod.resolve(root(), { repoName: 'bos-securitytxt-generator' });
    assert.strictEqual(cfg.projectName, 'bos-securitytxt-generator');
  });

  it('rejects an unknown audit rule', () => {
    const dir = root();
    write(dir, '.bos-securitytxt.yml', 'audit:\n  rules:\n    require_unicorns: warn\n');
    assert.throws(() => cfgMod.resolve(dir), /unknown rule/);
  });

  it('rejects an invalid severity', () => {
    const dir = root();
    write(dir, '.bos-securitytxt.yml', 'audit:\n  rules:\n    require_contact: explode\n');
    assert.throws(() => cfgMod.resolve(dir), /is not one of/);
  });

  it('rejects an invalid fail_on value', () => {
    const dir = root();
    write(dir, '.bos-securitytxt.yml', 'audit:\n  fail_on: sometimes\n');
    assert.throws(() => cfgMod.resolve(dir), /audit\.fail_on/);
  });

  it('rejects a filename containing a path separator', () => {
    const dir = root();
    write(dir, '.bos-securitytxt.yml', 'generate:\n  filename: nested/security.txt\n');
    assert.throws(() => cfgMod.resolve(dir), /bare filename/);
  });

  it('rejects a non-positive integer limit', () => {
    const dir = root();
    write(dir, '.bos-securitytxt.yml', 'audit:\n  max_size_kb: 0\n');
    assert.throws(() => cfgMod.resolve(dir), /positive integer/);
  });

  it('rejects a non-mapping top level document', () => {
    const dir = root();
    write(dir, '.bos-securitytxt.yml', '- one\n- two\n');
    assert.throws(() => cfgMod.resolve(dir), /top-level must be a mapping/);
  });

  it('raises for a missing explicit config path', () => {
    assert.throws(() => cfgMod.resolve(root(), { configPath: 'nope.yml' }), /config not found/);
  });

  it('deep merges nested mappings and replaces lists', () => {
    const merged = cfgMod.deepMerge(
      { a: { b: 1, c: 2 }, list: [1, 2] },
      { a: { c: 3 }, list: [9] },
    );
    assert.deepStrictEqual(merged, { a: { b: 1, c: 3 }, list: [9] });
  });

  it('exposes a severity for every known rule', () => {
    const cfg = cfgMod.resolve(root());
    for (const name of Object.keys(cfgMod.RULE_DEFAULTS)) {
      assert.ok(
        cfgMod.SEVERITIES.includes(cfg.audit.rules[name]),
        `${name} resolved to a valid severity`,
      );
    }
  });
});
