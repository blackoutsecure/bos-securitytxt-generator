// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
// Blackout Secure Security TXT Generator GitHub Action
// Copyright © 2025-2026 Blackout Secure
// Licensed under Apache License 2.0
// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
// Finding model, severity semantics, and Markdown report rendering.
//
// Severities:
//   pass  — control satisfied the configured policy
//   warn  — review recommended, not a hard block on its own
//   fail  — required control failed and should be remediated
//   error — the audit itself could not complete for this control
//   skip  — the control was disabled or lacked the evidence to assess
// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

const crypto = require('crypto');

const RFC = 'https://www.rfc-editor.org/rfc/rfc9116';

/**
 * Rule family display order — drives the section banners in reports.
 * Entries are `[idPrefix, header, blurb]`.
 */
const RULE_FAMILIES = Object.freeze([
  ['ST00', 'Required fields', 'Contact, Expires, and Canonical per RFC 9116 § 2.5'],
  ['ST01', 'Field hygiene', 'URI schemes, field cardinality, and unknown directives'],
  ['ST02', 'Recommended fields', 'Encryption, Policy, Acknowledgments, and Hiring'],
  ['ST03', 'File placement', 'Well-known location, size, and signature'],
  ['ST04', 'Encoding', 'UTF-8 and byte-order-mark compliance'],
]);

const RULE_TITLES = Object.freeze({
  ST001: 'Contact field present',
  ST002: 'Expires field present',
  ST003: 'Expires is in the future',
  ST004: 'Expires within the configured maximum',
  ST005: 'Canonical field present',
  ST006: 'Canonical matches the declared site URL',
  ST010: 'Web URIs use HTTPS',
  ST011: 'Contact values are valid URIs',
  ST012: 'More than one contact channel',
  ST013: 'Preferred-Languages uses valid language tags',
  ST014: 'Single-valued fields appear at most once',
  ST015: 'No unknown directives',
  ST020: 'Encryption key published',
  ST021: 'Disclosure policy published',
  ST022: 'Acknowledgments page published',
  ST023: 'Security hiring page published',
  ST030: 'Served from /.well-known/security.txt',
  ST031: 'File size within limits',
  ST032: 'OpenPGP signature published',
  ST040: 'UTF-8 encoded without a byte-order mark',
});

const RULE_HELP = Object.freeze({
  ST001: `${RFC}#section-2.5.3`,
  ST002: `${RFC}#section-2.5.5`,
  ST003: `${RFC}#section-2.5.5`,
  ST004: `${RFC}#section-2.5.5`,
  ST005: `${RFC}#section-2.5.2`,
  ST006: `${RFC}#section-2.5.2`,
  ST010: `${RFC}#section-2.5`,
  ST011: `${RFC}#section-2.5.3`,
  ST012: `${RFC}#section-2.5.3`,
  ST013: `${RFC}#section-2.5.8`,
  ST014: `${RFC}#section-2.4`,
  ST015: `${RFC}#section-4`,
  ST020: `${RFC}#section-2.5.4`,
  ST021: `${RFC}#section-2.5.7`,
  ST022: `${RFC}#section-2.5.1`,
  ST023: `${RFC}#section-2.5.6`,
  ST030: `${RFC}#section-3`,
  ST031: `${RFC}#section-3`,
  ST032: `${RFC}#section-2.3`,
  ST040: `${RFC}#section-2.1`,
});

const DEFAULT_REMEDIATIONS = Object.freeze({
  ST001:
    'Set `security_contact` to at least one reachable channel — RFC 9116 § 2.5.3 makes Contact mandatory.',
  ST002:
    'Set `security_expires` so the file carries an Expires directive; RFC 9116 § 2.5.5 makes it mandatory.',
  ST003:
    'Regenerate security.txt with a future Expires date — an expired file signals the disclosure channel is unmaintained.',
  ST004:
    'Shorten `security_expires` to at most the configured maximum; RFC 9116 recommends less than one year.',
  ST005:
    'Set `site_url` or `security_canonical` so the file declares where it is authoritatively served from.',
  ST006:
    'Point Canonical at `<site_url>/.well-known/security.txt` so researchers can verify the file was not copied from another host.',
  ST010:
    'Replace any http:// URI with its https:// equivalent — RFC 9116 requires secure transport for web URIs.',
  ST011:
    'Express every Contact value as a URI (`mailto:`, `https://`, or `tel:`) per RFC 9116 § 2.5.3.',
  ST012:
    'Publish a second contact channel so a single mailbox outage cannot block vulnerability reports.',
  ST013:
    'Use RFC 5646 language tags (for example `en, es, fr`) in `security_preferred_languages`, listed once.',
  ST014:
    'Remove the duplicates — Expires and Preferred-Languages must appear at most once per RFC 9116 § 2.4.',
  ST015:
    'Remove the unregistered directive, or register it with IANA; unknown fields are ignored by parsers.',
  ST020:
    'Publish an OpenPGP key and set `security_encryption` so researchers can send encrypted reports.',
  ST021:
    'Publish a vulnerability disclosure policy and set `security_policy` so researchers know your terms.',
  ST022: 'Publish an acknowledgments page and set `security_acknowledgments` to credit reporters.',
  ST023:
    'Set `security_hiring` if you advertise security roles; otherwise leave this control skipped.',
  ST030:
    'Write the file to `<public_dir>/.well-known/security.txt` — RFC 9116 § 3 defines that as the canonical location.',
  ST031:
    'Trim the file; an oversized security.txt is usually a sign of duplicated or templated content.',
  ST032: 'Sign security.txt with OpenPGP and publish the detached `security.txt.sig` alongside it.',
  ST040:
    'Write the file as UTF-8 without a byte-order mark — a BOM breaks strict RFC 9116 parsers.',
});

function defaultTitle(ruleId) {
  return RULE_TITLES[ruleId] || ruleId;
}

function defaultRemediation(ruleId, message) {
  return (
    DEFAULT_REMEDIATIONS[ruleId] ||
    message ||
    'Review the security.txt configuration and apply the recommended RFC 9116 control.'
  );
}

/** A single evidence-backed audit result. */
class Finding {
  /**
   * @param {object} options - Finding fields.
   * @param {string} options.ruleId - Stable rule identifier (e.g. `ST001`).
   * @param {string} options.severity - One of pass/warn/fail/error/skip.
   * @param {string} options.message - Evidence describing what was observed.
   * @param {string} [options.location] - File path or directive name.
   * @param {string} [options.title] - Human-readable control name.
   * @param {object} [options.evidence] - Machine-readable evidence payload.
   * @param {string} [options.remediation] - Recommended remediation text.
   * @param {string} [options.source] - Emitting subsystem.
   */
  constructor({
    ruleId,
    severity,
    message,
    location = '',
    title = '',
    evidence = {},
    remediation = '',
    source = 'securitytxt-audit',
  }) {
    this.ruleId = ruleId;
    this.severity = severity;
    this.message = message;
    this.location = location;
    this.title = title || defaultTitle(ruleId);
    this.evidence = evidence || {};
    this.remediation = remediation || defaultRemediation(ruleId, message);
    this.remediationConfidence = 'deterministic';
    this.remediationSource = 'Blackout Secure Recommended Remediation';
    this.source = source;
    this.helpUri = RULE_HELP[ruleId] || RFC;
  }

  /** Identity that stays stable as recommendation wording changes. */
  get findingKey() {
    const identity = `${this.ruleId}|${this.location || '(security.txt)'}`;
    const digest = crypto.createHash('sha256').update(identity, 'utf8').digest('hex').slice(0, 16);
    return `${this.ruleId.toLowerCase()}-${digest}`;
  }

  /** @returns {object} JSON-serialisable representation. */
  toJSON() {
    return {
      finding_key: this.findingKey,
      rule_id: this.ruleId,
      severity: this.severity,
      title: this.title,
      message: this.message,
      source: this.source,
      location: this.location,
      evidence: this.evidence,
      remediation: this.remediation,
      remediation_confidence: this.remediationConfidence,
      remediation_source: this.remediationSource,
      help_uri: this.helpUri,
    };
  }

  /** @returns {object} Machine-readable recommendation contract. */
  recommendation() {
    return {
      finding_key: this.findingKey,
      rule_id: this.ruleId,
      title: this.title,
      location: this.location,
      recommendation: this.remediation,
      confidence: this.remediationConfidence,
      source: this.remediationSource,
      patch_status: 'unavailable',
    };
  }
}

/** Aggregate of every finding emitted by one audit run. */
class AuditResult {
  /**
   * @param {Finding[]} [findings] - Findings in emission order.
   * @param {object} [context] - Run context echoed into reports.
   */
  constructor(findings = [], context = {}) {
    this.findings = findings;
    this.context = context;
  }

  get passed() {
    return this.findings.filter((f) => f.severity === 'pass');
  }

  get warned() {
    return this.findings.filter((f) => f.severity === 'warn');
  }

  get failed() {
    return this.findings.filter((f) => f.severity === 'fail');
  }

  get errored() {
    return this.findings.filter((f) => f.severity === 'error');
  }

  get skipped() {
    return this.findings.filter((f) => f.severity === 'skip');
  }

  /** @returns {object} Per-severity counts. */
  totals() {
    return {
      pass: this.passed.length,
      warn: this.warned.length,
      fail: this.failed.length,
      error: this.errored.length,
      skip: this.skipped.length,
    };
  }

  /** @returns {object[]} Recommendation contracts for non-pass findings. */
  recommendations() {
    return this.findings
      .filter((f) => f.severity !== 'pass' && f.remediation.trim())
      .map((f) => f.recommendation());
  }

  /** @returns {object} Full JSON report payload. */
  toJSON() {
    return {
      schema_version: 1,
      context: this.context,
      totals: this.totals(),
      verdict: verdict(this.totals())[0],
      findings: this.findings.map((f) => f.toJSON()),
      recommendations: this.recommendations(),
    };
  }

  /** @returns {string} GitHub-flavoured Markdown audit report. */
  summaryMarkdown() {
    return renderMarkdown(this);
  }
}

function verdict(totals) {
  if (totals.error) {
    return [
      'Inconclusive',
      'One or more controls could not be evaluated. Re-run after resolving the audit errors below.',
    ];
  }
  if (totals.fail) {
    return [
      'Action required',
      'At least one required RFC 9116 control failed and should be remediated before release.',
    ];
  }
  if (totals.warn) {
    return [
      'Review recommended',
      'No blocking failures. The warnings below are worth reviewing before release.',
    ];
  }
  if (totals.pass) {
    return ['Pass', 'Every configured RFC 9116 control satisfied its policy.'];
  }
  return ['Not assessed', 'No controls produced an assessable result for this run.'];
}

function severityLabel(severity) {
  switch (severity) {
    case 'pass':
      return '✅ Pass';
    case 'warn':
      return '⚠️ Warning';
    case 'fail':
      return '🔴 High';
    case 'error':
      return '🔥 Critical';
    default:
      return '⚪ Not Assessed';
  }
}

function mdEscape(text) {
  return String(text ?? '')
    .replace(/\|/g, '\\|')
    .replace(/\r?\n/g, ' ');
}

function familyFor(ruleId) {
  return RULE_FAMILIES.findIndex(([prefix]) => ruleId.startsWith(prefix));
}

function recommendedActions(totals) {
  const actions = [];
  if (totals.fail) {
    actions.push('Remediate every 🔴 High finding — these are required controls that failed.');
  }
  if (totals.error) {
    actions.push(
      'Investigate every 🔥 Critical finding — the audit could not collect evidence for those controls.',
    );
  }
  if (totals.warn) {
    actions.push(
      'Triage the ⚠️ Warning findings and either remediate them or set the rule to `skip` in config once accepted.',
    );
  }
  if (totals.skip) {
    actions.push(
      'Review ⚪ Not Assessed controls — enable them in `security_txt.audit.rules` when they are relevant.',
    );
  }
  if (!actions.length) {
    actions.push('No action required. Keep the audit wired into CI to catch regressions.');
  }
  return actions;
}

function renderMarkdown(result) {
  const totals = result.totals();
  const [headline, detail] = verdict(totals);
  const ctx = result.context || {};

  const lines = [
    '# Blackout Secure Security TXT Generator Audit Report',
    '',
    '**Provided by [Blackout Secure](https://blackoutsecure.app)**',
    '',
    '## Summary',
    '',
    `**Verdict:** ${mdEscape(headline)}`,
    '',
    detail,
    '',
    `**Totals:** ✅ ${totals.pass} pass · ⚠️ ${totals.warn} warning · ` +
      `🔴 ${totals.fail} high · 🔥 ${totals.error} critical · ` +
      `⚪ ${totals.skip} not assessed`,
    '',
    '| Severity | Count | Meaning |',
    '| -------- | ----- | ------- |',
    `| ✅ Pass | ${totals.pass} | Control satisfied the configured policy. |`,
    `| ⚠️ Warning | ${totals.warn} | Review recommended; not usually a hard block by itself. |`,
    `| 🔴 High | ${totals.fail} | Required control failed and should be remediated. |`,
    `| 🔥 Critical | ${totals.error} | Audit execution or evidence collection error. |`,
    `| ⚪ Not Assessed | ${totals.skip} | Check was skipped or lacked sufficient evidence. |`,
    '',
  ];

  if (Object.keys(ctx).length) {
    lines.push('## Run Context', '');
    lines.push('| Field | Value |', '| ----- | ----- |');
    for (const [key, value] of Object.entries(ctx)) {
      lines.push(`| ${mdEscape(key)} | ${mdEscape(value)} |`);
    }
    lines.push('');
  }

  lines.push('## Recommended Actions', '');
  for (const action of recommendedActions(totals)) {
    lines.push(`- ${action}`);
  }
  lines.push('');

  lines.push(
    '## Scope and Methodology',
    '',
    'This automated audit reviews the generated security.txt against RFC 9116 — required and recommended directives, URI schemes, field cardinality, expiry hygiene, canonical placement, and encoding. Results are evidence-based at run time and are intended to support release, compliance, and vulnerability-disclosure readiness review.',
    '',
  );

  const recommendations = result.findings.filter(
    (f) => f.severity !== 'pass' && f.remediation.trim(),
  );
  lines.push(
    '## Recommendations',
    '',
    '| Finding Key | Rule | Assessment | Location | Evidence / Why | Recommended Action |',
    '| ----------- | ---- | ---------- | -------- | -------------- | ------------------ |',
  );
  if (recommendations.length) {
    for (const f of recommendations) {
      lines.push(
        `| \`${f.findingKey}\` | \`${f.ruleId}\` | ${severityLabel(f.severity)} | ` +
          `${mdEscape(f.location || '—')} | ${mdEscape(f.message)} | ${mdEscape(f.remediation)} |`,
      );
    }
  } else {
    lines.push('| — | — | — | — | — | — |');
  }
  lines.push('');

  if (!result.findings.length) {
    lines.push(
      '## Detailed Findings',
      '',
      '_No findings were emitted by the configured audit controls._',
      '',
    );
    return `${lines.join('\n')}\n`;
  }

  const buckets = new Map();
  for (const f of result.findings) {
    const idx = familyFor(f.ruleId);
    if (!buckets.has(idx)) buckets.set(idx, []);
    buckets.get(idx).push(f);
  }

  lines.push('## Detailed Findings', '');
  for (const idx of [...RULE_FAMILIES.map((_, i) => i), -1]) {
    const rows = buckets.get(idx);
    if (!rows || !rows.length) continue;
    const [, header, blurb] =
      idx === -1 ? ['', 'Other', 'Uncategorised controls'] : RULE_FAMILIES[idx];
    lines.push(`### ${header}`, `_${blurb}_`, '');

    const attention = rows.filter((f) => f.severity !== 'pass');
    const passed = rows.filter((f) => f.severity === 'pass');

    if (attention.length) {
      lines.push(
        '#### Findings Requiring Attention',
        '',
        '| Rule | Severity | Location | Control | Evidence | Recommended Remediation |',
        '| ---- | -------- | -------- | ------- | -------- | ----------------------- |',
      );
      for (const f of attention) {
        lines.push(
          `| \`${f.ruleId}\` | ${severityLabel(f.severity)} | ${mdEscape(f.location || '—')} | ` +
            `${mdEscape(f.title)} | ${mdEscape(f.message)} | ${mdEscape(f.remediation)} |`,
        );
      }
      lines.push('');
    }

    if (passed.length) {
      lines.push(
        '#### Passed Controls',
        '',
        '| Rule | Severity | Location | Control | Evidence |',
        '| ---- | -------- | -------- | ------- | -------- |',
      );
      for (const f of passed) {
        lines.push(
          `| \`${f.ruleId}\` | ${severityLabel(f.severity)} | ${mdEscape(f.location || '—')} | ` +
            `${mdEscape(f.title)} | ${mdEscape(f.message)} |`,
        );
      }
      lines.push('');
    }
  }

  return `${lines.join('\n')}\n`;
}

module.exports = {
  Finding,
  AuditResult,
  RULE_FAMILIES,
  RULE_TITLES,
  RULE_HELP,
  DEFAULT_REMEDIATIONS,
  severityLabel,
  verdict,
  mdEscape,
  familyFor,
};
