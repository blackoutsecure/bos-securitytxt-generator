// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
// Blackout Secure Security TXT Generator GitHub Action
// Copyright © 2025-2026 Blackout Secure
// Licensed under Apache License 2.0
// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
// Deterministic RFC 9116 compliance audit.
//
// Every rule is driven by `security_txt.audit.rules.<name>` in the
// layered configuration. A rule configured as `skip` still emits a
// finding so the report records that the control was deliberately not
// assessed rather than silently dropped.
// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

const fs = require('fs');
const path = require('path');

const { Finding, AuditResult } = require('./findings');
const { parseSecurityTxt, SINGLE_VALUED_FIELDS } = require('./security-parser');

const MAX_EVIDENCE_SAMPLES = 5;

/** URI schemes RFC 9116 accepts for a Contact value. */
const CONTACT_SCHEMES = ['mailto:', 'https://', 'tel:'];

/** Fields whose values are web URIs and therefore must use HTTPS. */
const WEB_URI_FIELDS = ['acknowledgments', 'canonical', 'hiring', 'policy'];

/**
 * Run the full RFC 9116 audit against generated security.txt content.
 *
 * @param {object} options - Audit inputs.
 * @param {object} options.cfg - Resolved configuration.
 * @param {string} options.content - security.txt content.
 * @param {string} options.filePath - Path the file was written to.
 * @param {string} [options.siteUrl] - Declared public base URL.
 * @param {string} [options.publicDir] - Published site directory.
 * @param {Date} [options.now] - Clock injection point for expiry checks.
 * @returns {AuditResult} Findings plus run context.
 */
function audit({ cfg, content, filePath, siteUrl = '', publicDir = '', now = new Date() }) {
  const rules = cfg.audit.rules;
  const findings = [];
  const location = filePath ? relativeTo(publicDir || process.cwd(), filePath) : 'security.txt';

  /**
   * Evaluate one rule against a boolean outcome.
   * @param {string} ruleId - Rule identifier.
   * @param {string} ruleName - Config key under `audit.rules`.
   * @param {object} outcome - Evaluation outcome.
   * @param {boolean} outcome.ok - Whether the control is satisfied.
   * @param {string} outcome.passMessage - Evidence when satisfied.
   * @param {string} outcome.failMessage - Evidence when violated.
   * @param {object} [outcome.evidence] - Machine-readable evidence.
   */
  const evaluate = (ruleId, ruleName, outcome) => {
    const severity = rules[ruleName];
    if (severity === 'skip') {
      findings.push(
        new Finding({
          ruleId,
          severity: 'skip',
          message: `Control disabled via \`security_txt.audit.rules.${ruleName}: skip\`.`,
          location,
          evidence: { rule: ruleName },
        }),
      );
      return;
    }
    findings.push(
      new Finding({
        ruleId,
        severity: outcome.ok ? 'pass' : severity,
        message: outcome.ok ? outcome.passMessage : outcome.failMessage,
        location,
        evidence: outcome.evidence || {},
      }),
    );
  };

  const parsed = parseSecurityTxt(content || '');
  const get = (name) => parsed.fields[name] || [];

  const contacts = get('contact');
  const expiresValues = get('expires');
  const canonicals = get('canonical');

  // ── ST00x: required fields ───────────────────────────────────────
  evaluate('ST001', 'require_contact', {
    ok: contacts.length > 0,
    passMessage: `${contacts.length} Contact directive(s) present.`,
    failMessage: 'No Contact directive found; RFC 9116 § 2.5.3 makes it mandatory.',
    evidence: { contact_count: contacts.length },
  });

  evaluate('ST002', 'require_expires', {
    ok: expiresValues.length > 0,
    passMessage: `Expires directive present (${expiresValues[0]}).`,
    failMessage: 'No Expires directive found; RFC 9116 § 2.5.5 makes it mandatory.',
    evidence: { expires_count: expiresValues.length },
  });

  const expiresDate = expiresValues.length ? parseDate(expiresValues[0]) : null;
  const daysRemaining = expiresDate
    ? Math.round((expiresDate.getTime() - now.getTime()) / 86400000)
    : null;

  evaluate('ST003', 'expires_not_expired', {
    ok: Boolean(expiresDate) && expiresDate.getTime() > now.getTime(),
    passMessage: `Expires is ${daysRemaining} day(s) in the future.`,
    failMessage: expiresDate
      ? `Expires is ${Math.abs(daysRemaining)} day(s) in the past (${expiresValues[0]}).`
      : 'Expires is missing or not a parseable ISO 8601 timestamp.',
    evidence: { expires: expiresValues[0] || '', days_remaining: daysRemaining },
  });

  const maxDays = cfg.audit.expiresMaxDays;
  evaluate('ST004', 'expires_within_max_days', {
    ok: daysRemaining !== null && daysRemaining <= maxDays,
    passMessage: `Expires is ${daysRemaining} day(s) out, within the ${maxDays}-day maximum.`,
    failMessage:
      daysRemaining === null
        ? 'Expires is missing or unparseable, so the validity window cannot be bounded.'
        : `Expires is ${daysRemaining} day(s) out, beyond the ${maxDays}-day maximum.`,
    evidence: { days_remaining: daysRemaining, max_days: maxDays },
  });

  evaluate('ST005', 'require_canonical', {
    ok: canonicals.length > 0,
    passMessage: `${canonicals.length} Canonical directive(s) present.`,
    failMessage: 'No Canonical directive found; researchers cannot verify where the file belongs.',
    evidence: { canonical_count: canonicals.length },
  });

  const expectedCanonical = siteUrl
    ? `${siteUrl.replace(/\/+$/, '')}/.well-known/security.txt`
    : '';
  evaluate('ST006', 'canonical_matches_site_url', {
    ok: Boolean(expectedCanonical) && canonicals.includes(expectedCanonical),
    passMessage: `Canonical matches ${expectedCanonical}.`,
    failMessage: expectedCanonical
      ? `No Canonical matches the expected ${expectedCanonical}.`
      : 'No site_url was supplied, so the expected Canonical URI is unknown.',
    evidence: { expected: expectedCanonical, ...samples(canonicals) },
  });

  // ── ST01x: field hygiene ─────────────────────────────────────────
  const insecureUris = [];
  for (const field of WEB_URI_FIELDS) {
    for (const value of get(field)) {
      if (/^http:\/\//i.test(value)) insecureUris.push(`${field}: ${value}`);
    }
  }
  for (const value of contacts) {
    if (/^http:\/\//i.test(value)) insecureUris.push(`contact: ${value}`);
  }
  evaluate('ST010', 'require_https_uris', {
    ok: insecureUris.length === 0,
    passMessage: 'Every web URI uses HTTPS.',
    failMessage: `${insecureUris.length} directive value(s) use insecure http://.`,
    evidence: samples(insecureUris),
  });

  const invalidContacts = contacts.filter(
    (value) => !CONTACT_SCHEMES.some((scheme) => value.toLowerCase().startsWith(scheme)),
  );
  evaluate('ST011', 'valid_contact_uri', {
    ok: contacts.length > 0 && invalidContacts.length === 0,
    passMessage: 'Every Contact value is a mailto:, https://, or tel: URI.',
    failMessage: contacts.length
      ? `${invalidContacts.length} Contact value(s) are not a supported URI scheme.`
      : 'No Contact directive to validate.',
    evidence: samples(invalidContacts),
  });

  evaluate('ST012', 'require_multiple_contacts', {
    ok: contacts.length > 1,
    passMessage: `${contacts.length} contact channels are published.`,
    failMessage: `Only ${contacts.length} contact channel is published; a single channel is a availability risk.`,
    evidence: { contact_count: contacts.length },
  });

  const languages = get('preferred-languages');
  const invalidTags = languages.length
    ? languages[0]
        .split(',')
        .map((tag) => tag.trim())
        .filter((tag) => tag && !/^[a-z]{2,3}(-[a-z0-9]{2,8})*$/i.test(tag))
    : [];
  evaluate('ST013', 'valid_preferred_languages', {
    ok: invalidTags.length === 0,
    passMessage: languages.length
      ? `Preferred-Languages uses valid RFC 5646 tags (${languages[0]}).`
      : 'No Preferred-Languages directive to validate.',
    failMessage: `${invalidTags.length} invalid language tag(s) in Preferred-Languages.`,
    evidence: samples(invalidTags),
  });

  const duplicated = SINGLE_VALUED_FIELDS.filter((name) => get(name).length > 1);
  evaluate('ST014', 'single_valued_fields', {
    ok: duplicated.length === 0,
    passMessage: 'Single-valued directives appear at most once.',
    failMessage: `Single-valued directive(s) repeated: ${duplicated.join(', ')}.`,
    evidence: samples(duplicated),
  });

  evaluate('ST015', 'forbid_unknown_fields', {
    ok: parsed.unknownFields.length === 0 && parsed.malformedLines.length === 0,
    passMessage: 'Only registered RFC 9116 directives are present.',
    failMessage:
      `${parsed.unknownFields.length} unknown directive(s) and ` +
      `${parsed.malformedLines.length} malformed line(s) found.`,
    evidence: {
      ...samples(parsed.unknownFields),
      malformed_lines: parsed.malformedLines.slice(0, MAX_EVIDENCE_SAMPLES),
    },
  });

  // ── ST02x: recommended fields ────────────────────────────────────
  const recommended = [
    ['ST020', 'recommend_encryption', 'encryption', 'Encryption'],
    ['ST021', 'recommend_policy', 'policy', 'Policy'],
    ['ST022', 'recommend_acknowledgments', 'acknowledgments', 'Acknowledgments'],
    ['ST023', 'recommend_hiring', 'hiring', 'Hiring'],
  ];
  for (const [ruleId, ruleName, field, label] of recommended) {
    const values = get(field);
    evaluate(ruleId, ruleName, {
      ok: values.length > 0,
      passMessage: `${label} directive present (${values.length} value(s)).`,
      failMessage: `No ${label} directive found.`,
      evidence: { count: values.length },
    });
  }

  // ── ST03x: file placement ────────────────────────────────────────
  const normalizedPath = (filePath || '').replace(/\\/g, '/');
  evaluate('ST030', 'well_known_location', {
    ok: normalizedPath.endsWith('/.well-known/security.txt'),
    passMessage: 'File is written to /.well-known/security.txt.',
    failMessage: `File is written to ${normalizedPath || '(unknown)'}, not /.well-known/security.txt.`,
    evidence: { path: normalizedPath },
  });

  const sizeBytes = byteLength(content);
  const maxBytes = cfg.audit.maxSizeKb * 1024;
  evaluate('ST031', 'file_size_limit', {
    ok: sizeBytes <= maxBytes,
    passMessage: `File is ${sizeBytes} bytes, within the ${cfg.audit.maxSizeKb} KB limit.`,
    failMessage: `File is ${sizeBytes} bytes, beyond the ${cfg.audit.maxSizeKb} KB limit.`,
    evidence: { size_bytes: sizeBytes, max_bytes: maxBytes },
  });

  const signaturePath = filePath ? `${filePath}.sig` : '';
  const signatureOnDisk = signaturePath ? existsFile(signaturePath) : false;
  evaluate('ST032', 'require_signature', {
    ok: parsed.signed || signatureOnDisk,
    passMessage: parsed.signed
      ? 'File carries an inline OpenPGP cleartext signature.'
      : 'A detached security.txt.sig is published alongside the file.',
    failMessage: 'No OpenPGP signature found inline or as a detached security.txt.sig.',
    evidence: { inline_signature: parsed.signed, detached_signature: signatureOnDisk },
  });

  // ── ST04x: encoding ──────────────────────────────────────────────
  evaluate('ST040', 'require_utf8_no_bom', {
    ok: !parsed.hasBom,
    passMessage: 'File is UTF-8 encoded without a byte-order mark.',
    failMessage: 'File starts with a UTF-8 byte-order mark, which breaks strict parsers.',
    evidence: { has_bom: parsed.hasBom },
  });

  return new AuditResult(findings, {
    site_url: siteUrl,
    public_dir: publicDir,
    file_path: normalizedPath,
    size_bytes: sizeBytes,
    contact_count: contacts.length,
    expires: expiresValues[0] || '',
    days_remaining: daysRemaining,
  });
}

/**
 * Decide the process exit disposition for an audit result.
 * @param {AuditResult} result - Completed audit.
 * @param {string} failOn - Either `fail` or `never`.
 * @returns {boolean} True when the run should be marked failed.
 */
function shouldFail(result, failOn) {
  if (failOn === 'never') return false;
  return result.failed.length > 0 || result.errored.length > 0;
}

function parseDate(value) {
  const parsed = new Date(value);
  return Number.isNaN(parsed.getTime()) ? null : parsed;
}

function byteLength(content) {
  return Buffer.byteLength(content || '', 'utf8');
}

function existsFile(candidate) {
  try {
    return fs.statSync(candidate).isFile();
  } catch {
    return false;
  }
}

function relativeTo(baseDir, filePath) {
  const relative = path.relative(baseDir, filePath);
  const chosen = relative && !relative.startsWith('..') ? relative : filePath;
  return chosen.replace(/\\/g, '/');
}

function samples(values) {
  if (!values || !values.length) return {};
  return {
    samples: values.slice(0, MAX_EVIDENCE_SAMPLES),
    sample_truncated: values.length > MAX_EVIDENCE_SAMPLES,
    total: values.length,
  };
}

module.exports = {
  audit,
  shouldFail,
  CONTACT_SCHEMES,
  WEB_URI_FIELDS,
  MAX_EVIDENCE_SAMPLES,
};
