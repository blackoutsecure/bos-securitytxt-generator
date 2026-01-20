/**
 * Copyright 2025 Blackout Secure
 * SPDX-License-Identifier: Apache-2.0
 *
 * Unit tests for security.txt parser
 */

const assert = require('assert');
const {
  buildSecurityTxt,
  parseSecurityConfig,
} = require('../../src/lib/security-parser');

describe('buildSecurityTxt', () => {
  it('should throw error when contact is missing', () => {
    assert.throws(() => {
      buildSecurityTxt({ expires: '2025-12-31T23:59:59Z' });
    }, /Contact field is required per RFC 9116/);
  });

  it('should throw error when expires is missing', () => {
    assert.throws(() => {
      buildSecurityTxt({ contact: 'mailto:security@example.com' });
    }, /Expires field is required per RFC 9116/);
  });

  it('should generate minimal security.txt with required fields only', () => {
    const result = buildSecurityTxt({
      contact: 'mailto:security@example.com',
      expires: '2025-12-31T23:59:59Z',
    });

    assert.ok(result.includes('Contact: mailto:security@example.com'));
    assert.ok(result.includes('Expires: 2025-12-31T23:59:59Z'));
    assert.ok(!result.includes('#')); // No comments by default
  });

  it('should handle multiple contacts', () => {
    const result = buildSecurityTxt({
      contact: ['mailto:security@example.com', 'https://example.com/security'],
      expires: '2025-12-31T23:59:59Z',
    });

    assert.ok(result.includes('Contact: mailto:security@example.com'));
    assert.ok(result.includes('Contact: https://example.com/security'));
  });

  it('should include comments when enabled', () => {
    const result = buildSecurityTxt({
      contact: 'mailto:security@example.com',
      expires: '2025-12-31T23:59:59Z',
      includeComments: true,
    });

    assert.ok(result.includes('# security.txt file per RFC 9116'));
    assert.ok(result.includes('# https://www.rfc-editor.org/rfc/rfc9116'));
    assert.ok(
      result.includes('# Contact information for security researchers'),
    );
    assert.ok(result.includes('# Expiration date (ISO 8601 format)'));
  });

  it('should include all optional fields', () => {
    const result = buildSecurityTxt({
      contact: 'mailto:security@example.com',
      expires: '2025-12-31T23:59:59Z',
      acknowledgments: 'https://example.com/hall-of-fame',
      canonical: 'https://example.com/.well-known/security.txt',
      encryption: 'https://example.com/pgp-key.txt',
      hiring: 'https://example.com/jobs',
      policy: 'https://example.com/security-policy',
      preferredLanguages: 'en, es, fr',
    });

    assert.ok(result.includes('Contact: mailto:security@example.com'));
    assert.ok(result.includes('Expires: 2025-12-31T23:59:59Z'));
    assert.ok(
      result.includes('Acknowledgments: https://example.com/hall-of-fame'),
    );
    assert.ok(
      result.includes(
        'Canonical: https://example.com/.well-known/security.txt',
      ),
    );
    assert.ok(result.includes('Encryption: https://example.com/pgp-key.txt'));
    assert.ok(result.includes('Hiring: https://example.com/jobs'));
    assert.ok(result.includes('Policy: https://example.com/security-policy'));
    assert.ok(result.includes('Preferred-Languages: en, es, fr'));
  });

  it('should handle multiple values for repeatable fields', () => {
    const result = buildSecurityTxt({
      contact: ['mailto:security@example.com', 'tel:+1-555-0100'],
      expires: '2025-12-31T23:59:59Z',
      acknowledgments: [
        'https://example.com/hall-of-fame',
        'https://example.com/thanks',
      ],
      canonical: [
        'https://example.com/.well-known/security.txt',
        'https://www.example.com/.well-known/security.txt',
      ],
      encryption: [
        'https://example.com/pgp-key.txt',
        'openpgp4fpr:1234567890ABCDEF',
      ],
    });

    assert.ok(result.includes('Contact: mailto:security@example.com'));
    assert.ok(result.includes('Contact: tel:+1-555-0100'));
    assert.ok(
      result.includes('Acknowledgments: https://example.com/hall-of-fame'),
    );
    assert.ok(result.includes('Acknowledgments: https://example.com/thanks'));
    assert.ok(
      result.includes(
        'Canonical: https://example.com/.well-known/security.txt',
      ),
    );
    assert.ok(
      result.includes(
        'Canonical: https://www.example.com/.well-known/security.txt',
      ),
    );
    assert.ok(result.includes('Encryption: https://example.com/pgp-key.txt'));
    assert.ok(result.includes('Encryption: openpgp4fpr:1234567890ABCDEF'));
  });

  it('should auto-convert plain email to mailto: URI', () => {
    const result = buildSecurityTxt({
      contact: 'security@example.com',
      expires: '2025-12-31T23:59:59Z',
    });

    assert.ok(result.includes('Contact: mailto:security@example.com'));
  });

  it('should auto-convert phone number to tel: URI', () => {
    const result = buildSecurityTxt({
      contact: '+1-555-0100',
      expires: '2025-12-31T23:59:59Z',
    });

    assert.ok(result.includes('Contact: tel:+1-555-0100'));
  });

  it('should maintain correct field order per RFC 9116', () => {
    const result = buildSecurityTxt({
      contact: 'mailto:security@example.com',
      expires: '2025-12-31T23:59:59Z',
      canonical: 'https://example.com/.well-known/security.txt',
      acknowledgments: 'https://example.com/hall-of-fame',
      encryption: 'https://example.com/pgp-key.txt',
      policy: 'https://example.com/policy',
    });

    const lines = result
      .split('\n')
      .filter((line) => line && !line.startsWith('#'));

    // Canonical should come first (if present)
    assert.ok(lines[0].match(/^Canonical:/));

    // Contact should come before Expires
    const contactIndex = lines.findIndex((line) => line.startsWith('Contact:'));
    const expiresIndex = lines.findIndex((line) => line.startsWith('Expires:'));
    assert.ok(contactIndex > -1);
    assert.ok(expiresIndex > -1);
    assert.ok(contactIndex < expiresIndex);
  });
});

describe('parseSecurityConfig', () => {
  it('should parse single contact', () => {
    const config = parseSecurityConfig({
      contact: 'mailto:security@example.com',
      expires: '2025-12-31T23:59:59Z',
    });

    assert.strictEqual(config.contact, 'mailto:security@example.com');
    assert.strictEqual(config.expires, '2025-12-31T23:59:59Z');
  });

  it('should parse comma-separated contacts', () => {
    const config = parseSecurityConfig({
      contact: 'mailto:security@example.com, https://example.com/security',
      expires: '2025-12-31T23:59:59Z',
    });

    assert.deepStrictEqual(config.contact, [
      'mailto:security@example.com',
      'https://example.com/security',
    ]);
  });

  it('should parse all optional fields', () => {
    const config = parseSecurityConfig({
      contact: 'mailto:security@example.com',
      expires: '2025-12-31T23:59:59Z',
      acknowledgments: 'https://example.com/thanks',
      canonical: 'https://example.com/.well-known/security.txt',
      encryption: 'https://example.com/pgp-key.txt',
      hiring: 'https://example.com/jobs',
      policy: 'https://example.com/policy',
      preferredLanguages: 'en, es, fr',
      includeComments: true,
    });

    assert.strictEqual(config.acknowledgments, 'https://example.com/thanks');
    assert.strictEqual(
      config.canonical,
      'https://example.com/.well-known/security.txt',
    );
    assert.strictEqual(config.encryption, 'https://example.com/pgp-key.txt');
    assert.strictEqual(config.hiring, 'https://example.com/jobs');
    assert.strictEqual(config.policy, 'https://example.com/policy');
    assert.strictEqual(config.preferredLanguages, 'en, es, fr');
    assert.strictEqual(config.includeComments, true);
  });

  it('should handle comma-separated values for repeatable fields', () => {
    const config = parseSecurityConfig({
      contact: 'mailto:sec1@example.com, mailto:sec2@example.com',
      expires: '2025-12-31T23:59:59Z',
      acknowledgments:
        'https://example.com/thanks1, https://example.com/thanks2',
      encryption: 'https://example.com/key1.txt, https://example.com/key2.txt',
    });

    assert.deepStrictEqual(config.contact, [
      'mailto:sec1@example.com',
      'mailto:sec2@example.com',
    ]);
    assert.deepStrictEqual(config.acknowledgments, [
      'https://example.com/thanks1',
      'https://example.com/thanks2',
    ]);
    assert.deepStrictEqual(config.encryption, [
      'https://example.com/key1.txt',
      'https://example.com/key2.txt',
    ]);
  });

  it('should filter empty values from comma-separated input', () => {
    const config = parseSecurityConfig({
      contact: 'mailto:security@example.com, , ',
      expires: '2025-12-31T23:59:59Z',
    });

    assert.strictEqual(config.contact, 'mailto:security@example.com');
  });

  it('should trim whitespace from comma-separated values', () => {
    const config = parseSecurityConfig({
      contact: ' mailto:security@example.com , https://example.com/security ',
      acknowledgments:
        ' https://example.com/thanks , https://example.com/more ',
      canonical:
        ' https://example.com/.well-known/security.txt , https://www.example.com/.well-known/security.txt ',
      expires: '2025-12-31T23:59:59Z',
    });

    assert.deepStrictEqual(config.contact, [
      'mailto:security@example.com',
      'https://example.com/security',
    ]);
    assert.deepStrictEqual(config.acknowledgments, [
      'https://example.com/thanks',
      'https://example.com/more',
    ]);
    assert.deepStrictEqual(config.canonical, [
      'https://example.com/.well-known/security.txt',
      'https://www.example.com/.well-known/security.txt',
    ]);
  });

  it('should default includeComments to false', () => {
    const config = parseSecurityConfig({
      contact: 'mailto:security@example.com',
      expires: '2025-12-31T23:59:59Z',
    });

    assert.strictEqual(config.includeComments, false);
  });
});
