// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
// Blackout Secure Security TXT Generator GitHub Action
// Copyright © 2025-2026 Blackout Secure
// Licensed under Apache License 2.0
// Website: https://blackoutsecure.app
// Repository: https://github.com/blackoutsecure/bos-securitytxt-generator
// Issues: https://github.com/blackoutsecure/bos-securitytxt-generator/issues
// Docs: https://github.com/blackoutsecure/bos-securitytxt-generator#readme
// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
// Security.txt generation and parsing utilities (RFC 9116 compliant)
// Reference: https://www.rfc-editor.org/rfc/rfc9116
// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

const { getSecurityTxtHeader } = require('./project-config');

// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
// Security.txt Content Builder
// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

/**
 * Build security.txt content following RFC 9116 standard
 * @param {object} options - Configuration options
 * @param {string|string[]} options.contact - Contact method(s) for reporting vulnerabilities (required)
 * @param {string} options.expires - Expiration date in ISO 8601 format (required)
 * @param {string|string[]} options.acknowledgments - URL(s) to security acknowledgments page
 * @param {string|string[]} options.canonical - Canonical URI(s) for this file
 * @param {string|string[]} options.encryption - URL(s) to encryption key
 * @param {string|string[]} options.hiring - URL(s) to security job postings
 * @param {string|string[]} options.policy - URL(s) to vulnerability disclosure policy
 * @param {string} options.preferredLanguages - Comma-separated language codes (e.g., "en, es, fr")
 * @param {boolean} options.includeComments - Include explanatory comments
 * @returns {string} - Generated security.txt content
 */
function buildSecurityTxt(options = {}) {
  const {
    contact,
    expires,
    acknowledgments,
    canonical,
    encryption,
    hiring,
    policy,
    preferredLanguages,
    includeComments = false,
  } = options;

  // Validate required fields
  if (!contact || (Array.isArray(contact) && contact.length === 0)) {
    throw new Error('Contact field is required per RFC 9116 § 2.5.3');
  }
  if (!expires) {
    throw new Error('Expires field is required per RFC 9116 § 2.5.5');
  }

  // Validate contact URIs per RFC 9116 § 2.5.3
  const contacts = Array.isArray(contact) ? contact : [contact];
  for (const c of contacts) {
    // Contact must be a URI or email/phone that can be converted to URI
    const isEmail = c.includes('@');
    const isPhone = /^\+?\d/.test(c);
    const isUri =
      c.startsWith('mailto:') ||
      c.startsWith('https://') ||
      c.startsWith('http://') ||
      c.startsWith('tel:');

    if (!isEmail && !isPhone && !isUri) {
      throw new Error(
        `Invalid contact URI: "${c}". Per RFC 9116 § 2.5.3, contact must be a URI (mailto:, https://, tel:) or email address.`,
      );
    }
  }

  const lines = [];

  // Add generation header and guidance comments only when explicitly requested
  if (includeComments) {
    const headerLines = getSecurityTxtHeader().split('\n');
    lines.push(...headerLines);
    lines.push('');
    lines.push('# security.txt file per RFC 9116');
    lines.push('# https://www.rfc-editor.org/rfc/rfc9116');
    lines.push('');
  }

  // Canonical URIs (optional, but recommended for signed files)
  if (canonical) {
    if (includeComments) {
      lines.push('# Canonical URIs where this file is located');
    }
    const canonicalUrls = Array.isArray(canonical) ? canonical : [canonical];
    for (const url of canonicalUrls) {
      lines.push(`Canonical: ${url}`);
    }
    lines.push('');
  }

  // Contact (required, can appear multiple times)
  if (includeComments) {
    lines.push('# Contact information for security researchers');
  }
  // Reuse contacts array from validation above
  for (const c of contacts) {
    // Ensure proper URI format
    let contactUri = c;
    if (c.includes('@') && !c.startsWith('mailto:')) {
      contactUri = `mailto:${c}`;
    } else if (/^\+?\d/.test(c) && !c.startsWith('tel:')) {
      contactUri = `tel:${c}`;
    }
    lines.push(`Contact: ${contactUri}`);
  }
  lines.push('');

  // Expires (required, exactly once)
  if (includeComments) {
    lines.push('# Expiration date (ISO 8601 format)');
  }
  lines.push(`Expires: ${expires}`);
  lines.push('');

  // Encryption (optional)
  if (encryption) {
    if (includeComments) {
      lines.push('# Link to encryption key for secure communication');
    }
    const encryptionUrls = Array.isArray(encryption)
      ? encryption
      : [encryption];
    for (const url of encryptionUrls) {
      lines.push(`Encryption: ${url}`);
    }
    lines.push('');
  }

  // Acknowledgments (optional)
  if (acknowledgments) {
    if (includeComments) {
      lines.push('# Security researchers hall of fame');
    }
    const ackUrls = Array.isArray(acknowledgments)
      ? acknowledgments
      : [acknowledgments];
    for (const url of ackUrls) {
      lines.push(`Acknowledgments: ${url}`);
    }
    lines.push('');
  }

  // Preferred-Languages (optional, max once)
  if (preferredLanguages) {
    if (includeComments) {
      lines.push('# Preferred languages for security reports');
    }
    lines.push(`Preferred-Languages: ${preferredLanguages}`);
    lines.push('');
  }

  // Policy (optional)
  if (policy) {
    if (includeComments) {
      lines.push('# Vulnerability disclosure policy');
    }
    const policyUrls = Array.isArray(policy) ? policy : [policy];
    for (const url of policyUrls) {
      lines.push(`Policy: ${url}`);
    }
    lines.push('');
  }

  // Hiring (optional)
  if (hiring) {
    if (includeComments) {
      lines.push('# Security-related job openings');
    }
    const hiringUrls = Array.isArray(hiring) ? hiring : [hiring];
    for (const url of hiringUrls) {
      lines.push(`Hiring: ${url}`);
    }
    lines.push('');
  }

  return lines.join('\n');
}

// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
// Configuration Parser
// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

/**
 * Parse security.txt configuration from inputs
 * @param {object} inputs - Raw input values
 * @returns {object} - Parsed configuration
 */
function parseSecurityConfig(inputs) {
  const config = {
    includeComments: inputs.includeComments || false,
  };

  // Contact (required)
  if (inputs.contact) {
    const contacts = inputs.contact
      .split(',')
      .map((s) => s.trim())
      .filter(Boolean);
    config.contact = contacts.length === 1 ? contacts[0] : contacts;
  }

  // Expires (required)
  if (inputs.expires) {
    config.expires = inputs.expires;
  }

  // Acknowledgments (optional)
  if (inputs.acknowledgments) {
    const acks = inputs.acknowledgments
      .split(',')
      .map((s) => s.trim())
      .filter(Boolean);
    config.acknowledgments = acks.length === 1 ? acks[0] : acks;
  }

  // Canonical (optional)
  if (inputs.canonical) {
    const cans = inputs.canonical
      .split(',')
      .map((s) => s.trim())
      .filter(Boolean);
    config.canonical = cans.length === 1 ? cans[0] : cans;
  }

  // Encryption (optional)
  if (inputs.encryption) {
    const encs = inputs.encryption
      .split(',')
      .map((s) => s.trim())
      .filter(Boolean);
    config.encryption = encs.length === 1 ? encs[0] : encs;
  }

  // Hiring (optional)
  if (inputs.hiring) {
    const hires = inputs.hiring
      .split(',')
      .map((s) => s.trim())
      .filter(Boolean);
    config.hiring = hires.length === 1 ? hires[0] : hires;
  }

  // Policy (optional)
  if (inputs.policy) {
    const pols = inputs.policy
      .split(',')
      .map((s) => s.trim())
      .filter(Boolean);
    config.policy = pols.length === 1 ? pols[0] : pols;
  }

  // Preferred-Languages (optional, single value with comma-separated codes)
  if (inputs.preferredLanguages) {
    config.preferredLanguages = inputs.preferredLanguages;
  }

  return config;
}

module.exports = {
  buildSecurityTxt,
  parseSecurityConfig,
};
