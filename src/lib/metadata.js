// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
// Blackout Secure Security TXT Generator GitHub Action
// Copyright © 2025-2026 Blackout Secure
// Licensed under Apache License 2.0
// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
// Package identity, independent of repository policy configuration.
// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

const PACKAGE_NAME = 'bos-securitytxt-generator';
const PACKAGE_AUTHOR = 'Blackout Secure';
const PACKAGE_DESCRIPTION =
  'Generate, validate, and audit RFC 9116-compliant security.txt for responsible vulnerability disclosure.';

/**
 * Return package identity without loading any marketplace configuration.
 * @returns {{name: string, version: string, author: string, description: string}}
 */
function packageMetadata() {
  let pkg = {};
  try {
    pkg = require('../../package.json');
  } catch {
    pkg = {};
  }
  return {
    name: pkg.name || PACKAGE_NAME,
    version: pkg.version || '0.0.0',
    author: typeof pkg.author === 'string' ? pkg.author : pkg.author?.name || PACKAGE_AUTHOR,
    description: pkg.description || PACKAGE_DESCRIPTION,
  };
}

module.exports = {
  PACKAGE_NAME,
  PACKAGE_AUTHOR,
  PACKAGE_DESCRIPTION,
  packageMetadata,
};
