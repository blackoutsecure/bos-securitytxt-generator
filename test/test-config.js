/**
 * Central Test Configuration
 *
 * This file contains shared configuration values used across all tests.
 * Modify values here to update them project-wide.
 */

const path = require('path');

const TEST_CONFIG = {
  // Directory path (relative to project root)
  // This serves as both the source directory (public_dir) and default output directory
  PUBLIC_DIR: 'dist',

  // Default site URL for tests
  SITE_URL: 'https://example.com/',

  // Test file names
  TEST_HTML_FILE: 'git-test.html',
  INDEX_HTML_FILE: 'index.html',

  // Sitemap generation defaults (for tests)
  SITEMAP_GENERATION: {
    XML: 'sitemap.xml',
    TXT: 'sitemap.txt',
    GZ: 'sitemap.xml.gz',
    INDEX: 'sitemap-index.xml',
    INDEX_GZ: 'sitemap-index.xml.gz',
  },

  // Robots.txt generation defaults (for tests)
  ROBOTS_GENERATION: {
    FILENAME: 'robots.txt',
    USER_AGENT: '*',
    DISALLOW: '/admin,/private',
  },

  // Humans.txt and security artifact names
  HUMANS_TXT: 'humans.txt',
  SECURITY_TXT: '.well-known/security.txt',

  // Timeouts (keep conservative to avoid runaway CI costs)
  // ACTION_TIMEOUT_MS should stay well below typical GitHub runner limits
  // ASYNC_WAIT_MS is the per-step wait used in async polling tests
  ACTION_TIMEOUT_MS: 12000,
  ASYNC_WAIT_MS: 1200,

  // Artifact retention
  RETENTION_DAYS: 5,

  // Humans.txt generation defaults (for tests)
  HUMANS_GENERATION: {
    TEAM_NAME: 'Development Team',
    TEAM_TITLE: 'Full Stack Developers',
    TEAM_CONTACT: 'dev@example.com',
    TEAM_LOCATION: 'San Francisco, CA',
    THANKS_NAME: 'Open Source Community',
    THANKS_URL: 'https://github.com',
    SITE_STANDARDS: 'HTML5, CSS3',
    SITE_COMPONENTS: 'React, Alpine.js',
    SITE_SOFTWARE: 'Node.js, Webpack',
    SITE_LANGUAGE: 'English',
    SITE_DOCTYPE: 'HTML5',
    COMMENTS: true,
  },

  // Security.txt generation defaults (for tests)
  SECURITY_GENERATION: {
    CONTACT: 'mailto:security@example.com',
    CONTACT_COMPANY: 'mailto:security@company.com',
    CONTACT_REPORT_URL: 'https://company.com/report',
    ACKNOWLEDGMENTS: 'https://example.com/hall-of-fame',
    ENCRYPTION: 'https://example.com/pgp-key.txt',
    POLICY: 'https://example.com/security-policy',
    HIRING: 'https://example.com/jobs',
    PREFERRED_LANGUAGES: 'en, es, fr',
    CANONICAL: 'https://example.com/.well-known/security.txt',
    COMMENTS: true,
  },

  // Additional URLs for testing
  ADDITIONAL_URLS: [
    'https://example.com/manual-1',
    'https://example.com/docs/guide',
  ],

  // URL variants for testing
  URL_VARIANTS: {
    SITE: 'https://example.com/',
    SITE_NO_SLASH: 'https://example.com',
    CANONICAL_SRC: 'https://example.com/src-canonical',
    EXTRA_PATH: 'https://example.com/extra.html',
    SECURITY_POLICY: 'https://example.com/security-policy',
    HALL_OF_FAME: 'https://example.com/hall-of-fame',
    PGP_KEY: 'https://example.com/pgp-key.txt',
    JOBS: 'https://example.com/jobs',
  },
};

/**
 * Get absolute path to a directory
 * @param {string} dir - Directory name from config (e.g., PUBLIC_DIR)
 * @returns {string} Absolute path
 */
function getAbsolutePath(dir) {
  return path.join(__dirname, '..', dir);
}

/**
 * Get absolute path to a file in public directory
 * @param {string} filename - File name
 * @returns {string} Absolute path
 */
function getPublicFilePath(filename) {
  return path.join(__dirname, '..', TEST_CONFIG.PUBLIC_DIR, filename);
}

module.exports = {
  TEST_CONFIG,
  getAbsolutePath,
  getPublicFilePath,
};

// Basic sanity validation to prevent runaway waits in CI
function validateConfig() {
  const maxActionTimeout = 30000; // hard safety cap for runner cost control
  const maxAsyncWait = 10000; // per-wait cap to avoid long hangs

  if (
    !Number.isFinite(TEST_CONFIG.ACTION_TIMEOUT_MS) ||
    TEST_CONFIG.ACTION_TIMEOUT_MS <= 0
  ) {
    throw new Error('TEST_CONFIG.ACTION_TIMEOUT_MS must be a positive number');
  }
  if (TEST_CONFIG.ACTION_TIMEOUT_MS > maxActionTimeout) {
    throw new Error(
      `TEST_CONFIG.ACTION_TIMEOUT_MS (${TEST_CONFIG.ACTION_TIMEOUT_MS}) exceeds safe cap (${maxActionTimeout}). Reduce to avoid runner overuse.`,
    );
  }

  if (
    !Number.isFinite(TEST_CONFIG.ASYNC_WAIT_MS) ||
    TEST_CONFIG.ASYNC_WAIT_MS <= 0
  ) {
    throw new Error('TEST_CONFIG.ASYNC_WAIT_MS must be a positive number');
  }
  if (TEST_CONFIG.ASYNC_WAIT_MS > maxAsyncWait) {
    throw new Error(
      `TEST_CONFIG.ASYNC_WAIT_MS (${TEST_CONFIG.ASYNC_WAIT_MS}) exceeds safe cap (${maxAsyncWait}). Reduce to avoid runner overuse.`,
    );
  }
  if (TEST_CONFIG.ASYNC_WAIT_MS > TEST_CONFIG.ACTION_TIMEOUT_MS) {
    throw new Error(
      'TEST_CONFIG.ASYNC_WAIT_MS must not exceed ACTION_TIMEOUT_MS; reduce wait or increase action timeout within safe limits.',
    );
  }
}

validateConfig();
