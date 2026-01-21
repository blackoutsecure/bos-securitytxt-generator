// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
// Blackout Secure Security TXT Generator GitHub Action
// Copyright © 2025-2026 Blackout Secure
// Licensed under Apache License 2.0
// Website: https://blackoutsecure.app
// Repository: https://github.com/blackoutsecure/bos-securitytxt-generator
// Issues: https://github.com/blackoutsecure/bos-securitytxt-generator/issues
// Docs: https://github.com/blackoutsecure/bos-securitytxt-generator#readme
// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
// Main entry point for generating RFC 9116 compliant security.txt files
// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

const core = require('@actions/core');
const path = require('path');
const fs = require('fs');

// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
// Artifact Client Initialization
// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

let artifactClient;

/**
 * Initialize the GitHub Actions artifact client for uploading generated files
 * Supports both DefaultArtifactClient and legacy artifact interfaces
 * @returns {object|null} Artifact client instance or null if not available
 */
function initializeArtifactClient() {
  if (artifactClient !== undefined) {
    return artifactClient;
  }

  artifactClient = null;

  try {
    if (process.env.GITHUB_ACTIONS === 'true') {
      const artifact = require('@actions/artifact');
      if (artifact?.DefaultArtifactClient) {
        artifactClient = new artifact.DefaultArtifactClient();
      } else if (
        artifact?.default &&
        typeof artifact.default.uploadArtifact === 'function'
      ) {
        artifactClient = artifact.default;
      }
    }
  } catch {
    // Artifact client not available (likely local/dev environment)
  }

  return artifactClient;
}

// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
// Library Imports
// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

const { buildSecurityTxt } = require('./lib/security-parser');

// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━// Date Parsing and Validation
// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

/**
 * Parse expires date from various formats
 * @param {string} input - User input (ISO 8601, "30d", "6m", "1y", or empty)
 * @returns {object} {date: ISO string, daysFromNow: number}
 */
function parseExpiresDate(input) {
  let targetDate;
  let isoString;
  const now = new Date();

  if (!input) {
    // Default: 180 days (6 months) - well under 1 year per RFC 9116
    targetDate = new Date(now.getTime() + 180 * 24 * 60 * 60 * 1000);
    isoString = targetDate.toISOString();
  } else if (/^\d+d$/i.test(input)) {
    // Days format: "30d", "180d"
    const days = parseInt(input, 10);
    targetDate = new Date(now.getTime() + days * 24 * 60 * 60 * 1000);
    isoString = targetDate.toISOString();
  } else if (/^\d+m$/i.test(input)) {
    // Months format: "6m", "12m"
    const months = parseInt(input, 10);
    targetDate = new Date(now);
    targetDate.setMonth(targetDate.getMonth() + months);
    isoString = targetDate.toISOString();
  } else if (/^\d+y$/i.test(input)) {
    // Years format: "1y"
    const years = parseInt(input, 10);
    targetDate = new Date(now);
    targetDate.setFullYear(targetDate.getFullYear() + years);
    isoString = targetDate.toISOString();
  } else {
    // Assume ISO 8601 format or parseable date string
    targetDate = new Date(input);
    if (isNaN(targetDate.getTime())) {
      throw new Error(
        `Invalid expires date format: "${input}". Use ISO 8601, "30d", "6m", or "1y".`,
      );
    }
    // Preserve original format if it's already ISO 8601
    isoString = input;
  }

  const daysFromNow = Math.round(
    (targetDate.getTime() - now.getTime()) / (24 * 60 * 60 * 1000),
  );
  return {
    date: isoString,
    daysFromNow,
  };
}

// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━// Output Formatting Functions
// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

/**
 * Print branded header banner to action output
 * @param {object} core - GitHub Actions core module
 */
function printHeader(core) {
  const {
    getProjectTitle,
    getRepositoryUrl,
    getSupportUrl,
    getDocsUrl,
    getCopyrightNotice,
  } = require('./lib/project-config');

  const divider = '━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━';
  core.info(divider);
  core.info(getProjectTitle());
  core.info(divider);
  core.info(getCopyrightNotice());
  core.info(getRepositoryUrl());
  core.info(getSupportUrl());
  core.info(divider);
}

/**
 * Print completion message to action output
 * @param {object} core - GitHub Actions core module
 */
function printFooter(core) {
  const {
    getRepositoryUrl,
    getCopyrightNotice,
  } = require('./lib/project-config');
  const divider = '━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━';
  core.info('✓ Security.txt generation completed');
  core.info(divider);
  core.info('✅ Security.txt generation complete!');
  core.info(divider);
  core.info(getCopyrightNotice());
  core.info(getRepositoryUrl());
  core.info(divider);
}

// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
// Main Execution Function
// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

/**
 * Main execution function for the GitHub Action
 * Reads inputs, generates security.txt, and optionally uploads artifacts
 */
async function run() {
  try {
    // Print application header
    printHeader(core);

    // Read inputs
    const outputDir = core.getInput('public_dir') || 'dist';
    const siteUrl = core.getInput('site_url');
    const securityContact = core.getInput('security_contact');

    // Validate required contact field per RFC 9116 § 2.5.3
    if (!securityContact) {
      throw new Error(
        'security_contact is required per RFC 9116 § 2.5.3. Must be a URI (mailto:, https://, tel:) or email address.',
      );
    }
    const securityExpiresInput = core.getInput('security_expires');
    const securityAcknowledgments = core.getInput('security_acknowledgments');
    const securityCanonical = core.getInput('security_canonical');
    const securityEncryption = core.getInput('security_encryption');
    const securityHiring = core.getInput('security_hiring');
    const securityPolicy = core.getInput('security_policy');
    const securityPreferredLanguages = core.getInput(
      'security_preferred_languages',
    );
    const securityComments = /^true$/i.test(
      core.getInput('security_comments') || 'true',
    );
    const uploadArtifacts = /^true$/i.test(
      core.getInput('upload_artifacts') || 'true',
    );
    const artifactName = core.getInput('artifact_name') || 'securitytxt';
    const artifactRetentionDays = core.getInput('artifact_retention_days');
    const debug = /^true$/i.test(core.getInput('debug') || 'false');

    // Parse and validate expires date
    const { date: securityExpires, daysFromNow } =
      parseExpiresDate(securityExpiresInput);

    // RFC 9116 compliance check
    if (daysFromNow > 365) {
      core.warning(
        `⚠️  Expires date is ${daysFromNow} days from now. RFC 9116 recommends less than 1 year (365 days) to avoid staleness.`,
      );
    } else if (!securityExpiresInput) {
      core.info(
        `ℹ️  Using default expiration: ${daysFromNow} days (${securityExpires})`,
      );
    }

    // ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
    // Configuration Logging
    // ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
    const keyPad = (label) => `${label}:`.padEnd(22, ' ');
    core.info('⚙️  Configuration:');
    if (siteUrl) core.info(`   ${keyPad('Site URL')} ${siteUrl}`);
    core.info(`   ${keyPad('Public Directory')} ./${outputDir}`);
    core.info(`   ${keyPad('Security Output Dir')} ./${outputDir}`);
    core.info(`   ${keyPad('Security Filename')} security.txt`);
    core.info(`   ${keyPad('Contact')} ${securityContact}`);
    core.info(`   ${keyPad('Expires')} ${securityExpires}`);
    const canonicalPreview =
      securityCanonical ||
      (siteUrl ? `${siteUrl}/.well-known/security.txt` : '') ||
      '(none)';
    core.info(`   ${keyPad('Canonical')} ${canonicalPreview}`);
    core.info(
      `   ${keyPad('Include Comments')} ${securityComments ? 'Yes' : 'No'}`,
    );
    core.info(
      `   ${keyPad('Upload Artifacts')} ${uploadArtifacts ? 'Enabled' : 'Disabled'}`,
    );
    if (artifactRetentionDays) {
      core.info(
        `   ${keyPad('Artifact Retention')} ${artifactRetentionDays} day(s)`,
      );
    }

    // ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
    // Security.txt Content Generation
    // ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
    const securityData = {
      contact: securityContact,
      expires: securityExpires,
      canonical:
        securityCanonical ||
        (siteUrl ? `${siteUrl}/.well-known/security.txt` : undefined),
      acknowledgments: securityAcknowledgments,
      encryption: securityEncryption,
      hiring: securityHiring,
      policy: securityPolicy,
      preferredLanguages: securityPreferredLanguages,
      includeComments: securityComments,
    };

    core.info('');
    core.info('📝 Generating security.txt...');
    const securityTxt = buildSecurityTxt(securityData);

    if (!securityTxt) {
      throw new Error(
        'Failed to generate security.txt. Check inputs and try again.',
      );
    }

    // ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
    // File System Operations
    // ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
    const wellKnownDir = path.join(outputDir, '.well-known');
    if (!fs.existsSync(wellKnownDir)) {
      fs.mkdirSync(wellKnownDir, { recursive: true });
    }

    // Write security.txt
    const securityTxtPath = path.join(wellKnownDir, 'security.txt');
    fs.writeFileSync(securityTxtPath, securityTxt, 'utf-8');
    // Validation block
    const divider = '━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━';
    core.info('');
    core.info('🔍 Validation:');
    try {
      const stats = fs.statSync(securityTxtPath);
      const sizeKb = (stats.size / 1024).toFixed(2);
      core.info(`   ✓ Size OK (${sizeKb} KB)`);
    } catch {
      // ignore size errors
    }
    const hasContact = /\n?Contact:\s/.test(securityTxt);
    const hasExpires = /\n?Expires:\s/.test(securityTxt);
    if (hasContact && hasExpires) {
      core.info('   ✓ Contains required fields (Contact, Expires)');
    }
    const hasCanonical = /\n?Canonical:\s/.test(securityTxt);
    if (hasCanonical) {
      core.info('   ✓ Contains Canonical reference');
    }

    core.info(
      `✅ security.txt written: ${path.relative(process.cwd(), securityTxtPath)}`,
    );
    try {
      const stats2 = fs.statSync(securityTxtPath);
      const sizeKb2 = (stats2.size / 1024).toFixed(2);
      core.info(`   Size: ${sizeKb2} KB`);
    } catch {}

    // Show content in debug mode
    if (debug) {
      core.info('📄 Content:');
      core.info(securityTxt);
    }

    // ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
    // Artifact Upload (Optional)
    // ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
    const client = initializeArtifactClient();
    if (uploadArtifacts && client) {
      core.info('📦 Uploading artifacts...');
      const uploadOptions = {};
      if (artifactRetentionDays) {
        uploadOptions.retentionDays = parseInt(artifactRetentionDays, 10);
      }

      try {
        await client.uploadArtifact(
          artifactName,
          [securityTxtPath],
          outputDir,
          uploadOptions,
        );
        core.info(`✓ Artifact uploaded: ${artifactName}`);
      } catch (err) {
        core.warning(`⚠️  Failed to upload artifact: ${err.message}`);
      }
    }

    // Set outputs
    core.setOutput('security_path', securityTxtPath);

    printFooter(core);
  } catch (error) {
    core.setFailed(error.message);
    process.exit(1);
  }
}

run();
