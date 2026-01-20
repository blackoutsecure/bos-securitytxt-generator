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

// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
// Output Formatting Functions
// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

/**
 * Print branded header banner to action output
 * @param {object} core - GitHub Actions core module
 */
function printHeader(core) {
  core.info('╔════════════════════════════════════════╗');
  core.info('║  Blackout Secure Security TXT Generator ║');
  core.info('║    RFC 9116 Vulnerability Disclosure   ║');
  core.info('║                                        ║');
  core.info('║  Copyright © 2025-2026 Blackout Secure ║');
  core.info('║     Licensed under Apache License 2.0 ║');
  core.info('╚════════════════════════════════════════╝');
}

/**
 * Print completion message to action output
 * @param {object} core - GitHub Actions core module
 */
function printFooter(core) {
  core.info('✓ Security.txt generation completed');
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
    const outputDir = core.getInput('output_dir') || '.';
    const siteUrl = core.getInput('site_url');
    const securityContact = core.getInput('security_contact');
    const securityExpires = core.getInput('security_expires');
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

    // ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
    // Configuration Logging
    // ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
    core.info('⚙️  Configuration:');
    core.info(`   Output Directory: ${outputDir}`);
    if (siteUrl) core.info(`   Site URL: ${siteUrl}`);
    if (securityContact) core.info(`   Contact: ${securityContact}`);
    if (securityExpires) core.info(`   Expires: ${securityExpires}`);
    if (securityPolicy) core.info(`   Policy: ${securityPolicy}`);

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
    core.info(`✓ Generated: ${securityTxtPath}`);

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
