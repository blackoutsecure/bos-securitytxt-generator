/**
 * Copyright 2025 Blackout Secure
 * SPDX-License-Identifier: Apache-2.0
 */

const core = require('@actions/core');
const path = require('path');
const fs = require('fs');

let artifactClient;

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

// Library imports
const { buildSecurityTxt } = require('./lib/security-parser');

function printHeader(core) {
  core.info('╔════════════════════════════════════════╗');
  core.info('║  Blackout Secure Security TXT Generator ║');
  core.info('║    RFC 9116 Vulnerability Disclosure   ║');
  core.info('║                                        ║');
  core.info('║   Copyright © 2025 Blackout Secure    ║');
  core.info('║     Licensed under Apache License 2.0 ║');
  core.info('╚════════════════════════════════════════╝');
}

function printFooter(core) {
  core.info('✓ Security.txt generation completed');
}

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

    // Log configuration
    core.info('⚙️  Configuration:');
    core.info(`   Output Directory: ${outputDir}`);
    if (siteUrl) core.info(`   Site URL: ${siteUrl}`);
    if (securityContact) core.info(`   Contact: ${securityContact}`);
    if (securityExpires) core.info(`   Expires: ${securityExpires}`);
    if (securityPolicy) core.info(`   Policy: ${securityPolicy}`);

    // Build security.txt content
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

    // Create output directory structure
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

    // Upload artifacts
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
