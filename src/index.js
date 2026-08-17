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
      } else if (artifact?.default && typeof artifact.default.uploadArtifact === 'function') {
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
const { parseExpiresDate } = require('./lib/expires');
const cfgMod = require('./lib/config');
const auditMod = require('./lib/audit');
const sarifMod = require('./lib/sarif');
const reportMod = require('./lib/report');
const aiMod = require('./lib/ai');
const { packageMetadata } = require('./lib/metadata');

// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
// Input Resolution Helpers
// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

/**
 * Read a boolean action input, falling back to the layered config value.
 * @param {string} name - Action input name.
 * @param {boolean} fallback - Config-derived default.
 * @returns {boolean} Resolved boolean.
 */
function boolInput(name, fallback) {
  const raw = (core.getInput(name) || '').trim();
  if (!raw) return fallback;
  return /^true$/i.test(raw);
}

/**
 * Read a comma-separated list input, falling back to the config value.
 * @param {string} name - Action input name.
 * @param {ReadonlyArray<string>} fallback - Config-derived default.
 * @returns {string[]} Resolved list.
 */
function listInput(name, fallback) {
  const raw = (core.getInput(name) || '').trim();
  if (!raw) return [...fallback];
  return raw
    .split(',')
    .map((s) => s.trim())
    .filter(Boolean);
}

/**
 * Resolve the tri-state `use_global_config` input.
 * @returns {boolean|null} true = require, false = disable, null = auto.
 */
function globalConfigMode() {
  const raw = (core.getInput('use_global_config') || 'auto').trim().toLowerCase();
  if (raw === 'true') return true;
  if (raw === 'false') return false;
  return null;
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
  const { getRepositoryUrl, getCopyrightNotice } = require('./lib/project-config');
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

    // ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
    // Layered configuration
    // ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
    // Precedence: action input (when set) > repository config > global
    // config > bundled marketplace baseline > built-in default.
    let cfg;
    try {
      cfg = cfgMod.resolve(process.cwd(), {
        configPath: core.getInput('config_path') || '',
        globalConfigPath: core.getInput('global_config_path') || cfgMod.DEFAULT_GLOBAL_CONFIG_PATH,
        useGlobalConfig: globalConfigMode(),
        useMarketplaceConfig: boolInput('use_marketplace_config', true),
        repoName: (process.env.GITHUB_REPOSITORY || '').split('/')[1] || '',
      });
    } catch (configError) {
      core.setFailed(`❌ Configuration error: ${configError.message}`);
      return;
    }

    const pkg = packageMetadata();
    core.info(`⚙️  ${pkg.name} v${pkg.version}`);
    core.info('   Config cascade:');
    for (const source of cfg.sourcePaths) {
      core.info(`      - ${source}`);
    }
    core.setOutput('config_sources', cfg.sourcePaths.join(','));

    // Read inputs
    const outputDir = core.getInput('public_dir') || 'dist';
    const siteUrl = core.getInput('site_url');
    const contactList = listInput('security_contact', cfg.fields.contact);

    // Validate required contact field per RFC 9116 § 2.5.3
    if (!contactList.length) {
      throw new Error(
        'security_contact is required per RFC 9116 § 2.5.3. Must be a URI (mailto:, https://, tel:) or email address.',
      );
    }
    const securityContact = contactList.length === 1 ? contactList[0] : contactList;
    const securityExpiresInput = core.getInput('security_expires') || cfg.fields.expires;
    const securityAcknowledgments = listInput(
      'security_acknowledgments',
      cfg.fields.acknowledgments,
    );
    const securityCanonical = listInput('security_canonical', cfg.fields.canonical);
    const securityEncryption = listInput('security_encryption', cfg.fields.encryption);
    const securityHiring = listInput('security_hiring', cfg.fields.hiring);
    const securityPolicy = listInput('security_policy', cfg.fields.policy);
    const securityPreferredLanguages =
      core.getInput('security_preferred_languages') || cfg.fields.preferredLanguages;
    const securityComments = boolInput('security_comments', cfg.generate.includeComments);
    const writeRootFallback = boolInput('write_root_fallback', cfg.generate.writeRootFallback);
    const uploadArtifacts = /^true$/i.test(core.getInput('upload_artifacts') || 'true');
    const artifactName = core.getInput('artifact_name') || 'securitytxt';
    const artifactRetentionDays = core.getInput('artifact_retention_days');
    const debug = /^true$/i.test(core.getInput('debug') || 'false');

    // Parse and validate expires date
    const { date: securityExpires, daysFromNow } = parseExpiresDate(securityExpiresInput);

    // RFC 9116 compliance check
    if (daysFromNow > cfg.audit.expiresMaxDays) {
      core.warning(
        `⚠️  Expires date is ${daysFromNow} days from now, beyond the configured ${cfg.audit.expiresMaxDays}-day maximum. RFC 9116 recommends less than 1 year to avoid staleness.`,
      );
    } else if (!core.getInput('security_expires')) {
      core.info(`ℹ️  Using configured expiration: ${daysFromNow} days (${securityExpires})`);
    }

    // ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
    // Configuration Logging
    // ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
    const keyPad = (label) => `${label}:`.padEnd(22, ' ');
    core.info('⚙️  Configuration:');
    if (siteUrl) core.info(`   ${keyPad('Site URL')} ${siteUrl}`);
    core.info(`   ${keyPad('Public Directory')} ./${outputDir}`);
    core.info(`   ${keyPad('Security Output Dir')} ./${outputDir}`);
    core.info(`   ${keyPad('Security Filename')} ${cfg.generate.filename}`);
    core.info(`   ${keyPad('Contact')} ${contactList.join(', ')}`);
    core.info(`   ${keyPad('Expires')} ${securityExpires}`);
    const canonicalPreview =
      securityCanonical.join(', ') ||
      (siteUrl ? `${siteUrl}/.well-known/security.txt` : '') ||
      '(none)';
    core.info(`   ${keyPad('Canonical')} ${canonicalPreview}`);
    core.info(`   ${keyPad('Include Comments')} ${securityComments ? 'Yes' : 'No'}`);
    core.info(`   ${keyPad('Root Fallback')} ${writeRootFallback ? 'Enabled' : 'Disabled'}`);
    core.info(`   ${keyPad('Upload Artifacts')} ${uploadArtifacts ? 'Enabled' : 'Disabled'}`);
    if (artifactRetentionDays) {
      core.info(`   ${keyPad('Artifact Retention')} ${artifactRetentionDays} day(s)`);
    }
    core.info(
      `   ${keyPad('Audit')} ${boolInput('enable_audit', cfg.audit.enable) ? 'Enabled' : 'Disabled'}`,
    );
    core.info(
      `   ${keyPad('Audit Fail On')} ${core.getInput('audit_fail_on') || cfg.audit.failOn}`,
    );
    core.info(`   ${keyPad('SARIF Output')} ${core.getInput('sarif_output') || '(disabled)'}`);
    core.info(`   ${keyPad('JSON Report')} ${core.getInput('report_json') || '(disabled)'}`);

    // ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
    // Security.txt Content Generation
    // ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
    const oneOrMany = (values) =>
      values.length === 0 ? undefined : values.length === 1 ? values[0] : values;

    const securityData = {
      contact: securityContact,
      expires: securityExpires,
      canonical:
        oneOrMany(securityCanonical) ||
        (siteUrl ? `${siteUrl.replace(/\/+$/, '')}/.well-known/security.txt` : undefined),
      acknowledgments: oneOrMany(securityAcknowledgments),
      encryption: oneOrMany(securityEncryption),
      hiring: oneOrMany(securityHiring),
      policy: oneOrMany(securityPolicy),
      preferredLanguages: securityPreferredLanguages || undefined,
      includeComments: securityComments,
    };

    core.info('');
    core.info('📝 Generating security.txt...');
    const securityTxt = buildSecurityTxt(securityData);

    if (!securityTxt) {
      throw new Error('Failed to generate security.txt. Check inputs and try again.');
    }

    // ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
    // File System Operations
    // ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
    const wellKnownDir = path.join(outputDir, '.well-known');
    if (!fs.existsSync(wellKnownDir)) {
      fs.mkdirSync(wellKnownDir, { recursive: true });
    }

    // Write security.txt
    const securityTxtPath = path.join(wellKnownDir, cfg.generate.filename);
    fs.writeFileSync(securityTxtPath, securityTxt, 'utf-8');

    // RFC 9116 § 3 allows a legacy root copy for pre-standard crawlers.
    let rootFallbackPath = '';
    if (writeRootFallback) {
      rootFallbackPath = path.join(outputDir, cfg.generate.filename);
      fs.writeFileSync(rootFallbackPath, securityTxt, 'utf-8');
      core.info(`✅ legacy root copy written: ${path.relative(process.cwd(), rootFallbackPath)}`);
    }
    // Validation block
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

    core.info(`✅ security.txt written: ${path.relative(process.cwd(), securityTxtPath)}`);
    try {
      const stats2 = fs.statSync(securityTxtPath);
      const sizeKb2 = (stats2.size / 1024).toFixed(2);
      core.info(`   Size: ${sizeKb2} KB`);
    } catch (error) {
      core.debug(`Unable to read generated file stats: ${error.message}`);
    }

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
        await client.uploadArtifact(artifactName, [securityTxtPath], outputDir, uploadOptions);
        core.info(`✓ Artifact uploaded: ${artifactName}`);
      } catch (err) {
        core.warning(`⚠️  Failed to upload artifact: ${err.message}`);
      }
    }

    // ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
    // RFC 9116 Audit + Reporting
    // ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
    if (boolInput('enable_audit', cfg.audit.enable)) {
      const auditResult = auditMod.audit({
        cfg,
        content: securityTxt,
        filePath: securityTxtPath,
        siteUrl,
        publicDir: outputDir,
      });

      reportMod.printAuditTable(core, auditResult);

      const failOnInput = (core.getInput('audit_fail_on') || '').trim();
      const failOn = cfgMod.FAIL_ON_LEVELS.includes(failOnInput) ? failOnInput : cfg.audit.failOn;
      if (failOnInput && !cfgMod.FAIL_ON_LEVELS.includes(failOnInput)) {
        core.warning(
          `audit_fail_on: '${failOnInput}' is not one of ${cfgMod.FAIL_ON_LEVELS.join(', ')}; using '${failOn}'.`,
        );
      }
      const failRun = auditMod.shouldFail(auditResult, failOn);
      reportMod.annotate(core, auditResult, failRun);

      const remediation = {
        ...cfg.remediation,
        enableAiFindingsSummary: boolInput(
          'enable_ai_summary',
          cfg.remediation.enableAiFindingsSummary,
        ),
        aiFindingsSummaryProvider:
          core.getInput('ai_provider') || cfg.remediation.aiFindingsSummaryProvider,
      };
      const summary = await aiMod.buildSummary(auditResult, remediation);
      if (summary.text) {
        core.info('');
        core.info(`🤖 Findings summary (${summary.provider}):`);
        for (const line of summary.text.split('\n')) {
          core.info(`   ${line}`);
        }
      }

      const sarifPath = core.getInput('sarif_output') || '';
      if (cfg.reporting.sarif && sarifPath) {
        try {
          sarifMod.dump(
            sarifMod.merge({
              runs: [sarifMod.auditRun(auditResult.findings, { baseDir: process.cwd() })],
            }),
            sarifPath,
          );
          core.info(`   ✓ SARIF written: ${sarifPath}`);
          core.setOutput('sarif_path', sarifPath);
        } catch (err) {
          core.warning(`   ⚠️  Failed to write SARIF: ${err.message}`);
        }
      }

      const reportPath = core.getInput('report_json') || '';
      if (cfg.reporting.jsonReport && reportPath) {
        try {
          reportMod.writeJsonReport(auditResult, reportPath, {
            ai_summary: summary.text,
            ai_provider: summary.provider,
            config_sources: [...cfg.sourcePaths],
            package: pkg,
          });
          core.info(`   ✓ JSON report written: ${reportPath}`);
          core.setOutput('report_json_path', reportPath);
        } catch (err) {
          core.warning(`   ⚠️  Failed to write JSON report: ${err.message}`);
        }
      }

      const recommendationsPath = core.getInput('recommendations_json') || '';
      if (cfg.reporting.recommendations && recommendationsPath) {
        try {
          reportMod.writeRecommendations(auditResult, recommendationsPath);
          core.info(`   ✓ Recommendations written: ${recommendationsPath}`);
          core.setOutput('recommendations_json_path', recommendationsPath);
        } catch (err) {
          core.warning(`   ⚠️  Failed to write recommendations: ${err.message}`);
        }
      }

      const skipsPath = core.getInput('skips_json') || '';
      if (skipsPath) {
        try {
          reportMod.writeSkips(auditResult, skipsPath);
          core.info(`   ✓ Skips written: ${skipsPath}`);
        } catch (err) {
          core.warning(`   ⚠️  Failed to write skips: ${err.message}`);
        }
      }

      if (boolInput('step_summary', cfg.reporting.stepSummary)) {
        reportMod.writeStepSummary(auditResult, {
          aiSummary: summary.text,
          aiProvider: summary.provider,
        });
      }

      const totals = auditResult.totals();
      core.setOutput('audit_verdict', auditResult.toJSON().verdict);
      core.setOutput('audit_pass_count', String(totals.pass));
      core.setOutput('audit_warn_count', String(totals.warn));
      core.setOutput('audit_fail_count', String(totals.fail));
      core.setOutput('audit_error_count', String(totals.error));
      core.setOutput('audit_skip_count', String(totals.skip));
      core.setOutput('ai_summary', summary.text);
    } else {
      core.info('');
      core.info('🛡️  RFC 9116 Audit: Disabled');
    }

    // Set outputs
    core.setOutput('security_path', securityTxtPath);
    core.setOutput('security_root_path', rootFallbackPath);
    core.setOutput('security_expires', securityExpires);

    printFooter(core);
  } catch (error) {
    core.setFailed(error.message);
    process.exit(1);
  }
}

run();
