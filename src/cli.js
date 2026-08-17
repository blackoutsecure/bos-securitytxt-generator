#!/usr/bin/env node
// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
// Blackout Secure Security TXT Generator GitHub Action
// Copyright © 2025-2026 Blackout Secure
// Licensed under Apache License 2.0
// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
// CLI companion to the Action.
//
// Subcommands:
//   version   Print the package version.
//   validate  Resolve layered configuration and print the result.
//   generate  Write security.txt from the resolved configuration.
//   audit     Audit an existing security.txt against RFC 9116.
//   sarif     Merge SARIF files into one log ready for GHAS upload.
//
// The Action and the CLI share the same modules, so a local dry-run
// produces byte-identical reports to a CI run.
// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

const fs = require('fs');
const path = require('path');

const cfgMod = require('./lib/config');
const metadataMod = require('./lib/metadata');
const auditMod = require('./lib/audit');
const sarifMod = require('./lib/sarif');
const reportMod = require('./lib/report');
const aiMod = require('./lib/ai');
const { buildSecurityTxt } = require('./lib/security-parser');
const { parseExpiresDate } = require('./lib/expires');

const USAGE = `bos-securitytxt <command> [options]

Commands:
  version                       Print the package version.
  validate                      Resolve and validate layered configuration.
  generate                      Write security.txt from the resolved config.
  audit                         Audit an existing security.txt (RFC 9116).
  sarif                         Merge SARIF files into one log.

Common options:
  --root <dir>                  Repository root (default: cwd).
  --config <path>               Explicit repository config path.
  --global-config <path>        Global config path (default: ${cfgMod.DEFAULT_GLOBAL_CONFIG_PATH}).
  --use-global-config           Require the global config tier.
  --no-global-config            Disable global config discovery.
  --no-marketplace-config       Skip the bundled marketplace baseline.

generate options:
  --public-dir <dir>            Output directory (default: dist).
  --site-url <url>              Public base URL, used for Canonical.
  --contact <uri>               Contact value (repeatable; overrides config).

audit options:
  --file <path>                 security.txt to audit.
  --public-dir <dir>            Directory holding .well-known/security.txt.
  --site-url <url>              Public base URL, used for Canonical checks.
  --sarif <path>                Write audit findings as SARIF.
  --json <path>                 Write the machine-readable JSON report.
  --recommendations <path>      Write the recommendations sidecar.
  --skips <path>                Write the skipped-controls sidecar.
  --fail-on <fail|never>        Override the configured exit policy.
  --no-ai                       Disable the AI findings summary.

sarif options:
  --input <path>                SARIF file to merge (repeatable).
  --output <path>               Destination path (required).
`;

/**
 * Parse argv into a flag map plus repeated arguments.
 * @param {string[]} argv - Raw arguments (without node/script).
 * @returns {{command: string, flags: object, repeated: object}} Parsed args.
 */
function parseArgs(argv) {
  const flags = {};
  const repeated = { input: [], contact: [] };
  const [command = '', ...rest] = argv;

  for (let i = 0; i < rest.length; i += 1) {
    const token = rest[i];
    if (!token.startsWith('--')) continue;
    const key = token.slice(2);

    if (key === 'use-global-config') {
      flags.useGlobalConfig = true;
      continue;
    }
    if (key === 'no-global-config') {
      flags.useGlobalConfig = false;
      continue;
    }
    if (key === 'no-marketplace-config') {
      flags.useMarketplaceConfig = false;
      continue;
    }
    if (key === 'no-ai') {
      flags.noAi = true;
      continue;
    }
    if (key === 'help') {
      flags.help = true;
      continue;
    }

    const value = rest[i + 1];
    if (value === undefined || value.startsWith('--')) {
      throw new Error(`option --${key} requires a value`);
    }
    i += 1;
    if (key === 'input' || key === 'contact') repeated[key].push(value);
    else flags[camel(key)] = value;
  }

  return { command, flags, repeated };
}

function camel(key) {
  return key.replace(/-([a-z])/g, (_, ch) => ch.toUpperCase());
}

function resolveConfig(flags) {
  return cfgMod.resolve(flags.root || '.', {
    configPath: flags.config || '',
    globalConfigPath: flags.globalConfig || cfgMod.DEFAULT_GLOBAL_CONFIG_PATH,
    useGlobalConfig: flags.useGlobalConfig === undefined ? null : flags.useGlobalConfig,
    useMarketplaceConfig: flags.useMarketplaceConfig !== false,
    repoName: (process.env.GITHUB_REPOSITORY || '').split('/')[1] || '',
  });
}

function cmdVersion() {
  process.stdout.write(`${metadataMod.packageMetadata().version}\n`);
  return 0;
}

function cmdValidate(flags) {
  const pkg = metadataMod.packageMetadata();
  const cfg = resolveConfig(flags);

  const out = [
    'Package metadata:',
    `  name:        ${pkg.name}`,
    `  version:     ${pkg.version}`,
    `  author:      ${pkg.author}`,
    `  description: ${pkg.description}`,
    'Config cascade:',
    ...cfg.sourcePaths.map((source) => `  - ${source}`),
    `owner:        ${cfg.owner || '(unset)'}`,
    `project_name: ${cfg.projectName || '(unset)'}`,
    `email:        ${cfg.email || '(unset)'}`,
    `generate:     comments=${cfg.generate.includeComments} file=${cfg.generate.filename} root_fallback=${cfg.generate.writeRootFallback}`,
    `fields:       expires=${cfg.fields.expires} contacts=${cfg.fields.contact.length} policy=${cfg.fields.policy.length}`,
    `audit:        enable=${cfg.audit.enable} fail_on=${cfg.audit.failOn} max_size_kb=${cfg.audit.maxSizeKb} expires_max_days=${cfg.audit.expiresMaxDays}`,
    `reporting:    step_summary=${cfg.reporting.stepSummary} sarif=${cfg.reporting.sarif} json=${cfg.reporting.jsonReport} recommendations=${cfg.reporting.recommendations}`,
    `remediation:  ai=${cfg.remediation.enableAiFindingsSummary} provider=${cfg.remediation.aiFindingsSummaryProvider} fallback=${cfg.remediation.localHeuristicFallback}`,
    'audit rules:',
    ...Object.entries(cfg.audit.rules).map(
      ([name, severity]) => `  ${name.padEnd(30)} ${severity}`,
    ),
  ];
  process.stdout.write(`${out.join('\n')}\n`);
  return 0;
}

/**
 * Build security.txt content from resolved config plus CLI overrides.
 * @param {object} cfg - Resolved configuration.
 * @param {string} siteUrl - Public base URL.
 * @param {string[]} contactOverride - Contacts supplied on the command line.
 * @returns {string} security.txt content.
 */
function contentFromConfig(cfg, siteUrl, contactOverride) {
  const contact = contactOverride.length ? contactOverride : [...cfg.fields.contact];
  if (!contact.length) {
    throw new Error(
      'no contact configured — set `security_txt.fields.contact` or pass --contact <uri>',
    );
  }
  const canonical = cfg.fields.canonical.length
    ? [...cfg.fields.canonical]
    : siteUrl
      ? [`${siteUrl.replace(/\/+$/, '')}/.well-known/security.txt`]
      : undefined;

  return buildSecurityTxt({
    contact,
    expires: parseExpiresDate(cfg.fields.expires).date,
    canonical,
    acknowledgments: optional(cfg.fields.acknowledgments),
    encryption: optional(cfg.fields.encryption),
    hiring: optional(cfg.fields.hiring),
    policy: optional(cfg.fields.policy),
    preferredLanguages: cfg.fields.preferredLanguages || undefined,
    includeComments: cfg.generate.includeComments,
  });
}

function optional(values) {
  return values.length ? [...values] : undefined;
}

function cmdGenerate(flags, repeated) {
  const root = path.resolve(flags.root || '.');
  const cfg = resolveConfig(flags);
  const publicDir = path.resolve(root, flags.publicDir || 'dist');
  const content = contentFromConfig(cfg, flags.siteUrl || '', repeated.contact);

  const target = path.join(publicDir, '.well-known', cfg.generate.filename);
  fs.mkdirSync(path.dirname(target), { recursive: true });
  fs.writeFileSync(target, content, 'utf8');
  process.stderr.write(`wrote ${target}\n`);

  if (cfg.generate.writeRootFallback) {
    const fallback = path.join(publicDir, cfg.generate.filename);
    fs.writeFileSync(fallback, content, 'utf8');
    process.stderr.write(`wrote legacy fallback ${fallback}\n`);
  }
  return 0;
}

async function cmdAudit(flags) {
  const root = path.resolve(flags.root || '.');
  const cfg = resolveConfig(flags);

  const publicDir = path.resolve(root, flags.publicDir || 'dist');
  const filePath = flags.file
    ? path.resolve(root, flags.file)
    : path.join(publicDir, '.well-known', cfg.generate.filename);

  if (!fs.existsSync(filePath)) {
    process.stderr.write(`error: security.txt not found: ${filePath}\n`);
    return 2;
  }

  const result = auditMod.audit({
    cfg,
    content: fs.readFileSync(filePath, 'utf8'),
    filePath,
    siteUrl: flags.siteUrl || '',
    publicDir,
  });

  reportMod.printAuditTable(consoleCore(), result);

  const summary = flags.noAi
    ? { text: aiMod.localSummary(result), provider: 'local-heuristic' }
    : await aiMod.buildSummary(result, cfg.remediation);
  if (summary.text) {
    process.stdout.write(`\nFindings summary (${summary.provider}):\n${summary.text}\n`);
  }

  if (flags.sarif) {
    sarifMod.dump(
      sarifMod.merge({ runs: [sarifMod.auditRun(result.findings, { baseDir: root })] }),
      flags.sarif,
    );
    process.stderr.write(`wrote SARIF: ${flags.sarif}\n`);
  }
  if (flags.json) {
    reportMod.writeJsonReport(result, flags.json, {
      ai_summary: summary.text,
      ai_provider: summary.provider,
    });
    process.stderr.write(`wrote JSON report: ${flags.json}\n`);
  }
  if (flags.recommendations) {
    reportMod.writeRecommendations(result, flags.recommendations);
    process.stderr.write(`wrote recommendations: ${flags.recommendations}\n`);
  }
  if (flags.skips) {
    reportMod.writeSkips(result, flags.skips);
    process.stderr.write(`wrote skips: ${flags.skips}\n`);
  }
  reportMod.writeStepSummary(result, {
    aiSummary: summary.text,
    aiProvider: summary.provider,
  });

  const failOn = flags.failOn || cfg.audit.failOn;
  if (!cfgMod.FAIL_ON_LEVELS.includes(failOn)) {
    process.stderr.write(`error: --fail-on must be one of ${cfgMod.FAIL_ON_LEVELS.join(', ')}\n`);
    return 2;
  }
  return auditMod.shouldFail(result, failOn) ? 1 : 0;
}

function cmdSarif(flags, repeated) {
  if (!flags.output) {
    process.stderr.write('error: --output is required\n');
    return 2;
  }
  const logs = [];
  for (const input of repeated.input) {
    if (!fs.existsSync(input)) {
      process.stderr.write(`note: skipping missing SARIF input: ${input}\n`);
      continue;
    }
    logs.push(sarifMod.load(input));
  }
  const merged = sarifMod.merge(...logs);
  sarifMod.dump(merged, flags.output);
  process.stderr.write(
    `wrote merged SARIF: ${flags.output} (${merged.runs.length} run(s), ${logs.length} input(s))\n`,
  );
  return 0;
}

/** Minimal `@actions/core`-shaped logger for CLI use. */
function consoleCore() {
  return {
    info: (msg) => process.stdout.write(`${msg}\n`),
    warning: (msg) => process.stderr.write(`warning: ${msg}\n`),
    error: (msg) => process.stderr.write(`error: ${msg}\n`),
    debug: () => {},
    setFailed: (msg) => process.stderr.write(`error: ${msg}\n`),
  };
}

/**
 * CLI entry point.
 * @param {string[]} [argv] - Arguments without node/script.
 * @returns {Promise<number>} Process exit code.
 */
async function main(argv = process.argv.slice(2)) {
  let parsed;
  try {
    parsed = parseArgs(argv);
  } catch (err) {
    process.stderr.write(`error: ${err.message}\n`);
    return 2;
  }

  const { command, flags, repeated } = parsed;
  if (!command || flags.help || command === 'help') {
    process.stdout.write(USAGE);
    return command && command !== 'help' ? 2 : 0;
  }

  try {
    switch (command) {
      case 'version':
        return cmdVersion();
      case 'validate':
        return cmdValidate(flags);
      case 'generate':
        return cmdGenerate(flags, repeated);
      case 'audit':
        return await cmdAudit(flags);
      case 'sarif':
        return cmdSarif(flags, repeated);
      default:
        process.stderr.write(`error: unknown command '${command}'\n\n${USAGE}`);
        return 2;
    }
  } catch (err) {
    process.stderr.write(`error: ${err.message}\n`);
    return 2;
  }
}

if (require.main === module) {
  main().then((code) => {
    process.exitCode = code;
  });
}

module.exports = { main, parseArgs, contentFromConfig, USAGE };
