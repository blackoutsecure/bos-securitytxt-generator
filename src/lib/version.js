#!/usr/bin/env node
// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
// Blackout Secure Security TXT Generator GitHub Action
// Copyright © 2025-2026 Blackout Secure
// Licensed under Apache License 2.0
// Website: https://blackoutsecure.app
// Repository: https://github.com/blackoutsecure/bos-securitytxt-generator
// Issues: https://github.com/blackoutsecure/bos-securitytxt-generator/issues
// Docs: https://github.com/blackoutsecure/bos-securitytxt-generator#readme
// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
// Version management utility for synchronizing package.json and config
// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

const fs = require('fs');
const path = require('path');

// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
// File Path Constants
// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

const ROOT_DIR = path.join(__dirname, '..', '..');
const PACKAGE_JSON_PATH = path.join(ROOT_DIR, 'package.json');
const PROJECT_CONFIG_PATH = path.join(
  ROOT_DIR,
  'src',
  'lib',
  'project-config.js',
);

// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
// File Operations
// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

function readPackageJson() {
  const content = fs.readFileSync(PACKAGE_JSON_PATH, 'utf8');
  return JSON.parse(content);
}

function writePackageJson(pkg) {
  fs.writeFileSync(
    PACKAGE_JSON_PATH,
    JSON.stringify(pkg, null, 2) + '\n',
    'utf8',
  );
}

function updateProjectConfig(version) {
  try {
    const content = fs.readFileSync(PROJECT_CONFIG_PATH, 'utf8');
    const next = content.replace(
      /version:\s*['"][\d.]+['"]/,
      `version: '${version}'`,
    );
    if (next !== content) {
      fs.writeFileSync(PROJECT_CONFIG_PATH, next, 'utf8');
    }
  } catch {
    // optional - skip if file not present
  }
}

// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
// Version Operations
// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

/**
 * Get current version from package.json
 * @returns {string} Current version
 */
function getCurrentVersion() {
  const pkg = readPackageJson();
  return pkg.version;
}

/**
 * Set explicit version in package.json and project-config.js
 * @param {string} version - Version string in x.y.z format
 */
function setVersion(version) {
  if (!/^\d+\.\d+\.\d+$/.test(version)) {
    console.error('Invalid version. Use x.y.z (e.g., 1.2.3)');
    process.exit(1);
  }
  const pkg = readPackageJson();
  pkg.version = version;
  writePackageJson(pkg);
  updateProjectConfig(version);
  console.log(`Version updated to ${version}`);
}

function incrementVersion(type = 'patch') {
  const current = getCurrentVersion();
  const parts = current.split('.').map(Number);
  switch (type) {
    case 'major':
      parts[0]++;
      parts[1] = 0;
      parts[2] = 0;
      break;
    case 'minor':
      parts[1]++;
      parts[2] = 0;
      break;
    case 'patch':
    default:
      parts[2]++;
      break;
  }
  const next = parts.join('.');
  setVersion(next);
}

if (require.main === module) {
  const args = process.argv.slice(2);
  const cmd = args[0];
  if (!cmd) {
    console.log('Current version:', getCurrentVersion());
    console.log('\nUsage:');
    console.log('  node src/lib/version.js set 1.2.3');
    console.log('  node src/lib/version.js patch|min|minor|major');
    process.exit(0);
  }
  if (cmd === 'set') {
    const v = args[1];
    if (!v) {
      console.error('Provide a version to set, e.g., 1.2.3');
      process.exit(1);
    }
    setVersion(v);
    process.exit(0);
  }
  if (['patch', 'minor', 'major'].includes(cmd)) {
    incrementVersion(cmd);
    process.exit(0);
  }
  console.error('Unknown command:', cmd);
  process.exit(1);
}

module.exports = { getCurrentVersion, setVersion, incrementVersion };
