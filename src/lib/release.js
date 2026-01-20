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
// Automated release management and git tagging utility
// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

const { execSync } = require('child_process');
const { setVersion, getCurrentVersion } = require('./version');

// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
// Utilities
// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

function exec(command, options = {}) {
  console.log(`  $ ${command}`);
  try {
    return execSync(command, { stdio: 'inherit', ...options });
  } catch {
    console.error(`Command failed: ${command}`);
    process.exit(1);
  }
}

function checkGitClean() {
  try {
    execSync('git diff-index --quiet HEAD --', { stdio: 'pipe' });
    return true;
  } catch {
    return false;
  }
}

// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
// Release Automation
// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

function release(versionType = null) {
  console.log('Starting release process...');
  console.log();

  if (!checkGitClean()) {
    console.error('Git working directory is not clean. Commit changes first.');
    process.exit(1);
  }

  let version;
  if (versionType && /^\d+\.\d+\.\d+$/.test(versionType)) {
    version = versionType;
  } else if (versionType && ['patch', 'minor', 'major'].includes(versionType)) {
    const current = getCurrentVersion();
    const parts = current.split('.').map(Number);
    switch (versionType) {
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
    version = parts.join('.');
  } else {
    version = getCurrentVersion();
  }

  console.log(`Releasing v${version}...\n`);

  console.log(`1) Updating version to ${version}...`);
  setVersion(version);
  console.log();

  console.log('2) Building dist/...');
  exec('npm run build');
  console.log();

  console.log('3) Running tests...');
  exec('npm test');
  console.log();

  console.log('4) Committing changes...');
  exec(
    'git add package.json package-lock.json src/lib/project-config.js dist/',
  );
  exec(`git commit -m "chore: release v${version}"`);
  console.log();

  console.log(`5) Creating git tag v${version}...`);
  exec(`git tag -a v${version} -m "Release v${version}"`);
  console.log();

  console.log('6) Pushing to remote...');
  exec('git push origin main');
  exec(`git push origin v${version}`);
  console.log();

  const major = version.split('.')[0];
  console.log(`7) Creating moving tags v${major} and latest...`);
  exec(`git tag -f v${major} v${version}`);
  exec(`git push -f origin v${major}`);
  exec(`git tag -f latest v${version}`);
  exec(`git push -f origin latest`);
  console.log();

  console.log(`Successfully released v${version}`);
  console.log('\nUsers can now reference:');
  console.log(`   - @v${version}`);
  console.log(`   - @v${major}`);
  console.log('   - @latest');
}

if (require.main === module) {
  const args = process.argv.slice(2);
  let input = args[0];

  if (!input) {
    console.log('Usage:');
    console.log('  npm run release <version>   # e.g., 1.2.3');
    console.log('  npm run release patch|min|minor|major');
    console.log();
    console.log(`Current version: ${getCurrentVersion()}`);
    process.exit(1);
  }

  input = input.replace(/^v/, '');
  release(input);
}

module.exports = { release };
