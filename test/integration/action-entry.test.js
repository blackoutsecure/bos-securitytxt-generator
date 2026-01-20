const fs = require('fs');
const path = require('path');
const os = require('os');
const assert = require('assert');
const { setActionInput, clearActionInputs } = require('../test-helpers');

function waitForFile(filePath, timeoutMs = 2000, intervalMs = 50) {
  return new Promise((resolve, reject) => {
    const start = Date.now();
    const timer = setInterval(() => {
      if (fs.existsSync(filePath)) {
        clearInterval(timer);
        resolve();
      } else if (Date.now() - start > timeoutMs) {
        clearInterval(timer);
        reject(new Error(`Timed out waiting for file: ${filePath}`));
      }
    }, intervalMs);
  });
}

describe('Action entrypoint', () => {
  // Test against source to allow mocking, dist is tested implicitly by build
  const srcPath = path.resolve('src/index.js');
  let originalArtifactCache;
  let originalGithubActions;
  let originalCoreCache;

  function resetEnv() {
    if (originalGithubActions === undefined) {
      delete process.env.GITHUB_ACTIONS;
    } else {
      process.env.GITHUB_ACTIONS = originalGithubActions;
    }
  }

  before(function () {
    if (!fs.existsSync(srcPath)) {
      throw new Error(
        `Action entry point missing: ${srcPath}. Check src directory.`,
      );
    }
    originalGithubActions = process.env.GITHUB_ACTIONS;
  });

  afterEach(() => {
    if (originalArtifactCache) {
      require.cache[originalArtifactCache.id] = originalArtifactCache.entry;
      originalArtifactCache = null;
    } else {
      // Clear artifact cache even if we didn't save it, to ensure clean state
      try {
        const artifactModuleId = require.resolve('@actions/artifact');
        delete require.cache[artifactModuleId];
      } catch {
        // Module might not be cached, that's fine
      }
    }
    if (originalCoreCache) {
      require.cache[originalCoreCache.id] = originalCoreCache.entry;
      originalCoreCache = null;
    }
    // Clear the source module cache to reset artifact client state
    delete require.cache[require.resolve(srcPath)];
    // Clear all action inputs to prevent test pollution
    clearActionInputs();
    resetEnv();
  });

  it('runs index.js and writes security.txt', async function () {
    const tempDir = fs.mkdtempSync(path.join(os.tmpdir(), 'securitytxt-'));
    const outputDir = path.join(tempDir, 'out');

    try {
      setActionInput('output_dir', outputDir);
      setActionInput('security_contact', 'mailto:test@example.com');
      setActionInput('security_expires', '2026-12-31T23:59:59Z');
      setActionInput('security_comments', 'false');

      delete require.cache[require.resolve(srcPath)];
      require(srcPath);

      const securityTxtPath = path.join(
        outputDir,
        '.well-known',
        'security.txt',
      );
      await waitForFile(securityTxtPath);

      const content = fs.readFileSync(securityTxtPath, 'utf8');
      assert.match(content, /Contact: mailto:test@example.com/);
      assert.match(content, /Expires: 2026-12-31T23:59:59Z/);
    } finally {
      fs.rmSync(tempDir, { recursive: true, force: true });
    }
  });

  it('prints header and footer via core.info', async function () {
    const tempDir = fs.mkdtempSync(path.join(os.tmpdir(), 'securitytxt-'));
    const outputDir = path.join(tempDir, 'logs');
    const logs = [];
    const warnings = [];

    // Mock core before loading dist file since ncc bundles dependencies
    const coreModuleId = require.resolve('@actions/core');
    originalCoreCache = {
      id: coreModuleId,
      entry: require.cache[coreModuleId],
    };

    require.cache[coreModuleId] = {
      exports: {
        info: (msg) => logs.push(msg),
        warning: (msg) => warnings.push(msg),
        setOutput: () => {},
        setFailed: (msg) => warnings.push(`failed:${msg}`),
        getInput: (name) => process.env[`INPUT_${name.toUpperCase()}`] || '',
      },
    };

    try {
      setActionInput('output_dir', outputDir);
      setActionInput('security_contact', 'mailto:log@example.com');
      setActionInput('security_expires', '2026-12-31T23:59:59Z');
      setActionInput('security_comments', 'false');
      setActionInput('upload_artifacts', 'false');

      delete require.cache[require.resolve(srcPath)];
      require(srcPath);

      const securityTxtPath = path.join(
        outputDir,
        '.well-known',
        'security.txt',
      );
      await waitForFile(securityTxtPath);

      // Give a moment for async operations to complete
      await new Promise((resolve) => setTimeout(resolve, 100));

      assert.ok(
        logs.some((line) => line.includes('Blackout Secure Security TXT Generator')),
        'header logged',
      );
      assert.ok(
        logs.some((line) => line.includes('Security.txt generation completed')),
        'footer logged',
      );
      assert.strictEqual(warnings.length, 0);
    } finally {
      fs.rmSync(tempDir, { recursive: true, force: true });
    }
  });

  it('adds canonical URL and comments when enabled', async function () {
    const tempDir = fs.mkdtempSync(path.join(os.tmpdir(), 'securitytxt-'));
    const outputDir = path.join(tempDir, 'with-comments');

    try {
      setActionInput('output_dir', outputDir);
      setActionInput('site_url', 'https://example.com');
      setActionInput('security_contact', 'contact@example.com');
      setActionInput('security_expires', '2026-12-31T23:59:59Z');
      setActionInput('security_comments', 'true');

      delete require.cache[require.resolve(srcPath)];
      require(srcPath);

      const securityTxtPath = path.join(
        outputDir,
        '.well-known',
        'security.txt',
      );
      await waitForFile(securityTxtPath);

      const content = fs.readFileSync(securityTxtPath, 'utf8');
      assert.match(
        content,
        /Canonical: https:\/\/example\.com\/\.well-known\/security\.txt/,
      );
      assert.match(content, /# security\.txt file per RFC 9116/);
      assert.match(content, /Contact: mailto:contact@example.com/);
    } finally {
      fs.rmSync(tempDir, { recursive: true, force: true });
    }
  });

  it('uploads artifact when GITHUB_ACTIONS is true', async function () {
    const tempDir = fs.mkdtempSync(path.join(os.tmpdir(), 'securitytxt-'));
    const outputDir = path.join(tempDir, 'artifact');
    const uploads = [];

    // Set environment before mocking
    process.env.GITHUB_ACTIONS = 'true';

    const artifactModuleId = require.resolve('@actions/artifact');
    originalArtifactCache = {
      id: artifactModuleId,
      entry: require.cache[artifactModuleId],
    };

    require.cache[artifactModuleId] = {
      exports: {
        DefaultArtifactClient: class {
          async uploadArtifact(name, files, root, options) {
            uploads.push({ name, files, root, options });
            return { id: 1 };
          }
        },
      },
    };

    try {
      setActionInput('output_dir', outputDir);
      setActionInput('security_contact', 'mailto:upload@example.com');
      setActionInput('security_expires', '2026-12-31T23:59:59Z');
      setActionInput('artifact_name', 'securitytxt');
      setActionInput('artifact_retention_days', '5');

      delete require.cache[require.resolve(srcPath)];
      require(srcPath);

      const securityTxtPath = path.join(
        outputDir,
        '.well-known',
        'security.txt',
      );
      await waitForFile(securityTxtPath);

      // Give a moment for async operations to complete
      await new Promise((resolve) => setTimeout(resolve, 100));

      assert.strictEqual(uploads.length, 1);
      const upload = uploads[0];
      assert.strictEqual(upload.name, 'securitytxt');
      assert.deepStrictEqual(upload.files, [securityTxtPath]);
      assert.strictEqual(upload.root, outputDir);
      assert.strictEqual(upload.options.retentionDays, 5);
    } finally {
      fs.rmSync(tempDir, { recursive: true, force: true });
    }
  });
});
