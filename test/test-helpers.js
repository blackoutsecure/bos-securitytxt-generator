const fs = require('fs');
const path = require('path');

/**
 * Set GitHub Actions input environment variable
 */
function setActionInput(key, value) {
  const envName = `INPUT_${key.replace(/[^A-Za-z0-9_]/g, '_').toUpperCase()}`;
  process.env[envName] = String(value);
}

/**
 * Clear all GitHub Actions input environment variables
 */
function clearActionInputs() {
  Object.keys(process.env).forEach((key) => {
    if (key.startsWith('INPUT_')) {
      delete process.env[key];
    }
  });
}

/**
 * Load event.json and set up environment for local action execution
 */
function setupActionEnvironment(eventJsonPath) {
  if (!fs.existsSync(eventJsonPath)) {
    throw new Error(`event.json not found at ${eventJsonPath}`);
  }

  const raw = fs.readFileSync(eventJsonPath, 'utf8');
  let parsed;

  try {
    parsed = JSON.parse(raw);
  } catch (e) {
    throw new Error(`Failed to parse event.json: ${e.message}`);
  }

  const inputs = (parsed && parsed.inputs) || {};

  Object.entries(inputs).forEach(([k, v]) => setActionInput(k, v));

  // Sensible defaults for security.txt generation
  if (!inputs.security_contact)
    setActionInput('security_contact', 'security@example.com');
  if (!inputs.security_expires)
    setActionInput('security_expires', '2026-12-31T23:59:59Z');
  if (!inputs.public_dir) setActionInput('public_dir', '.well-known');
  if (!inputs.upload_artifacts) setActionInput('upload_artifacts', 'true');
  if (!inputs.artifact_name) setActionInput('artifact_name', 'securitytxt');
  if (!inputs.artifact_retention_days)
    setActionInput('artifact_retention_days', '30');

  return inputs;
}

/**
 * Run the GitHub Action locally (uses bundled dist/index.js)
 */
function runActionLocally(distPath = 'dist/index.js') {
  const fullPath = path.resolve(distPath);
  if (!fs.existsSync(fullPath)) {
    throw new Error(
      `Action entry point not found: ${fullPath}. Run 'npm run build' first.`,
    );
  }

  delete require.cache[require.resolve(fullPath)];
  require(fullPath);
}

module.exports = {
  setActionInput,
  clearActionInputs,
  setupActionEnvironment,
  runActionLocally,
};
