# AGENTS.md

This file provides guidance to agents when working with code in this repository.

## What this is

`bos-securitytxt-generator` is a GitHub Marketplace Action that generates a
[RFC 9116](https://www.rfc-editor.org/rfc/rfc9116) `security.txt` — the machine-readable
vulnerability-disclosure document served from `/.well-known/security.txt`. It resolves a layered
configuration, assembles the RFC 9116 directives, writes the file plus an optional legacy root
copy, then runs a 20-control deterministic audit over its own output and emits that audit as a
Markdown step summary, SARIF 2.1.0 for GitHub code scanning, a JSON report, a recommendations
sidecar, and a skipped-controls sidecar. A companion CLI, `bos-securitytxt`, shares every module.

Because the artefact is a security disclosure document, correctness means RFC 9116 conformance,
not merely a green test run. A file that parses cleanly but names an unreachable contact, carries
an expired `Expires`, or is served from the wrong path is a defect regardless of test status.

The main consumer is `blackoutsecure/bos-automation-hub`. Its reusable
`.github/workflows/deploy-cloudflare-pages.yml` pins this action by commit SHA
(`blackoutsecure/bos-securitytxt-generator@7ca9d802... # v1.2.0`) behind a `generate_security_txt`
input, sparse-checks-out `sync-files/config/securitytxt-generator-global-config.json` into
`hub-generator-config/`, and passes it as `global_config_path`. That org-tier file is the only
place rules are promoted to `fail` — the bundled baseline never does — while keeping
`audit.fail_on: never` and disabling the AI summary.

Stack: Node.js (`runs.using: node20`, `engines.node >=20`), CommonJS throughout, no TypeScript.
Runtime deps are `@actions/core ^1.11.1`, `@actions/artifact ^2.1.2`, `js-yaml ^4.3.1`. Dev tooling
is `@vercel/ncc ^0.38.1`, `eslint ^9.12.0` with `@eslint/js ^9.39.1`, `prettier ^3.3.3`,
`mocha ^10.8.2`, `nyc ^17.1.0`. Version `1.2.0`, `private: true`, Apache-2.0.

## Commands

```bash
npm install                       # `prepare` hook also runs `npm run build`
npm run build                     # ncc build src/index.js -o dist  (regenerates dist/index.js)
npm test                          # mocha; the `pretest` hook rebuilds dist first
npx mocha test/unit/audit.test.js # one test file (skips the pretest rebuild)
npm run lint:check                # eslint .          (`npm run lint` adds --fix)
npm run format:check              # prettier --check "**/*.{js,json,md}"  (`format` writes)
npm run validate                  # lint:check + format:check; also the `prebuild` hook
npm run verify                    # validate + test
npm run coverage                  # nyc npm test
npm run cli -- validate           # print the resolved config cascade
npx bos-securitytxt audit --public-dir dist --site-url https://example.com --fail-on never
```

`npm run ver`, `ver:patch|minor|major`, `ver:set`, and `release` drive `src/lib/version.js` and
`src/lib/release.js`; do not run them by hand — releases are promoted from the hub.

## Validating changes

CI is hub-driven. The only workflow here is `.github/workflows/bos-universal-gatekeeper-kicker.yml`,
a dispatch front door gated by `blackoutsecure/bos-workflow-gatekeeper`. It routes to the hub's
reusable workflows in this order: `bos-universal-gatekeeper.yml` (release, deploy, security, and
metadata stages) on push and pull request; then, on `workflow_dispatch`, `bos-universal-sync.yml`
for managed-file reconciliation, `bos-universal-action-test.yml` for action smoke tests,
`repo-metadata-sync.yml`, `bos-universal-marketplace.yml`, and `release-promote.yml`.

Locally, work narrowest-first and finish with the rebuild:

1. `npx mocha test/unit/<the-file-you-touched>.test.js`
2. `npm run lint:check && npm run format:check`
3. `npm test` (full suite; `pretest` rebuilds `dist/`)
4. `npm run build`, then commit the regenerated `dist/index.js` in the same change

The suite proves module behaviour: config precedence and validation, `security.txt` parse and
assembly, every audit rule against synthetic content, SARIF and report rendering, AI provider
selection, and the CLI surface. `test/integration/action-entry.test.js` drives `src/index.js`
directly, not the bundle, so nothing proves that `dist/` is current, that a real runner resolves
the action, that GHAS accepts the SARIF, or that the published file is reachable at
`https://<host>/.well-known/security.txt`. Check emitted content against RFC 9116 by reading it.

## Architecture

```text
action.yml                        Marketplace manifest: 29 inputs, 14 outputs, node20 -> dist/index.js
dist/index.js                     Committed ncc bundle. Build output. Never hand-edited.
src/index.js                      Action entrypoint: inputs, generation, write, audit, reporting, outputs
src/cli.js                        `bos-securitytxt` CLI: version | validate | generate | audit | sarif
src/lib/config.js                 Four-tier cascade, schema validation, ConfigError, rule defaults
src/lib/security-parser.js        buildSecurityTxt (emission) and parseSecurityTxt (audit input)
src/lib/expires.js                Expires parsing per RFC 9116 § 2.5.5: ISO 8601, `Nd`, `Nm`, `Ny`
src/lib/audit.js                  The 20 ST### controls, severity resolution, shouldFail
src/lib/findings.js               Finding/AuditResult, rule titles, RFC help links, remediations
src/lib/sarif.js                  SARIF 2.1.0 run construction, merge, load, dump
src/lib/report.js                 Log table, annotations, step summary, JSON/recommendations/skips
src/lib/ai.js                     Optional summary provider with a deterministic local fallback
src/lib/utils.js                  URL normalisation, public-dir discovery, size formatting
src/lib/metadata.js               Package identity, deliberately separate from policy config
src/lib/project-config.js         Branding, banner text, and the generated file header
src/lib/version.js                Version bump helper behind the `ver*` scripts
src/lib/release.js                Release helper behind the `release` script
src/marketplace-config.json       Bundled tier-1 baseline; `require`d so ncc inlines it
test/unit/                        Per-module suites; test/integration/ drives src/index.js
test/test-helpers.js              INPUT_* env shims and local action invocation
test/test-config.js               Shared paths and fixture constants
.mocharc.json                     spec `test/**/*.test.js`, timeout 5000, reporter spec
eslint.config.js                  Flat config, `sourceType: 'commonjs'`, ignores dist/ and coverage/
.prettierrc.yaml                  Hub-managed; singleQuote, semi, trailingComma all, printWidth 100
.github/bos-universal-config.json Repo-owned overrides: marketplace allowlist, sync services
```

Config precedence, lowest to highest: bundled `src/marketplace-config.json`; the org global config
at `global_config_path` (default `.github/blackout-secure-securitytxt-generator-global-config.yml`,
tri-state via `use_global_config`); the repository config, either `config_path` or the first hit in
`.github/bos-universal-config.json|yml|yaml`, `bos-universal-config.*`, `.bos-securitytxt.yml|yaml`,
`bos-securitytxt.yml`; then any explicitly set action input. Each tier reads the `security_txt`
section (a bare document is treated as the section). Unknown top-level keys are ignored so kits can
share one universal config; unknown keys under `audit.rules` raise `ConfigError` so a typo fails
fast instead of silently disabling a control.

Field assembly happens in `buildSecurityTxt`. `Contact` and `Expires` are hard requirements —
missing either throws. A bare email is upgraded to `mailto:`, a leading digit or `+` to `tel:`.
`Canonical` falls back to `<site_url>/.well-known/security.txt` when `site_url` is set. Emission
order is fixed: optional header comments, `Canonical`, `Contact`, `Expires`, `Encryption`,
`Acknowledgments`, `Preferred-Languages`, `Policy`, `Hiring`, each group followed by a blank line.
RFC 9116 does not mandate that order, but it is a stable part of this action's output contract.
`parseExpiresDate` defaults to `180d`, accepts `Nd`/`Nm`/`Ny` and ISO 8601, preserves an absolute
value verbatim, and warns beyond `audit.expires_max_days` (default 365). Output goes to
`<public_dir>/.well-known/<generate.filename>`, with a byte-identical copy at
`<public_dir>/<filename>` when `write_root_fallback` is on. This action does not sign anything —
`ST032 require_signature` audits for an OpenPGP signature and defaults to `skip`.

The audit then runs over the generated content: `ST001`-`ST006` required fields, `ST010`-`ST015`
field hygiene, `ST020`-`ST023` recommended fields, `ST030`-`ST032` placement, size, and signature,
`ST040` UTF-8 without a BOM. Each resolves a severity from `security_txt.audit.rules`
(`fail`/`warn`/`skip`) into a `Finding` of `pass`, `warn`, `fail`, `error`, or `skip`. No rule
defaults to `fail` in the bundled baseline. A `skip` still emits a finding so the report records
the control as deliberately unassessed; SARIF drops those, which is why `skips_json` exists.

Action contract. Generation: `public_dir` (`dist`), `site_url`, `security_contact`,
`security_expires`, `security_acknowledgments`, `security_canonical`, `security_encryption`,
`security_hiring`, `security_policy`, `security_preferred_languages`, `security_comments`,
`write_root_fallback`. Artefacts: `upload_artifacts` (`true`), `artifact_name` (`securitytxt`),
`artifact_retention_days`, `debug` (`false`). Config: `config_path`, `global_config_path`,
`use_global_config` (`auto`), `use_marketplace_config` (`true`). Audit and reporting:
`enable_audit` (`true`), `audit_fail_on`, `sarif_output`, `report_json`, `recommendations_json`,
`skips_json`, `step_summary` (`true`), `enable_ai_summary` (`true`), `ai_provider` (`auto`). Every
other input defaults to empty, meaning "inherit from the cascade". Outputs: `security_path`,
`security_root_path`, `security_expires`, `config_sources`, `audit_verdict`, the five
`audit_*_count` totals, `sarif_path`, `report_json_path`, `recommendations_json_path`,
`ai_summary`. CLI exit codes: `0` success, `1` audit failed under `fail`, `2` usage or config error.

`src/` to `dist/`. `dist/index.js` is committed build output produced solely by `npm run build`
(`ncc build src/index.js -o dist`), a single ~134k-line webpack bundle with the runtime
dependencies and `src/marketplace-config.json` inlined. It is what `action.yml` loads at
`runs.main`, so a consumer never executes `src/`. Never hand-edit it. Any `src/` change must ship a
rebuilt `dist/` in the same commit or the published action silently keeps running old code. `dist/`
is ignored by the hub-managed `common` block in `.gitignore` while `dist/index.js` is tracked, so a
rebuild shows as an ordinary modification and a genuinely new `dist/` file would need `git add -f`.
`dist` is in both `allowlist_paths` and `required_paths` of `.github/bos-universal-config.json`, so
the Marketplace promote to `main` fails without it.

## Conventions

CommonJS everywhere — `require`/`module.exports`, `sourceType: 'commonjs'`, no ESM and no `.mjs`.
Modules are flat and single-purpose: `security-parser.js` never reads config, `config.js` never
emits findings, `audit.js` does no I/O beyond a `statSync` for file size. Exported functions carry
a JSDoc block with `@param`/`@returns`; resolved config objects and rule tables are `Object.freeze`d.
Names are `camelCase` for locals, `SCREAMING_SNAKE_CASE` for module constants, `snake_case` for
config keys and action inputs, with `camel()` bridging the two. Configuration problems raise
`ConfigError` and become `core.setFailed` at the boundary; optional work — artifact upload, SARIF,
JSON report, AI summary — is wrapped so a failure becomes `core.warning` and never aborts a run.

Inputs are read once at the top of `run()` through helpers, so "unset" consistently means "inherit
from the cascade" rather than "false" or "empty":

```js
function boolInput(name, fallback) {
  const raw = (core.getInput(name) || '').trim();
  if (!raw) return fallback;
  return /^true$/i.test(raw);
}
```

To add a field or option, do all six steps in one change: declare the input in `action.yml` citing
the relevant RFC 9116 section; add the key and default to `src/lib/config.js` (schema accessor plus
the `src/marketplace-config.json` baseline, and `RULE_DEFAULTS` if it is an audit control); wire it
through `src/index.js` and `src/cli.js` and emit it in `buildSecurityTxt` at the correct position;
for a control, add its `ST###` id, title, RFC help link, and default remediation to
`src/lib/findings.js`; add unit tests under `test/unit/`; document it in `README.md` in both the
input table and the rule table; then `npm run build` and commit the rebuilt `dist/index.js`.

## Blackout Secure conventions

These apply to every repository in the `blackoutsecure` organization.

### Branch model

- `dev` is the default branch and where all work lands.
- `main` is the promoted stable runtime that consumers reference through `@main`.
- Version tags (`vX.Y.Z` and a floating `vX`) point at promoted runtime commits.
- Promotion is driven from `bos-automation-hub` (`release-promote.yml`). Do not push
  directly to `main` and do not move tags by hand.

### Centrally managed files - do not hand-edit here

`blackoutsecure/bos-automation-hub` distributes these through
`bos-managed-file-sync-action`. Change the source under the hub's `sync-files/`, never the
copy in this repository:

- `LICENSE`, `CODE_OF_CONDUCT.md`, `CONTRIBUTING.md`, `SECURITY.md`, `SUPPORT.md`
- `.github/FUNDING.yml`, `.github/PULL_REQUEST_TEMPLATE.md`, `.github/ISSUE_TEMPLATE/`
- `.github/workflows/bos-universal-gatekeeper-kicker.yml`
- the `# >>> managed-file-sync:<service> >>> ... # <<< managed-file-sync:<service> <<<`
  delimited blocks inside `.editorconfig`, `.markdownlint.yaml`, `.shellcheckrc`,
  `.yamllint.yml`, `.gitignore`, and `README.md`

`.github/bos-universal-config.json` is repo-owned. It holds this repository's overrides on
top of the hub's global config and is the right place to change gate behaviour.

### CI gate

Pushes and pull requests run the hub's reusable `bos-universal-security.yml`, reported as a
single required check. It runs markdownlint, yamllint, shellcheck, and actionlint; ESLint,
Prettier, Ruff, pytest, and Bats where the repository has them; `bos-code-scanning-kit`
(secret scan, SAST, GHAS posture) and CodeQL; dependency review; and compliance checks for
the canonical README header and a conventional-commit PR title
(`feat|fix|docs|style|refactor|perf|test|build|ci|chore|revert: subject`).

Every `uses:` reference in a workflow must be a commit SHA with a trailing version comment,
for example `actions/checkout@<sha> # v4.2.2`.

## Boundaries

### Always

- Run `npm run build` and commit the regenerated `dist/index.js` with any `src/` change.
- Read the generated `security.txt` against RFC 9116 before calling a change done; a passing suite
  is necessary, not sufficient.
- Add unit tests under `test/unit/` for every new field, option, or `ST###` control, covering the
  non-pass path.
- Keep `npm run lint:check` and `npm run format:check` clean; both gate `prebuild`.
- Keep the config cascade order intact and let an unset input mean "inherit from config".
- Keep AI and artifact upload off the critical path, degrading to a warning or local fallback.
- Update `README.md` — input table and rule table — alongside any contract change.

### Ask first

- Any change to which RFC 9116 fields are emitted, or to the order they are emitted in. Downstream
  sites diff the published file and the hub's Cloudflare Pages deploy republishes it.
- Changing `Expires` semantics: the `180d` default, the `Nd`/`Nm`/`Ny` grammar, or the
  `expires_max_days` ceiling.
- Renaming, removing, or re-defaulting an `action.yml` input or output; the hub pins this action by
  SHA and passes inputs by name.
- Renumbering or renaming an existing `ST###` rule, or raising a default severity in
  `src/marketplace-config.json`, which changes behaviour for every consumer.
- Adding a runtime dependency, a new network call, or a new output file.
- Changing the `.well-known/` output path or the `write_root_fallback` behaviour.

### Never

- Never hand-edit `dist/index.js`; it is build output and the next `npm run build` discards it.
- Never commit real private keys, PGP secret material, tokens, or genuine security contact details
  in fixtures, tests, config, or docs — use `example.com` addresses.
- Never hand-edit centrally managed files or the `managed-file-sync` marker blocks listed above.
- Never use an unpinned `uses:` ref; every reference is a 40-character commit SHA with a trailing
  version comment.
- Never push directly to `main` or move a version tag by hand; promotion runs from the hub.
- Never lower an audit severity, add an ESLint disable, or set `audit_fail_on: never` merely to get
  a green run, and never let a `skip` finding be reported or treated as a `pass`.
