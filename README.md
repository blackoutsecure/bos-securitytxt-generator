# Blackout Secure Security TXT Generator

[![Marketplace](https://img.shields.io/badge/GitHub%20Marketplace-blue?logo=github)](https://github.com/marketplace/actions/bos-securitytxt-generator)
[![GitHub release](https://img.shields.io/github/v/release/blackoutsecure/bos-securitytxt-generator?sort=semver)](https://github.com/blackoutsecure/bos-securitytxt-generator/releases)
[![License](https://img.shields.io/badge/license-Apache%202.0-blue)](LICENSE)

Generate RFC 9116-compliant security.txt for responsible vulnerability disclosure. Automated deployment with GitHub Actions.

## Features

✅ **RFC 9116 Compliant** - Follows official security.txt standard  
✅ **Auto-Generated** - Creates properly formatted files from simple inputs  
✅ **Flexible Configuration** - Support for all RFC 9116 fields  
✅ **Layered Configuration** - Bundled marketplace baseline → org global config → repo config → action inputs  
✅ **Compliance Audit** - 20 evidence-based controls with per-rule `fail`/`warn`/`skip` severities  
✅ **Enterprise Reporting** - Markdown step summary, SARIF 2.1.0 for code scanning, JSON report, recommendations sidecar  
✅ **AI Findings Summary** - Optional GitHub Models summary with a deterministic local fallback  
✅ **Local CLI** - `bos-securitytxt validate|generate|audit|sarif` reproduces CI output on your machine  
✅ **Artifact Upload** - Optional automatic artifact storage

## Quick Start

Add this to your GitHub Actions workflow:

```yaml
name: Generate Security.txt
on:
  push:
    branches: [main]
  workflow_dispatch:

jobs:
  generate:
    runs-on: ubuntu-latest
    steps:
      - name: Checkout
        uses: actions/checkout@v4

      - name: Generate security.txt
        uses: blackoutsecure/bos-securitytxt-generator@v1
        with:
          security_contact: 'security@example.com'
```

## Configuration

See [action.yml](action.yml) for all available inputs.

### Required Inputs

- **`security_contact`** - Contact method(s) for security vulnerability reports. **Required per [RFC 9116 § 2.5.3](https://www.rfc-editor.org/rfc/rfc9116#section-2.5.3)**. Must be a URI using `mailto:`, `https://`, or `tel:` scheme. Emails are auto-converted to `mailto:` URIs. Comma-separated for multiple contacts.
  - Examples:
    - `security@example.com` (auto-converted to `mailto:security@example.com`)
    - `https://example.com/security`
    - `security@example.com,https://example.com/report`

### Optional Inputs

- **`security_expires`** - Expiration date for security.txt validity. [RFC 9116 § 2.5.5](https://www.rfc-editor.org/rfc/rfc9116#section-2.5.5) recommends < 1 year (365 days).
  - **Default:** `180d` (6 months)
  - **Formats supported:**
    - ISO 8601 timestamp: `2026-12-31T23:59:59Z`
    - Days: `30d`, `180d`, `365d`
    - Months: `6m`, `12m`
    - Years: `1y`
  - ⚠️ Values > 365 days trigger RFC compliance warning

- **`site_url`** - Your website URL (e.g., `https://example.com`). Optional but recommended for canonical URI generation.
- **`public_dir`** - Directory to write security.txt. **Default:** `dist`
- **`security_policy`** - Link to vulnerability disclosure policy
- **`security_acknowledgments`** - Link to security researchers hall of fame
- **`security_encryption`** - OpenPGP encryption key URL
- **`security_hiring`** - Link to security job postings
- **`security_preferred_languages`** - Preferred report languages (e.g., `en, es, fr`)
- **`security_comments`** - Include RFC 9116 comments in output (default: `true`)
- **`write_root_fallback`** - Also write a legacy copy at `<public_dir>/security.txt` (default: `false`)
- **`upload_artifacts`** - Upload to GitHub artifacts (default: `true`)
- **`debug`** - Display generated security.txt content (default: `false`)

### Configuration, Audit & Reporting Inputs

| Input                    | Description                                                | Default                                                           |
| ------------------------ | ---------------------------------------------------------- | ----------------------------------------------------------------- |
| `config_path`            | Explicit repository config file                            | auto-discover                                                     |
| `global_config_path`     | Organization-level global config                           | `.github/blackout-secure-securitytxt-generator-global-config.yml` |
| `use_global_config`      | Global tier: `auto`, `true` (require), `false` (disable)   | `auto`                                                            |
| `use_marketplace_config` | Apply the bundled marketplace baseline                     | `true`                                                            |
| `enable_audit`           | Run the RFC 9116 compliance audit                          | `true`                                                            |
| `audit_fail_on`          | `fail` or `never`; empty uses `security_txt.audit.fail_on` | from config                                                       |
| `sarif_output`           | Write SARIF 2.1.0 for GitHub code scanning                 | disabled                                                          |
| `report_json`            | Write the machine-readable JSON audit report               | disabled                                                          |
| `recommendations_json`   | Write structured remediation recommendations               | disabled                                                          |
| `skips_json`             | Write the skipped-controls sidecar                         | disabled                                                          |
| `step_summary`           | Append the Markdown report to `$GITHUB_STEP_SUMMARY`       | `true`                                                            |
| `enable_ai_summary`      | Generate a natural-language findings summary               | `true`                                                            |
| `ai_provider`            | `auto`, `none`, or a named provider                        | `auto`                                                            |

## 🗂️ Layered Configuration

Configuration is deep-merged, then validated. Precedence, lowest to highest:

1. **Bundled marketplace baseline** — `src/marketplace-config.json`, shipped with the action
2. **Organization global config** — `.github/blackout-secure-securitytxt-generator-global-config.yml`
3. **Repository config** — first match of `.github/bos-universal-config.json|yml|yaml`, `bos-universal-config.*`, or `.bos-securitytxt.yml|yaml`
4. **Action inputs** — any input you explicitly set wins over every config tier

Unknown top-level keys are ignored so the same `bos-universal-config.json` can be shared
with other Blackout Secure kits. Unknown keys **inside** `security_txt.audit.rules` are
rejected, so a typo in a rule name fails fast instead of silently disabling a control.

```yaml
# .github/bos-universal-config.json (YAML shown for readability)
security_txt:
  owner: blackoutsecure
  project_name: example-site

  generate:
    include_comments: true
    filename: security.txt
    write_root_fallback: false

  fields:
    expires: 180d
    contact:
      - mailto:security@example.com
      - https://example.com/report
    policy:
      - https://example.com/security-policy
    encryption:
      - https://example.com/pgp-key.txt
    preferred_languages: 'en, es'

  audit:
    enable: true
    fail_on: fail # or `never` to keep the audit advisory
    max_size_kb: 32
    expires_max_days: 365
    rules:
      require_contact: fail
      require_canonical: fail
      recommend_encryption: warn

  reporting:
    step_summary: true
    sarif: true
    json_report: true
    recommendations: true

  remediation:
    enable_ai_findings_summary: true
    ai_findings_summary_provider: auto
    local_heuristic_fallback: true
```

Because `fields.contact` can come from config, `security_contact` is no longer a hard
action-level requirement — supply it through either surface.

## 🛡️ RFC 9116 Compliance Audit

Every control is evidence-based and configurable through `security_txt.audit.rules.<name>`.
A rule set to `skip` still emits a finding, so the report records that the control was
deliberately not assessed.

| Rule    | Config key                   | Checks                                                    | Default |
| ------- | ---------------------------- | --------------------------------------------------------- | ------- |
| `ST001` | `require_contact`            | At least one Contact directive (§ 2.5.3)                  | `warn`  |
| `ST002` | `require_expires`            | An Expires directive is present (§ 2.5.5)                 | `warn`  |
| `ST003` | `expires_not_expired`        | Expires is still in the future                            | `warn`  |
| `ST004` | `expires_within_max_days`    | Expires is within `audit.expires_max_days`                | `warn`  |
| `ST005` | `require_canonical`          | A Canonical directive is present (§ 2.5.2)                | `warn`  |
| `ST006` | `canonical_matches_site_url` | Canonical points at `<site_url>/.well-known/security.txt` | `warn`  |
| `ST010` | `require_https_uris`         | No directive value uses insecure `http://`                | `warn`  |
| `ST011` | `valid_contact_uri`          | Contacts use `mailto:`, `https://`, or `tel:`             | `warn`  |
| `ST012` | `require_multiple_contacts`  | More than one contact channel is published                | `skip`  |
| `ST013` | `valid_preferred_languages`  | Preferred-Languages uses RFC 5646 tags (§ 2.5.8)          | `warn`  |
| `ST014` | `single_valued_fields`       | Expires/Preferred-Languages appear at most once (§ 2.4)   | `warn`  |
| `ST015` | `forbid_unknown_fields`      | No unregistered directives or malformed lines             | `warn`  |
| `ST020` | `recommend_encryption`       | An Encryption key is published (§ 2.5.4)                  | `skip`  |
| `ST021` | `recommend_policy`           | A disclosure Policy is published (§ 2.5.7)                | `warn`  |
| `ST022` | `recommend_acknowledgments`  | An Acknowledgments page is published (§ 2.5.1)            | `skip`  |
| `ST023` | `recommend_hiring`           | A security Hiring page is published (§ 2.5.6)             | `skip`  |
| `ST030` | `well_known_location`        | File is written to `/.well-known/security.txt` (§ 3)      | `warn`  |
| `ST031` | `file_size_limit`            | File stays within `audit.max_size_kb`                     | `warn`  |
| `ST032` | `require_signature`          | Inline or detached OpenPGP signature (§ 2.3)              | `skip`  |
| `ST040` | `require_utf8_no_bom`        | UTF-8 encoded without a byte-order mark (§ 2.1)           | `warn`  |

No rule defaults to `fail`, so adopting the audit never breaks an existing pipeline on
day one. Opt individual rules up to `fail` once your file is clean.

### Reporting example

```yaml
- name: Generate and audit security.txt
  id: securitytxt
  uses: blackoutsecure/bos-securitytxt-generator@v1
  with:
    site_url: 'https://example.com'
    public_dir: 'dist'
    security_contact: 'security@example.com'
    sarif_output: 'securitytxt-audit.sarif'
    report_json: 'securitytxt-audit.json'
    recommendations_json: 'securitytxt-recommendations.json'
    audit_fail_on: 'fail'

- name: Upload audit findings to code scanning
  uses: github/codeql-action/upload-sarif@v3
  with:
    sarif_file: securitytxt-audit.sarif

- run: echo "Verdict: ${{ steps.securitytxt.outputs.audit_verdict }}"
```

`skip` findings are intentionally omitted from SARIF — they would clutter the Security
tab with controls that were never assessed. Use `skips_json` when you need that record.

## 🤖 AI Findings Summary

When `enable_ai_summary` is on, the action asks a model for a three-bullet triage summary
of the non-passing findings and appends it to the step summary and JSON report.

- `ai_provider: auto` (default) uses **GitHub Models** whenever `GITHUB_MODELS_TOKEN` or
  `GITHUB_TOKEN` is exposed to the job. Grant `models: read` in the job permissions.
- `ai_provider: none` disables the model call.
- Any other name uses `<NAME>_API_KEY` plus `<NAME>_API_ENDPOINT` from the environment.

AI is never on the critical path: any missing credential, authorization failure, timeout,
or transport error falls back to a deterministic local summary, and the run continues.

## 🖥️ Local CLI

The CLI shares every module with the Action, so a local dry-run produces the same report
as CI — including auditing a `security.txt` this action did not generate.

```bash
npm install

# Resolve and print the merged configuration cascade
npx bos-securitytxt validate

# Write security.txt from the resolved configuration
npx bos-securitytxt generate \
  --public-dir dist \
  --site-url https://example.com \
  --contact mailto:security@example.com

# Audit any existing security.txt and write every report artefact
npx bos-securitytxt audit \
  --public-dir dist \
  --site-url https://example.com \
  --sarif securitytxt-audit.sarif \
  --json securitytxt-audit.json \
  --recommendations securitytxt-recommendations.json \
  --fail-on never

# Merge SARIF logs before a single code-scanning upload
npx bos-securitytxt sarif --input a.sarif --input b.sarif --output merged.sarif
```

Exit codes: `0` success, `1` audit failed under the `fail` policy, `2` usage or
configuration error.

## Output

Security.txt is automatically generated at:

```
<public_dir>/.well-known/security.txt
```

Per RFC 9116, the file **must** be served at `/.well-known/security.txt` over HTTPS.

### Outputs

| Output                      | Description                                                                        |
| --------------------------- | ---------------------------------------------------------------------------------- |
| `security_path`             | Path to the generated security.txt                                                 |
| `security_root_path`        | Path to the legacy root copy, when `write_root_fallback` is enabled                |
| `security_expires`          | Resolved `Expires` value written to the file                                       |
| `config_sources`            | Applied config tiers, in precedence order                                          |
| `audit_verdict`             | `Pass`, `Review recommended`, `Action required`, `Inconclusive`, or `Not assessed` |
| `audit_pass_count`          | Controls that passed                                                               |
| `audit_warn_count`          | Controls that warned                                                               |
| `audit_fail_count`          | Controls that failed                                                               |
| `audit_error_count`         | Controls that could not be evaluated                                               |
| `audit_skip_count`          | Controls that were not assessed                                                    |
| `sarif_path`                | Written SARIF file, when `sarif_output` is set                                     |
| `report_json_path`          | Written JSON report, when `report_json` is set                                     |
| `recommendations_json_path` | Written recommendations sidecar, when `recommendations_json` is set                |
| `ai_summary`                | Short natural-language summary of the audit findings                               |

## Example: Complete Configuration

```yaml
- name: Generate security.txt
  uses: blackoutsecure/bos-securitytxt-generator@v1
  with:
    public_dir: 'public'
    site_url: 'https://example.com'
    security_contact: 'security@example.com,https://example.com/report'
    security_expires: '6m' # 6 months (or use 180d, 2026-12-31T23:59:59Z, etc.)
    security_policy: 'https://example.com/security'
    security_acknowledgments: 'https://example.com/hall-of-fame'
    security_encryption: 'https://example.com/security-key.asc'
    security_hiring: 'https://example.com/careers/security'
    security_preferred_languages: 'en, es, fr'
    security_comments: true
    upload_artifacts: true
    artifact_name: 'securitytxt'
```

## RFC 9116 Compliance

Fully compliant with [RFC 9116](https://www.rfc-editor.org/rfc/rfc9116) ([securitytxt.org](https://securitytxt.org/)):

- ✅ **Required fields:** `Contact` (§ 2.5.3), `Expires` (§ 2.5.5)
- ✅ **Optional fields:** `Acknowledgments`, `Canonical`, `Encryption`, `Hiring`, `Policy`, `Preferred-Languages`
- ✅ **Contact validation:** Must be URI (`mailto:`, `https://`, `tel:`) per § 2.5.3
- ✅ **Expires recommendation:** < 1 year (365 days) per § 2.5.5
- ✅ Proper UTF-8 encoding and machine-parsable format
- ✅ Serves at `/.well-known/security.txt` over HTTPS

### Contact Field Requirements

Per [RFC 9116 § 2.5.3](https://www.rfc-editor.org/rfc/rfc9116#section-2.5.3), the Contact field:

- **MUST** appear at least once (required)
- **MUST** be a valid URI (e.g., `mailto:`, `https://`, `tel:`)
- **MAY** appear multiple times for different contact methods
- Web URIs (`https://`) are preferred over email for spam prevention

This action automatically converts email addresses to `mailto:` URIs for RFC compliance.

## Contributing

Contributions welcome! See [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines.

## Support

- 📚 [Documentation](https://github.com/blackoutsecure/bos-securitytxt-generator#readme)
- 🐛 [Report Issues](https://github.com/blackoutsecure/bos-securitytxt-generator/issues)
- 🔒 [Security Policy](SECURITY.md)

## License

Apache License 2.0 - See [LICENSE](LICENSE) for details.

---

**Copyright © 2025-2026 Blackout Secure**  
Website: [blackoutsecure.app](https://blackoutsecure.app)

<!-- >>> managed-file-sync:security_readme_pointer >>> -->
## Security & secrets

This repository is built with Blackout Secure's reusable GitHub Actions
workflows. If you fork or self-host these workflows and need to provision
your own credentials (GitHub App vs. PAT guidance, secret tiers, Docker
Hub/Cloudflare/Balena setup walkthroughs), see the
["Secrets pipelining strategy"](https://github.com/blackoutsecure/bos-automation-hub#secrets-pipelining-strategy)
section of `bos-automation-hub`. To report a vulnerability, see
[SECURITY.md](https://github.com/blackoutsecure/.github/blob/main/SECURITY.md).
<!-- <<< managed-file-sync:security_readme_pointer <<< -->
