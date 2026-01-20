# Blackout Secure Security TXT Generator

[![Marketplace](https://img.shields.io/badge/GitHub%20Marketplace-blue?logo=github)](https://github.com/marketplace/actions/bos-securitytxt-generator)
[![GitHub release](https://img.shields.io/github/v/release/blackoutsecure/bos-securitytxt-generator?sort=semver)](https://github.com/blackoutsecure/bos-securitytxt-generator/releases)
[![License](https://img.shields.io/badge/license-Apache%202.0-blue)](LICENSE)

Generate RFC 9116-compliant security.txt for responsible vulnerability disclosure. Automated deployment with GitHub Actions.

## Features

✅ **RFC 9116 Compliant** - Follows official security.txt standard  
✅ **Auto-Generated** - Creates properly formatted files from simple inputs  
✅ **Flexible Configuration** - Support for all RFC 9116 fields  
✅ **Zero Dependencies** - Runs in GitHub Actions with Node.js 20  
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
- **`upload_artifacts`** - Upload to GitHub artifacts (default: `true`)
- **`debug`** - Display generated security.txt content (default: `false`)

## Output

Security.txt is automatically generated at:

```
<public_dir>/.well-known/security.txt
```

Per RFC 9116, the file **must** be served at `/.well-known/security.txt` over HTTPS.

### Outputs

- **`security_path`** - Path to the generated security.txt file

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
