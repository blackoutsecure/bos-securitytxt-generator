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
          output_dir: 'public'
          site_url: 'https://example.com'
          security_contact: 'mailto:security@example.com'
          security_expires: '2026-12-31T23:59:59Z'
          security_policy: 'https://example.com/security'

      - name: Upload artifact
        uses: actions/upload-artifact@v4
        with:
          name: securitytxt
          path: public/.well-known/security.txt
```

## Configuration

See [action.yml](action.yml) for all available inputs.

### Required Inputs

- **`security_contact`** - Contact method for security reports (e.g., `mailto:security@example.com`)
- **`security_expires`** - Expiration date in ISO 8601 format (e.g., `2026-12-31T23:59:59Z`)

### Optional Inputs

- **`site_url`** - Your website URL (e.g., `https://example.com`)
- **`output_dir`** - Directory to write security.txt (default: current directory)
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
<output_dir>/.well-known/security.txt
```

Per RFC 9116, the file **must** be served at `/.well-known/security.txt` over HTTPS.

### Outputs

- **`security_path`** - Path to the generated security.txt file

## Example: Complete Configuration

```yaml
- name: Generate security.txt
  uses: blackoutsecure/bos-securitytxt-generator@v1
  with:
    output_dir: 'public'
    site_url: 'https://example.com'
    security_contact: 'mailto:security@example.com,https://example.com/report'
    security_expires: '2026-12-31T23:59:59Z'
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

Fully compliant with [RFC 9116](https://www.rfc-editor.org/rfc/rfc9116):

- ✅ Required fields: `Contact`, `Expires`
- ✅ Optional fields: `Acknowledgments`, `Canonical`, `Encryption`, `Hiring`, `Policy`, `Preferred-Languages`
- ✅ Proper UTF-8 encoding and machine-parsable format
- ✅ Serves at `/.well-known/security.txt` over HTTPS

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
