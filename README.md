# Blackout Secure Security TXT Generator

**Copyright © 2025 Blackout Secure | Apache License 2.0**

[![Marketplace](https://img.shields.io/badge/GitHub%20Marketplace-blue?logo=github)](https://github.com/marketplace/actions/robots-txt-generator)
[![GitHub release](https://img.shields.io/github/v/release/blackoutsecure/bos-securitytxt-generator?sort=semver)](https://github.com/blackoutsecure/bos-securitytxt-generator/releases)
[![License](https://img.shields.io/badge/license-Apache%202.0-blue)](LICENSE)

Automated **security.txt** generation per [RFC 9116](https://www.rfc-editor.org/rfc/rfc9116) for vulnerability disclosure and responsible security practices.

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

This action generates security.txt files fully compliant with [RFC 9116](https://www.rfc-editor.org/rfc/rfc9116) including:

- ✅ Machine-parsable format with strict syntax
- ✅ Required fields: `Contact`, `Expires`
- ✅ Optional fields: `Acknowledgments`, `Canonical`, `Encryption`, `Hiring`, `Policy`, `Preferred-Languages`
- ✅ Proper encoding (UTF-8)
- ✅ Served at `/.well-known/security.txt` over HTTPS
- ✅ Optional RFC reference comments

## Local Development

```bash
npm install
npm run build
npm test
npm run coverage
```

### Scripts

| Command              | Purpose                  |
| -------------------- | ------------------------ |
| `npm run build`      | Build action bundle      |
| `npm test`           | Run tests                |
| `npm run test:watch` | Watch mode               |
| `npm run coverage`   | Generate coverage report |
| `npm run lint`       | Lint code                |
| `npm run format`     | Format files             |

## Contributing

Contributions are welcome! Please:

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Run tests: `npm test`
5. Submit a pull request

## License

Apache License 2.0 - See [LICENSE](LICENSE) for details.
