# Security Policy

## Supported Versions

We actively support:

- Latest major version (e.g., `v1`, `v2`)
- Most recent minor/patch releases
- Critical security fixes for previous major versions

| Version | Supported           |
| ------- | ------------------- |
| 1.x     | ✅ Yes              |
| < 1.0   | ❌ No (development) |

## Reporting a Vulnerability

**Please report security vulnerabilities responsibly.**

### Preferred Method

Use [GitHub Security Advisories](https://github.com/blackoutsecure/bos-securitytxt-generator/security/advisories):

1. Click "Report a vulnerability" in the Security tab
2. Provide detailed information:
   - Affected version(s)
   - Description and impact
   - Steps to reproduce
   - Suggested fix (if available)

### Alternative Contact

If GitHub Security Advisories are unavailable, open an issue with prefix `[SECURITY]` requesting private communication.

**Do NOT disclose security issues publicly until coordinated disclosure.**

## Response Timeline

1. **Initial Response**: Within 5 business days
2. **Triage & Assessment**: Reproduce and evaluate severity
3. **Fix Development**: Create and test patch
4. **Coordinated Disclosure**: Publish fix and security advisory

We follow responsible disclosure practices and will work with you to understand and address the issue.

## Security Scope

This GitHub Action:

- Processes local repository files only
- Does not make external network calls (except GitHub Actions runtime APIs)
- Generates static text files from inputs
- Runs in isolated GitHub Actions environment

## Best Practices

For secure usage:

- 🔒 Pin to specific versions: `uses: blackoutsecure/bos-securitytxt-generator@v1.0.0`
- ✅ Review generated output before deployment
- 🚫 Avoid including sensitive data in inputs
- 📄 Use standard GitHub Actions security features

## Questions?

For security-related questions (non-vulnerabilities), open a discussion or contact us via the repository.
