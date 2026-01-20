# Contributing to Blackout Secure Security TXT Generator

Thank you for your interest in contributing! We welcome bug fixes, feature enhancements, and documentation improvements.

## Getting Started

1. **Fork** the repository
2. **Clone** your fork: `git clone https://github.com/YOUR_USERNAME/bos-securitytxt-generator.git`
3. **Install** dependencies: `npm install`
4. **Create** a branch: `git checkout -b feat/your-feature`

## Development Workflow

```bash
# Make your changes
npm run build        # Build the action
npm test             # Run tests
npm run lint         # Check code style
npm run format       # Format code
```

## Commit Guidelines

Use [Conventional Commits](https://www.conventionalcommits.org/):

- `feat:` New features
- `fix:` Bug fixes
- `docs:` Documentation changes
- `test:` Test updates
- `chore:` Maintenance tasks

Example: `feat: add support for multiple encryption keys`

## Pull Request Process

1. Ensure all tests pass: `npm test`
2. Update documentation if needed
3. Build the action: `npm run build`
4. Commit the built `dist/` files
5. Push and open a pull request
6. Describe your changes clearly

## Testing

- **Unit tests**: `test/unit/`
- **Integration tests**: `test/integration/`
- **Coverage**: `npm run coverage`

Add tests for new features and ensure existing tests pass.

## Code Style

We use ESLint and Prettier (auto-enforced). Run:

```bash
npm run lint      # Check for issues
npm run format    # Auto-fix formatting
```

## Adding New Features

When adding a new input parameter:

1. Update `action.yml` with the new input definition
2. Implement the feature in `src/index.js` or relevant module
3. Add comprehensive tests in `test/`
4. Update `README.md` documentation
5. Build and commit: `npm run build`

## Reporting Issues

Before opening an issue:

- Search existing issues to avoid duplicates
- Provide clear reproduction steps
- Include action version and relevant logs
- Use issue templates when available

## Security

See [SECURITY.md](SECURITY.md) for reporting vulnerabilities.

## Need Help?

Open an issue or start a discussion for questions and ideas.
