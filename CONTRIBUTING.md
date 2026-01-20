# Contributing

Thank you for considering a contribution!

## Workflow

1. Fork and create a branch: `git checkout -b feat/your-feature`
2. Install: `npm install`
3. Make changes
4. Build: `npm run build`
5. Test and lint:
   ```bash
   npm test
   npm run lint
   npm run format
   ```
6. Commit using conventional style (e.g., `feat: ...`, `fix: ...`)
7. Push and open a PR

## Testing

- Unit tests: `test/unit/`
- Run all: `npm test`
- Coverage: `npm run coverage`

## Adding an Input

1. Update `action.yml`
2. Implement in `src/index.js`
3. Add tests
4. Update README
5. Build: `npm run build`

## Code Style

- ESLint + Prettier (auto-enforced)
- Run `npm run lint` and `npm run format`

## Security

See [SECURITY.md](SECURITY.md) for reporting vulnerabilities.

## Need Help?

Open an issue or draft PR for discussion.
