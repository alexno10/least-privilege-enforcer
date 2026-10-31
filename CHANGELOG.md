# Changelog

All notable changes to **Least-Privilege Enforcer** are documented in this file.

## [v1.0.0] - 2026-11-01

### Added
- **Comment-Preserving YAML AST Parser & Mutator (`internal/ast`):** Parses and mutates `.github/workflows/*.yml` and `*.yaml` using `gopkg.in/yaml.v3` (`yaml.Node`) while preserving existing header comments, inline comments, and structure.
- **Immutable SHA Resolver (`internal/resolver`):** Resolves mutable GitHub Action tags and branches to 40-character commit SHAs via the GitHub Git References & Tags API, with recursive dereferencing for annotated tags and in-memory caching.
- **3-Tier Permission Inference Engine (`internal/permissions`):**
  1. Upstream `action.yml` / reusable workflow fetcher and parser.
  2. Curated security heuristics knowledge base (`actions/checkout`, `github/codeql-action/upload-sarif`, `softprops/action-gh-release`, `peter-evans/create-pull-request`, `docker/login-action`, `docker/build-push-action`, `actions/cache`, etc.).
  3. Static `run:` shell command analyzer (`git push`, `gh release create`, `gh pr create`/`comment`, `gh issue`) combined via a strict `none < read < write` permission lattice.
- **Idempotent Automated Pull Request Creator (`internal/gitpr`):** Commits remediated workflows via the GitHub Git Data API and opens or updates a single `security/least-privilege-enforcer-*` Pull Request with Markdown summary tables, plus `--dry-run` unified diff support.
- **Containerized GitHub Action (`action.yml` & `Dockerfile`):** Multi-stage Alpine container image ready for GitHub Marketplace usage.
