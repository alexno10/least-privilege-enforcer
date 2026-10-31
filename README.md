# 🛡️ Least-Privilege Enforcer

[![CI](https://github.com/alexno10/least-privilege-enforcer/actions/workflows/ci.yml/badge.svg)](https://github.com/alexno10/least-privilege-enforcer/actions/workflows/ci.yml)
[![Release](https://img.shields.io/github/v/release/alexno10/least-privilege-enforcer)](https://github.com/alexno10/least-privilege-enforcer/releases)
[![Go Version](https://img.shields.io/badge/Go-1.22%2B-00ADD8?logo=go)](https://go.dev/)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)

**Least-Privilege Enforcer** is a Go CLI tool and containerized GitHub Action that automatically hardens `.github/workflows/*.yml` (and `.yaml`) files against two critical CI/CD supply-chain vulnerabilities:

1. **Over-Privileged `GITHUB_TOKEN` Permissions:** Locks down top-level workflow permissions (`permissions: {}`) and injects calculated minimum-required `permissions:` blocks at the individual job level (`jobs.<job_id>.permissions`).
2. **Mutable Action References (Tag Hijacking):** Resolves mutable tags and branches (e.g., `actions/checkout@v4` or `@main`) to immutable 40-character Git Commit SHAs while preserving the human-readable version tag as an inline YAML comment (`# v4`).

Built on `gopkg.in/yaml.v3`'s `yaml.Node` Abstract Syntax Tree (AST), **Least-Privilege Enforcer** mutates workflows in-place while preserving existing header comments, inline comments, and structure.

---

## ✨ Key Features

- **Comment-Preserving YAML AST Mutation (`internal/ast`):** Uses `yaml.Node` manipulation rather than struct unmarshaling so your workflow comments remain intact.
- **Annotated & Lightweight Tag Dereferencing (`internal/resolver`):** Queries the GitHub Git References & Tags API, recursively dereferencing annotated `tag` objects until the underlying 40-character `commit` SHA is reached, backed by an in-memory cache.
- **3-Tier Permission Inference Engine (`internal/permissions`):**
  1. **Upstream `action.yml` / Reusable Workflow Inspection:** Fetches upstream metadata at the resolved commit SHA to extract declared or annotated token scopes.
  2. **Curated Security Heuristics:** Built-in mappings for common ecosystem actions (`actions/checkout`, `github/codeql-action/upload-sarif`, `softprops/action-gh-release`, `peter-evans/create-pull-request`, `docker/login-action`, `docker/build-push-action`, `actions/cache`, etc.).
  3. **Static Shell (`run:`) Analyzer:** Scans shell scripts for privileged operations (`git push`, `gh release create`, `gh pr create`, `gh pr comment`, `gh issue`, etc.) and merges scopes across all steps in a job using a strict lattice (`none < read < write`), defaulting to `contents: read`.
- **Idempotent Automated Pull Requests (`internal/gitpr`):** Commits remediated workflows via the GitHub Git Data API and opens (or updates an existing `security/least-privilege-enforcer-*`) Pull Request with Markdown summary tables of all pinned SHAs and calculated job permissions.

---

## 🚀 Usage as a GitHub Action

Add `.github/workflows/least-privilege-enforcer.yml` to your repository:

```yaml
name: Least-Privilege Enforcer

on:
  schedule:
    - cron: "0 6 * * 1" # Weekly on Mondays at 06:00 UTC
  workflow_dispatch:

permissions: {}

jobs:
  enforce:
    runs-on: ubuntu-latest
    permissions:
      contents: write
      pull-requests: write
    steps:
      - name: Checkout repository
        uses: actions/checkout@11bd71901bbe5b1630ceea73d27597364c9af683 # v4.2.2

      - name: Run Least-Privilege Enforcer
        uses: alexno10/least-privilege-enforcer@75aecd6edf2b9fb19c7285a814a8f4713ab38da9 # v1.0.0
        with:
          github_token: ${{ secrets.GITHUB_TOKEN }}
          workflows_dir: ".github/workflows"
          repo: ${{ github.repository }}
          dry_run: "false"
          force: "false"
```

> **Repository Settings Note:** Ensure **Settings → Actions → General → Workflow permissions → "Allow GitHub Actions to create and approve pull requests"** is enabled so `GITHUB_TOKEN` is permitted to open remediation PRs.

### Action Inputs

| Input | Description | Required | Default |
| :--- | :--- | :---: | :--- |
| `github_token` | GitHub token (`GITHUB_TOKEN` or PAT) with `contents: write` and `pull-requests: write`. | Yes | `${{ github.token }}` |
| `workflows_dir` | Directory containing workflow `.yml` / `.yaml` files. | No | `.github/workflows` |
| `repo` | Target repository in `owner/repo` format. | No | `${{ github.repository }}` |
| `dry_run` | Print unified diffs to stdout without mutating files or creating a PR. | No | `"false"` |
| `force` | Recalculate and overwrite existing job-level `permissions:` blocks even if not `write-all`. | No | `"false"` |

### Action Outputs

| Output | Description |
| :--- | :--- |
| `pr-number` | Pull Request number created or updated. |
| `pr-url` | HTML URL of the created or updated Pull Request. |
| `branch` | Head branch name pushed by the enforcer. |
| `modified-workflows` | Count of remediated workflow files. |

---

## 💻 Local CLI Usage

### Build & Test

```bash
go test -v ./...
go build -o least-privilege-enforcer ./cmd/enforcer
```

### Run in Dry-Run Mode (Unified Diff Only)

```bash
./least-privilege-enforcer \
  --workflows-dir .github/workflows \
  --github-token "$GITHUB_TOKEN" \
  --dry-run
```

### Run and Open an Automated Remediation PR

```bash
./least-privilege-enforcer \
  --workflows-dir .github/workflows \
  --github-token "$GITHUB_TOKEN" \
  --repo owner/repo
```

---

## 🔍 Example Remediation (Before vs. After)

**Before (`.github/workflows/vulnerable.yml`):**
```yaml
# Supply-Chain Vulnerable CI Workflow
name: Vulnerable CI & Release Pipeline
on: [push]

permissions: write-all

jobs:
  release:
    runs-on: ubuntu-latest
    permissions: write-all
    steps:
      - name: Checkout main branch
        uses: actions/checkout@v4.1.1
      - name: Publish GitHub Release
        uses: softprops/action-gh-release@v2.0.5
      - name: Notify pull request
        run: gh pr comment 42 --body "Release completed"
```

**After:**
```yaml
# Supply-Chain Vulnerable CI Workflow
name: Vulnerable CI & Release Pipeline
on: [push]

permissions: {}

jobs:
  release:
    runs-on: ubuntu-latest
    permissions:
      contents: write
      pull-requests: write
    steps:
      - name: Checkout main branch
        uses: actions/checkout@b4ffde65f46336ab88eb53be808477a3936bae11 # v4.1.1
      - name: Publish GitHub Release
        uses: softprops/action-gh-release@3333333333333333333333333333333333333333 # v2.0.5
      - name: Notify pull request
        run: gh pr comment 42 --body "Release completed"
```

---

## 📄 License

Released under the [MIT License](LICENSE).
