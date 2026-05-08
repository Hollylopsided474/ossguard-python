# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- Docker image published to `ghcr.io/kirankotari/ossguard` on every push
- Standalone binary builds (macOS, Linux, Windows) via PyInstaller on release
- Homebrew tap: `brew install kirankotari/tap/ossguard`
- PyPI and Docker badges in README
- Comprehensive installation section in README (PyPI, pipx, binaries, Homebrew, Docker)
- Issue templates (bug report, feature request) and PR template
- CODEOWNERS file for review routing
- GitHub repo metadata (description, topics, homepage)

### Security

- Pin all GitHub Actions to commit SHAs across all 8 workflows (Scorecard PinnedDependencies)
- Pin Docker base image to digest in Dockerfile
- Set `permissions: read-all` at workflow top level (Scorecard Token-Permissions)
- Job-level least-privilege permissions for write operations

### Fixed

- Bump all GitHub Actions to Node.js 24 compatible versions (checkout v6, setup-python v6, upload-artifact v7, download-artifact v8)
- Fix `ossf/scorecard-action@v2` (non-existent tag) to `@v2.4.0`
- Apply `ruff format` to all source files
- Fix all 47 ruff lint errors (unused imports, ambiguous variable names)

## [0.1.0] - 2026-05-07

### Added

- **Core commands**: `init`, `scan`, `version`
- **Dependency analysis**: `deps`, `drift`, `watch`, `tpn`
- **Security analysis**: `reach`, `audit`, `secrets`
- **Remediation**: `fix`, `update`
- **Compliance**: `baseline`, `badge`, `license`, `policy`
- **Supply chain**: `slsa`, `supply-chain`, `pin`, `maturity`
- **Generation**: `insights`, `sbom-gen`, `ci`, `report`
- **Container security**: `container`
- **Utilities**: `compare`, `fuzz`
- Project detection for Python, JavaScript, Go, Rust, Java, C/C++
- OSV and deps.dev API integrations
- Rich CLI output with tables, panels, and color
- JSON output mode for all analysis commands
- 147 unit tests with full coverage of analyzers
- OpenSSF repository standards: LICENSE, CONTRIBUTING.md, CODE_OF_CONDUCT.md, CHANGELOG.md
- CI workflow with Python version matrix, ruff linting, and pytest
- Release workflow for PyPI with trusted publishing
- Scorecard, CodeQL, SBOM, and Sigstore workflows
