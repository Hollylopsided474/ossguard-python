# OSSGuard — Python Implementation

**The reference Python implementation of [OSSGuard](https://github.com/kirankotari/ossguard).**

[![CI](https://github.com/kirankotari/ossguard-python/actions/workflows/ci.yml/badge.svg)](https://github.com/kirankotari/ossguard-python/actions/workflows/ci.yml)
[![PyPI](https://img.shields.io/pypi/v/ossguard)](https://pypi.org/project/ossguard/)
[![License: Apache-2.0](https://img.shields.io/badge/License-Apache_2.0-blue.svg)](LICENSE)
[![Python 3.9+](https://img.shields.io/badge/python-3.9%2B-blue.svg)](https://www.python.org/downloads/)

> For full documentation, all install methods, and command examples, see the main [ossguard](https://github.com/kirankotari/ossguard) repo.

## Install

```bash
pip install ossguard

# Or with pipx (isolated install)
pipx install ossguard
```

## Quick Start

```bash
ossguard scan .       # Quick security posture check
ossguard audit .      # Full security audit
ossguard init .       # Bootstrap all OpenSSF configs
ossguard baseline .   # OSPS Baseline compliance
```

## Features

This is the **reference implementation** with the richest UI (Rich tables, colored panels, interactive prompts).

- **27 commands** covering the full OpenSSF security lifecycle
- **Rich terminal UI** with tables, panels, and progress indicators
- **Auto-detection** of languages, package managers, and frameworks
- **Python 3.9+** with dependencies: typer, rich, pyyaml, jinja2, questionary, httpx

For the complete command reference and real-world output examples, see the main [ossguard](https://github.com/kirankotari/ossguard) README.

## Other Implementations

| Implementation | Install | Best for |
|---------------|---------|----------|
| **[ossguard-go](https://github.com/kirankotari/ossguard-go)** | `brew install kirankotari/tap/ossguard` | CI pipelines, single binary |
| **[ossguard-npm](https://github.com/kirankotari/ossguard-npm)** | `npx ossguard` | Node.js projects |

## Development

```bash
# Clone and install
git clone https://github.com/kirankotari/ossguard-python.git
cd ossguard-python
pip install -e ".[dev]"

# Run tests (147 tests)
pytest

# Lint
ruff check src/ tests/
```

## Contributing

Contributions are welcome! Please see [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines.

## License

Apache-2.0 — see [LICENSE](LICENSE) for details.
