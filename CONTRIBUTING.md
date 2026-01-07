# Contributing to MCP Cybersec Watchdog

Thanks for your interest in contributing! Here's how to get started.

## Quick Start

```bash
# Fork the repo on GitHub, then clone your fork
git clone https://github.com/YOUR_USERNAME/mcp-cybersec-watchdog
cd mcp-cybersec-watchdog

# Install dev dependencies
pip install -e ".[dev]"

# Run tests
pytest tests/ -v

# Code formatting
black src/ tests/
ruff check src/ tests/
```

## Development Workflow

1. **Create a branch** for your feature/fix:
   ```bash
   git checkout -b feature/your-feature-name
   ```

2. **Make your changes** and add tests

3. **Run tests** to ensure everything works:
   ```bash
   pytest tests/ -v
   ```

4. **Format your code**:
   ```bash
   black src/ tests/
   ```

5. **Commit** with a clear message:
   ```bash
   git commit -m "Add feature: description"
   ```

6. **Push** and create a Pull Request:
   ```bash
   git push origin feature/your-feature-name
   ```

## Code Standards

- Python 3.10+ required
- Follow **black** code style (line length: 100)
- Add **tests** for new features
- Update **documentation** if needed
- Keep functions **simple and focused**

## Pull Request Guidelines

- One feature/fix per PR
- Include tests that pass
- Update README if adding new features
- Add your changes to commit message

## Adding New Security Analyzers

1. Create new file in `src/mcp_security/analyzers/`
2. Implement analyzer function returning dict with `issues` key
3. Register in `audit.py` analyzer registry
4. Add tests in `tests/`

## Questions?

Open an issue or reach out via [GitHub Discussions](https://github.com/girste/mcp-cybersec-watchdog/discussions).
