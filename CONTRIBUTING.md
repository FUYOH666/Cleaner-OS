# Contributing to Cleaner-OS

Thank you for your interest in contributing to Cleaner-OS! This document provides guidelines and instructions for contributing.

## Code of Conduct

- Be respectful and considerate
- Welcome newcomers and help them learn
- Focus on constructive feedback
- Respect different viewpoints and experiences

## How to Contribute

### Reporting Bugs

- Use the [bug report template](.github/ISSUE_TEMPLATE/bug_report.md)
- Include steps to reproduce the issue
- Provide system information (OS, Python version, etc.)
- Include relevant error messages or logs

### Suggesting Features

- Use the [feature request template](.github/ISSUE_TEMPLATE/feature_request.md)
- Clearly describe the feature and its use case
- Explain why this feature would be useful
- Consider potential implementation approaches

### Pull Requests

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing-feature`)
3. Make your changes
4. Add tests if applicable
5. Ensure all tests pass (`uv run pytest`)
6. Run linter (`uv run ruff check .`)
7. Run type checker (`uv run pyright`)
8. Commit your changes (`git commit -m 'Add amazing feature'`)
9. Push to your branch (`git push origin feature/amazing-feature`)
10. Open a Pull Request

## Development Setup

```bash
# Clone your fork
git clone https://github.com/YOUR_USERNAME/Cleaner-OS.git
cd Cleaner-OS

# Install dependencies
uv sync

# Run tests
uv run pytest

# Run linter
uv run ruff check .

# Run type checker
uv run pyright
```

## Coding Standards

- Follow PEP 8 style guide
- Use type hints for all functions
- Write docstrings for all public functions and classes
- Keep functions focused and small
- Write meaningful commit messages

## Testing

- Write tests for new features
- Ensure all existing tests pass
- Aim for good test coverage
- Use pytest for testing

## Documentation

- Update README.md if needed
- Add docstrings to new functions/classes
- Update CHANGELOG.md for user-facing changes

## Questions?

Feel free to open an issue for any questions or concerns.

Thank you for contributing to Cleaner-OS! 🎉

