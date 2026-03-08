# Contributing to shzx

Thanks for your interest in making AI agents safer.

## Getting Started

```bash
git clone https://github.com/anthropics/shzx.git
cd shzx
pip install -e .
python -m pytest tests/ -v
```

## What to Work On

- **New command handlers** — add support for commands not yet in `handlers.py`
- **Better risk heuristics** — improve scoring accuracy for existing commands
- **New agent integrations** — hooks for other AI coding tools
- **False positive fixes** — if shzx flags something incorrectly, open an issue

## How to Add a Command Handler

1. Add the handler to the `parse_single_command()` function in `handlers.py`
2. Add any new risk constants to `constants.py`
3. Add unit tests in `tests/test_handlers.py`
4. Run `python -m pytest tests/ -v` to verify

## Code Style

- Use type hints on all public functions
- Use constants from `constants.py` instead of bare integers for risk scores
- Keep handlers consistent with existing patterns in `handlers.py`

## Testing

```bash
python -m pytest tests/ -v
```

All tests must pass before submitting a PR. Current count: 242 tests.

## Pull Requests

- Keep PRs focused — one feature or fix per PR
- Add tests for new functionality
- Update `CHANGELOG.md` under an `[Unreleased]` section

## License

By contributing, you agree that your contributions will be licensed under the Apache License 2.0.
