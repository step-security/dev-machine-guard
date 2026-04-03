# Contributing to StepSecurity Dev Machine Guard

Thank you for your interest in contributing! Dev Machine Guard is an open-source project by [StepSecurity](https://stepsecurity.io) and we welcome contributions from the community.

## Ways to Contribute

### Add a New Detection

To add detection for a new AI tool, IDE, or framework:

1. Open an issue using the [Feature Request](.github/ISSUE_TEMPLATE/feature_request.yml) template, or
2. Submit a PR modifying the appropriate detector in `internal/detector/`

**How to add a new IDE/desktop app:**

Find the IDE detector in `internal/detector/ide.go` and add an entry to the apps list. See [Adding Detections](docs/adding-detections.md) for the full guide.

**How to add a new AI CLI tool:**

Find the AI CLI detector in `internal/detector/ai_cli.go` and add an entry to the tools list. See [Adding Detections](docs/adding-detections.md) for the full guide.

### Improve Documentation

Documentation lives in the `docs/` folder. Improvements, corrections, and new guides are always welcome.

## Development Setup

1. Clone the repository:
   ```bash
   git clone https://github.com/step-security/dev-machine-guard.git
   cd dev-machine-guard
   ```

2. Build the binary:
   ```bash
   make build
   ```

3. Run locally:
   ```bash
   # Pretty output with progress messages
   ./stepsecurity-dev-machine-guard --verbose

   # JSON output
   ./stepsecurity-dev-machine-guard --json

   # HTML report
   ./stepsecurity-dev-machine-guard --html report.html
   ```

## Code Style

- Go source code in `internal/` must pass `golangci-lint` (our CI runs it on every PR)
- Follow the existing code patterns (package structure, naming conventions, JSON struct tags)
- Use the `progress` package for status messages (they respect the `--verbose` flag)
- Use standard Go error handling patterns

## Pull Request Process

1. Fork the repository
2. Create a feature branch (`git checkout -b add-new-tool-detection`)
3. Edit Go source in `internal/` (not the legacy shell script)
4. Test locally: `./stepsecurity-dev-machine-guard --verbose`
5. Ensure lint and tests pass: `make lint && make test && make smoke`
6. Submit a PR using our [PR template](.github/pull_request_template.md)

## Reporting Issues

- **Bugs**: Use the [Bug Report](.github/ISSUE_TEMPLATE/bug_report.yml) template
- **Features**: Use the [Feature Request](.github/ISSUE_TEMPLATE/feature_request.yml) template
- **Security vulnerabilities**: See [SECURITY.md](SECURITY.md)

## Code of Conduct

This project follows the [Contributor Covenant Code of Conduct](CODE_OF_CONDUCT.md). By participating, you agree to uphold this code.

## License

By contributing, you agree that your contributions will be licensed under the [Apache License 2.0](LICENSE).
