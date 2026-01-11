# Contributing to Nubicustos

First off, thank you for considering contributing to Nubicustos! It's people like you that make Nubicustos such a great tool for the security community.

## Table of Contents

- [Code of Conduct](#code-of-conduct)
- [Getting Started](#getting-started)
- [Development Environment](#development-environment)
- [How to Contribute](#how-to-contribute)
- [Code Style Guidelines](#code-style-guidelines)
- [Pull Request Process](#pull-request-process)
- [Issue Guidelines](#issue-guidelines)
- [Community](#community)

---

## Code of Conduct

This project and everyone participating in it is governed by our commitment to providing a welcoming and inclusive environment. By participating, you are expected to:

- Use welcoming and inclusive language
- Be respectful of differing viewpoints and experiences
- Gracefully accept constructive criticism
- Focus on what is best for the community
- Show empathy towards other community members

Unacceptable behavior may be reported to the project maintainers.

---

## Getting Started

### Prerequisites

Before you begin, ensure you have:

- Docker Engine 20.10+
- Docker Compose 2.0+
- Git
- Python 3.9+ (for scripts and API development)
- Node.js 18+ (for frontend development)

### Fork and Clone

1. Fork the repository on GitHub
2. Clone your fork locally:

```bash
git clone https://github.com/YOUR-USERNAME/Nubicustos.git
cd Nubicustos
```

3. Add the upstream repository:

```bash
git remote add upstream https://github.com/Su1ph3r/Nubicustos.git
```

4. Keep your fork in sync:

```bash
git fetch upstream
git checkout main
git merge upstream/main
```

---

## Development Environment

### Quick Setup

```bash
# Copy environment file
cp .env.example .env

# Edit .env with development settings
# Use simple passwords for local development

# Start the stack
docker-compose up -d

# Verify services
docker-compose ps
```

### Component-Specific Development

#### API Development (FastAPI)

```bash
cd api

# Create virtual environment
python -m venv venv
source venv/bin/activate  # Linux/Mac
# or: venv\Scripts\activate  # Windows

# Install dependencies
pip install -r requirements.txt
pip install -r requirements-dev.txt  # If available

# Run locally
uvicorn main:app --reload --port 8000
```

#### Frontend Development (Vue.js)

```bash
cd frontend

# Install dependencies
npm install

# Run development server
npm run dev

# Build for production
npm run build
```

#### Report Processor Development

```bash
cd report-processor

# Create virtual environment
python -m venv venv
source venv/bin/activate

# Install dependencies
pip install -r requirements.txt

# Run scripts
python parse_findings.py --help
```

### Running Tests

```bash
# API tests
cd api
pytest

# Frontend tests
cd frontend
npm test

# Integration tests
./scripts/test-integration.sh
```

---

## How to Contribute

### Types of Contributions

We welcome many types of contributions:

1. **Bug Reports** - Found a bug? Let us know!
2. **Feature Requests** - Have an idea? We'd love to hear it!
3. **Documentation** - Help improve our docs
4. **Code** - Fix bugs, add features, improve performance
5. **Testing** - Write tests, report test failures
6. **Security Tools** - Add support for new scanning tools

### Good First Issues

New to the project? Look for issues labeled `good first issue` - these are great starting points for new contributors.

### Adding a New Security Tool

To add support for a new security scanning tool:

1. Add the service definition to `docker-compose.yml`
2. Create the report directory in `reports/`
3. Add the `ENABLE_*` variable to `.env.example`
4. Update `scripts/run-all-audits.sh` to include the tool
5. Add parsing logic to `report-processor/` if needed
6. Update documentation
7. Add tests

Example service definition:

```yaml
new-tool:
  image: vendor/new-tool:latest
  container_name: new-tool
  volumes:
    - ./reports/new-tool:/reports
    - ./credentials:/credentials:ro
  command: scan --output /reports/results.json
  networks:
    - security-net
  restart: unless-stopped
```

---

## Code Style Guidelines

### Python

We follow PEP 8 with these specifics:

```python
# Use 4 spaces for indentation
# Maximum line length: 100 characters
# Use type hints where practical

def process_findings(
    findings: list[dict],
    severity_filter: str | None = None
) -> list[dict]:
    """
    Process security findings with optional severity filtering.

    Args:
        findings: List of finding dictionaries
        severity_filter: Optional severity level to filter by

    Returns:
        Filtered and processed findings list
    """
    pass
```

### JavaScript/Vue

```javascript
// Use 2 spaces for indentation
// Use single quotes for strings
// Use const/let, never var
// Use arrow functions where appropriate

const processFindings = (findings, options = {}) => {
  return findings.filter(f => f.severity === options.severity)
}
```

### Docker/YAML

```yaml
# Use 2 spaces for indentation
# Group related services with comments
# Always specify restart policy
# Include healthchecks where appropriate
```

### Commit Messages

Follow the conventional commits format:

```
type(scope): description

[optional body]

[optional footer]
```

Types:
- `feat`: New feature
- `fix`: Bug fix
- `docs`: Documentation changes
- `style`: Code style changes (formatting, etc.)
- `refactor`: Code refactoring
- `test`: Adding or updating tests
- `chore`: Maintenance tasks

Examples:

```
feat(api): add endpoint for scan comparison
fix(prowler): correct output path in docker command
docs(readme): update quick start instructions
```

---

## Pull Request Process

### Before Submitting

1. **Update your fork** with the latest upstream changes
2. **Create a feature branch** from `main`:
   ```bash
   git checkout -b feature/your-feature-name
   ```
3. **Make your changes** following our code style guidelines
4. **Write/update tests** for your changes
5. **Update documentation** if needed
6. **Test locally** to ensure everything works

### Submitting the PR

1. Push your branch to your fork:
   ```bash
   git push origin feature/your-feature-name
   ```

2. Create a Pull Request on GitHub with:
   - Clear title describing the change
   - Description of what and why
   - Link to related issue(s) if applicable
   - Screenshots for UI changes

3. Fill out the PR template completely

### PR Review Process

1. Maintainers will review your PR
2. Address any requested changes
3. Once approved, a maintainer will merge your PR
4. Your contribution will be included in the next release

### PR Checklist

- [ ] Code follows project style guidelines
- [ ] Self-review completed
- [ ] Documentation updated (if needed)
- [ ] Tests added/updated
- [ ] All tests pass locally
- [ ] Commit messages follow conventions
- [ ] PR description is complete

---

## Issue Guidelines

### Bug Reports

When reporting bugs, include:

1. **Summary**: Clear description of the bug
2. **Steps to Reproduce**: How to trigger the bug
3. **Expected Behavior**: What should happen
4. **Actual Behavior**: What actually happens
5. **Environment**: OS, Docker version, etc.
6. **Logs**: Relevant error messages or logs

Use the bug report template when creating issues.

### Feature Requests

When requesting features:

1. **Problem Statement**: What problem does this solve?
2. **Proposed Solution**: How should it work?
3. **Alternatives**: Other approaches considered
4. **Additional Context**: Screenshots, examples, etc.

Use the feature request template when creating issues.

### Security Vulnerabilities

**Do NOT report security vulnerabilities through public issues.**

Instead:
- Use GitHub's private vulnerability reporting
- Email the maintainers directly
- Provide details confidentially

We take security seriously and will respond promptly.

---

## Community

### Getting Help

- **Issues**: For bugs and feature requests
- **Discussions**: For questions and general discussion
- **Documentation**: Check our docs first

### Recognition

Contributors are recognized in:
- The CHANGELOG for their release
- The Contributors graph on GitHub
- Release notes when applicable

---

## License

By contributing to Nubicustos, you agree that your contributions will be licensed under the MIT License.

---

Thank you for contributing to Nubicustos!
