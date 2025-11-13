# Contributing to Blockchain

Thank you for your interest in contributing to this blockchain implementation! This document provides guidelines and instructions for contributing.

## Table of Contents

- [Code of Conduct](#code-of-conduct)
- [Getting Started](#getting-started)
- [How to Contribute](#how-to-contribute)
- [Development Setup](#development-setup)
- [Coding Standards](#coding-standards)
- [Testing Guidelines](#testing-guidelines)
- [Pull Request Process](#pull-request-process)
- [Reporting Bugs](#reporting-bugs)
- [Suggesting Enhancements](#suggesting-enhancements)

## Code of Conduct

This project adheres to a [Code of Conduct](CODE_OF_CONDUCT.md). By participating, you are expected to uphold this code.

## Getting Started

1. Fork the repository
2. Clone your fork: `git clone https://github.com/your-username/Blockchain.git`
3. Add upstream remote: `git remote add upstream https://github.com/pyenthusiasts/Blockchain.git`
4. Create a feature branch: `git checkout -b feature/your-feature-name`

## How to Contribute

### Types of Contributions

We welcome various types of contributions:

- **Bug fixes**: Fix identified bugs in the codebase
- **New features**: Implement new blockchain features
- **Documentation**: Improve or add documentation
- **Tests**: Add or improve test coverage
- **Performance improvements**: Optimize existing code
- **Code quality**: Refactoring and code cleanup

### Development Setup

```bash
# Clone the repository
git clone https://github.com/pyenthusiasts/Blockchain.git
cd Blockchain

# Create a virtual environment
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate

# Install dependencies
pip install -r requirements.txt
pip install -e .

# Install development dependencies
pip install pytest pytest-cov black flake8 pylint mypy
```

## Coding Standards

### Python Style Guide

- Follow [PEP 8](https://www.python.org/dev/peps/pep-0008/) style guide
- Use meaningful variable and function names
- Maximum line length: 120 characters
- Use type hints for function parameters and return values

### Code Formatting

We use `black` for code formatting:

```bash
# Format code
black blockchain_core tests examples

# Check formatting
black --check blockchain_core tests examples
```

### Linting

```bash
# Run flake8
flake8 blockchain_core tests --max-line-length=120

# Run pylint
pylint blockchain_core --max-line-length=120
```

### Type Checking

```bash
# Run mypy
mypy blockchain_core --ignore-missing-imports
```

### Documentation

- Add docstrings to all public functions, classes, and methods
- Use Google-style docstrings
- Include type hints in function signatures
- Update README.md if adding new features

Example docstring:

```python
def add_transaction(
    self,
    sender_public_key: str,
    recipient_address: str,
    value: float,
    signature: bytes
) -> bool:
    """
    Add a new transaction to the pending transactions.

    Args:
        sender_public_key: Sender's public key
        recipient_address: Recipient's address
        value: Transaction amount
        signature: Transaction signature

    Returns:
        True if transaction was added, False if invalid

    Raises:
        ValueError: If transaction data is invalid
    """
```

## Testing Guidelines

### Writing Tests

- Write tests for all new features
- Maintain or improve code coverage
- Use pytest for testing
- Place tests in the `tests/` directory
- Name test files `test_*.py`
- Name test functions `test_*`

### Running Tests

```bash
# Run all tests
pytest

# Run with coverage
pytest --cov=blockchain_core --cov-report=html

# Run specific test file
pytest tests/test_blockchain.py

# Run specific test
pytest tests/test_blockchain.py::TestBlockchain::test_mine_block

# Run verbose
pytest -v

# Run with markers
pytest -m "not slow"  # Skip slow tests
```

### Test Structure

```python
import pytest
from blockchain_core import Blockchain

class TestBlockchain:
    """Test cases for Blockchain class."""

    def test_feature_name(self):
        """Test description."""
        # Arrange
        blockchain = Blockchain()

        # Act
        result = blockchain.some_method()

        # Assert
        assert result == expected_value
```

## Pull Request Process

1. **Update your fork**:
   ```bash
   git fetch upstream
   git rebase upstream/main
   ```

2. **Create a feature branch**:
   ```bash
   git checkout -b feature/your-feature-name
   ```

3. **Make your changes**:
   - Write clean, documented code
   - Add tests for new features
   - Update documentation as needed

4. **Run tests and checks**:
   ```bash
   pytest
   black blockchain_core tests
   flake8 blockchain_core tests
   ```

5. **Commit your changes**:
   ```bash
   git add .
   git commit -m "Add feature: description of your changes"
   ```

   Commit message format:
   - Use present tense ("Add feature" not "Added feature")
   - Use imperative mood ("Move cursor to..." not "Moves cursor to...")
   - Limit first line to 72 characters
   - Reference issues and pull requests

6. **Push to your fork**:
   ```bash
   git push origin feature/your-feature-name
   ```

7. **Create a Pull Request**:
   - Go to the original repository on GitHub
   - Click "New Pull Request"
   - Select your fork and branch
   - Fill out the PR template
   - Link any related issues

### Pull Request Checklist

- [ ] Code follows project style guidelines
- [ ] Tests pass locally
- [ ] New tests added for new features
- [ ] Documentation updated
- [ ] Commit messages are clear and descriptive
- [ ] Branch is up to date with main
- [ ] No merge conflicts

## Reporting Bugs

### Before Submitting a Bug Report

- Check existing issues to avoid duplicates
- Verify the bug exists in the latest version
- Collect relevant information

### Bug Report Template

```markdown
**Describe the bug**
A clear description of the bug.

**To Reproduce**
Steps to reproduce the behavior:
1. Go to '...'
2. Run command '...'
3. See error

**Expected behavior**
What you expected to happen.

**Actual behavior**
What actually happened.

**Environment**
- OS: [e.g., Ubuntu 20.04]
- Python version: [e.g., 3.11]
- Blockchain version: [e.g., 1.0.0]

**Additional context**
Any other relevant information.
```

## Suggesting Enhancements

### Before Submitting an Enhancement

- Check if the enhancement already exists
- Consider if it fits the project scope
- Think about backward compatibility

### Enhancement Proposal Template

```markdown
**Is your feature request related to a problem?**
A clear description of the problem.

**Describe the solution you'd like**
A clear description of what you want to happen.

**Describe alternatives you've considered**
Other solutions or features you've considered.

**Additional context**
Any other relevant information, mockups, or examples.
```

## Code Review Process

- Maintainers will review your PR
- Address any requested changes
- Be patient and respectful
- PRs may take time to review

### Review Criteria

- Code quality and style
- Test coverage
- Documentation
- Performance impact
- Security implications
- Backward compatibility

## Recognition

Contributors will be recognized in:
- README.md contributors section
- Release notes
- GitHub contributors page

## Questions?

- Open an issue with the "question" label
- Join discussions in issues and pull requests
- Contact maintainers through GitHub

## License

By contributing, you agree that your contributions will be licensed under the MIT License.

---

Thank you for contributing to this project! Your efforts help make blockchain technology more accessible and educational.
