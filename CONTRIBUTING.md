# Contributing to JWT Analyzer

First off, thank you for considering contributing to **JWT Analyzer**! We appreciate any help in making this tool more secure and efficient. Whether it's a bug fix, a new security check, or a feature addition, your help is welcome.

## Getting Started

1. **Fork the repository** to your own GitHub account.
2. **Clone your fork** locally: `git clone https://github.com/ItsWanheda/jwt-analyzer.git`
3. **Install dependencies**: `pip install -r requirements.txt` (Ensure you are using a virtual environment).
4. **Create a feature branch**: `git checkout -b feature/your-feature-name` or `fix/your-fix-name`.

## The Pull Request Process

1. **Update documentation**: If you've changed the API or added a new feature, update the README or relevant docs.
2. **Run tests**: Make sure all existing tests pass.
3. **Commit your changes**: Use descriptive commit messages (e.g., `feat: add RSA-PSS signature support`).
4. **Push to your branch**: `git push origin your-branch-name`.
5. **Open a Pull Request**: Explain what you changed and why. Reference any related issues.

## Coding Standards

To keep the codebase consistent and readable, please follow these guidelines:

* **PEP 8**: Adhere strictly to [PEP 8](https://pep8.org/).
* **Type Hinting**: All new functions and methods must have Python type hints.
* **Documentation**: Use Google-style docstrings for all new functions/classes.

## Reporting Issues

Before opening a new issue, please search the tracker to see if it has already been reported. When creating a new issue, please provide:

* **Environment Details**: OS, Python version, and version of `jwt_analyzer`.
* **Steps to Reproduce**: Provide a minimal, reproducible example if possible.
* **Expected Behavior**: What should happen.
* **Actual Behavior**: What is actually happening (include stack traces/errors).
