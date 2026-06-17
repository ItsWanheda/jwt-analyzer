# Contributing to JWT Analyzer

First off, thank you for considering contributing to **JWT Analyzer**!  
We truly appreciate your time, energy, and support in making this project more secure, reliable, and efficient.

Whether you're fixing a bug, improving documentation, adding a security check, or proposing a new feature, your contribution is very welcome.

---

## Getting Started

Follow these steps to set up your local development environment:

1. **Fork** the repository to your GitHub account.
2. **Clone** your fork locally:
```bash
   git clone https://github.com/ItsWanheda/jwt-analyzer.git
```
3. **Create** and activate a virtual environment:
```bash
   python -m venv .venv
   source .venv/bin/activate
```
On Windows:
```bash
   .venv\Scripts\activate
```
4. **Install dependencies:**
```bash
   pip install -r requirements.txt
```
5. **Create a feature branch:**
```bash
   git checkout -b feature/your-feature-name
```
**or for bug fixes:**
```bash
   git checkout -b fix/your-fix-name
```

---

## Pull Request Process
> Before opening a pull request, please make sure you:
1. **Update documentation**
  If you changed the API or added a new feature, update the README or any relevant documentation.
2. **Run tests**
  Ensure all existing tests pass and your changes do not introduce regressions.
3. **Commit your changes**
   Use clear and descriptive commit messages, for example:
```bash
   feat: add RSA-PSS signature support
```
4. **Push your branch:**
```bash
   git push origin your-branch-name
```
5. **Open a Pull** RequestDescribe what you changed, why you changed it, and reference any related issues.

---

## Coding Standards
To keep the codebase clean, consistent, and easy to maintain, please follow these standards:
* PEP 8: Follow PEP 8 as closely as possible.
* Type Hints: All new functions and methods must include Python type hints.
* Docstrings: Use Google-style docstrings for all new functions and classes.
* Readability: Prefer clear, maintainable code over clever but confusing solutions.

---

## Reporting Issues
Before opening a new issue, please search the issue tracker to check whether it has already been reported.
When filing a new issue, please include:

* Environment Details
* Steps to Reproduce
* Expected Behavior
* Actual Behavior

---

## Thank You
Every contribution matters — whether it’s a small typo fix or a major feature improvement.
**Thanks again for helping make JWT Analyzer better for everyone. 💙**
