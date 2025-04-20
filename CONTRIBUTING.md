# Contributing to RDP Management PowerShell Module

Thank you for your interest in contributing to the RDP Management PowerShell Module! This document provides guidelines and instructions for contributing to this project.

## Code of Conduct

By participating in this project, you agree to abide by our Code of Conduct. Please be respectful and professional in all interactions.

## How to Contribute

### Reporting Issues

If you find a bug or have a suggestion for improving the module:

1. Check if the issue already exists in the [GitHub issue tracker](https://github.com/Jaymateo11/RDP-Management-Powershell-Module/issues)
2. If not, create a new issue with a descriptive title and detailed information:
   - Steps to reproduce the issue
   - Expected behavior
   - Actual behavior
   - PowerShell version and OS information
   - Any relevant error messages or screenshots

### Submitting Changes

1. Fork the repository
2. Create a new branch for your feature or bugfix: `git checkout -b feature/your-feature-name` or `git checkout -b fix/issue-description`
3. Make your changes
4. Add tests for your changes if applicable
5. Run existing tests to ensure you haven't broken anything
6. Commit your changes with a clear, descriptive commit message
7. Push your branch to your fork
8. Submit a pull request to the main branch

### Pull Request Process

1. Update the README.md or documentation with details of your changes if needed
2. Update the CHANGELOG.md with details of your changes
3. The PR will be reviewed by maintainers who may request changes
4. Once approved, your PR will be merged

## Coding Standards

### PowerShell Style Guide

* Follow [PowerShell Best Practices and Style Guide](https://github.com/PoshCode/PowerShellPracticeAndStyle)
* Use proper [comment-based help](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.core/about/about_comment_based_help) for all functions
* Add [parameter validation](https://learn.microsoft.com/en-us/powershell/scripting/developer/cmdlet/validating-parameter-input) where appropriate
* Follow consistent error handling patterns

### Code Structure Guidelines

* Functions should be focused on doing one thing well
* Code should be well-commented and easy to understand
* Use meaningful variable and function names
* Include appropriate error handling and logging
* Add comment-based help for all functions
* Use PowerShell-approved verbs (Get-, Set-, New-, Remove-, etc.)

### Testing

* Add appropriate tests for new functionality
* Ensure all existing tests pass before submitting a PR
* Test your code on PowerShell 5.1 and PowerShell Core if possible

## License

By contributing to this project, you agree that your contributions will be licensed under the project's [MIT License](LICENSE).

## Questions?

If you have any questions about contributing, please create an issue with your question.

Thank you for helping to improve the RDP Management PowerShell Module!

