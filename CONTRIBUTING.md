# Contributing to PanOS Evaluator

Thank you for your interest in contributing to PanOS Evaluator! This document provides guidelines and information for contributors.

## Getting Started

1. **Fork the repository** on GitHub
2. **Clone your fork** locally
3. **Create a feature branch** for your changes
4. **Make your changes** following the guidelines below
5. **Test your changes** thoroughly
6. **Submit a pull request**

## Development Setup

### Prerequisites
- Python 3.8 or higher
- Git

### Installation
```bash
# Clone your fork
git clone https://github.com/yourusername/pan_evaluator.git
cd pan_evaluator

# Install dependencies
pip install -r requirements.txt

# Install in development mode
pip install -e .
```

## Code Style Guidelines

### Python Code
- Follow PEP 8 style guidelines
- Use meaningful variable and function names
- Add docstrings to all functions and classes
- Keep functions focused and concise
- Use type hints where appropriate

### GUI Code
- Follow Tkinter best practices
- Use consistent naming conventions for widgets
- Organize UI code logically
- Add comments for complex UI logic

### Error Handling
- Use specific exception types when possible
- Provide meaningful error messages
- Log errors appropriately
- Handle edge cases gracefully

## Testing

### Manual Testing
Before submitting changes, please test:
- [ ] Application starts without errors
- [ ] All GUI elements work correctly
- [ ] API mode functionality (if applicable)
- [ ] CSV import functionality
- [ ] Export functionality (CSV and XLSX)
- [ ] Configuration persistence
- [ ] Error handling scenarios

### Test Scripts
The project includes several test scripts for troubleshooting:
- `test_network.py`: Network connectivity testing
- `test_panos_detailed.py`: Detailed API testing
- `test_api_key_format.py`: API key validation

## Pull Request Guidelines

### Before Submitting
1. **Test thoroughly** on your local environment
2. **Update documentation** if needed
3. **Check for any sensitive data** in your changes
4. **Ensure all tests pass**

### Pull Request Description
Please include:
- **Summary** of changes
- **Motivation** for the changes
- **Testing performed**
- **Screenshots** (if UI changes)
- **Related issues** (if any)

### Code Review
- All pull requests require review
- Address feedback promptly
- Keep discussions constructive
- Be open to suggestions

## Feature Requests

When requesting new features:
1. **Describe the problem** you're trying to solve
2. **Explain the proposed solution**
3. **Provide use cases** or examples
4. **Consider implementation complexity**

## Bug Reports

When reporting bugs:
1. **Describe the issue** clearly
2. **Provide steps to reproduce**
3. **Include error messages** and logs
4. **Specify your environment** (OS, Python version, etc.)
5. **Attach relevant files** if needed

## Security Considerations

- **Never commit sensitive data** (API keys, passwords, etc.)
- **Use environment variables** for configuration
- **Validate all inputs** from users
- **Follow security best practices**

## Documentation

When contributing documentation:
- Use clear, concise language
- Include examples where helpful
- Keep documentation up to date
- Follow the existing style

## Questions or Need Help?

- **Create an issue** for bugs or feature requests
- **Use discussions** for general questions
- **Check existing issues** before creating new ones
- **Be respectful** and constructive

## License

By contributing to this project, you agree that your contributions will be licensed under the MIT License.

---

Thank you for contributing to PanOS Evaluator! Your help makes this project better for everyone.
