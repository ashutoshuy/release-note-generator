# Contributing to Release Notes Generator

Thank you for your interest in contributing! 🎉

## 🚀 Quick Start

1. **Fork the repository**
2. **Clone your fork**: `git clone https://github.com/YOUR_USERNAME/release-notes-generator.git`
3. **Create a branch**: `git checkout -b feature/your-feature-name`
4. **Make changes and test**
5. **Commit**: `git commit -m "Add: your feature description"`
6. **Push**: `git push origin feature/your-feature-name`
7. **Create a Pull Request**

## 🛠️ Development Setup

```bash
# Create virtual environment
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate

# Install dependencies
pip install -r requirements.txt

# Copy environment file
cp .env.sample .env

# Configure OAuth credentials in .env
# Run the application
python run.py
```

## 📝 Code Style

- Follow PEP 8 for Python code
- Use meaningful variable and function names
- Add docstrings for functions and classes
- Keep functions small and focused

## 🧪 Testing

Before submitting a PR:

1. **Test your changes locally**
2. **Ensure OAuth flows work with GitHub/GitLab**
3. **Test PDF generation**
4. **Check all pages render correctly**
5. **Verify error handling**

## 🐛 Bug Reports

When reporting bugs, please include:

- Python version
- Browser and version
- Steps to reproduce
- Error messages
- Screenshots (if applicable)

## ✨ Feature Requests

For new features:

- Describe the use case
- Explain why it would be valuable
- Consider implementation complexity
- Check if similar functionality exists

## 🎯 Areas for Contribution

- **New Git Providers**: Bitbucket, Azure DevOps
- **Export Formats**: Word, Markdown, JSON
- **UI Improvements**: Better responsive design
- **Performance**: Caching, pagination
- **Testing**: Unit tests, integration tests
- **Documentation**: Tutorials, examples

## 📋 Pull Request Guidelines

- **One feature per PR**
- **Update documentation** if needed
- **Add tests** for new functionality
- **Update CHANGELOG.md**
- **Ensure CI passes**

## 🔒 Security

For security vulnerabilities:
- **DO NOT** open public issues
- Email maintainers directly
- Provide detailed information
- Allow time for fixes before disclosure

## 📞 Getting Help

- Check existing issues and discussions
- Join our community discussions
- Tag maintainers for urgent issues

## 🎖️ Recognition

Contributors will be:
- Added to README acknowledgments
- Credited in release notes
- Invited to maintainer discussions

---

**Thank you for making this project better!** 🙏