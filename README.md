# Release Notes Generator

🚀 **Automated Release Documentation from Git Commits**

A Flask-based web application that automatically generates professional release notes from your Git repository commits. Supports GitHub and GitLab with OAuth authentication.

## ✨ Features

- 🔐 **Multi-Provider OAuth**: GitHub and GitLab authentication
- 🏷️ **Automatic Commit Categorization**: Features, bugs, enhancements, hotfixes, maintenance
- 🌿 **Release Branch Detection**: Supports `r_X.Y.Z` and `release/X.Y.Z` patterns
- 📄 **Professional PDF Generation**: Beautifully formatted release notes
- 📚 **Release History**: Track and manage all generated release notes
- ✍️ **Custom Entries**: Add manual entries to release notes
- 🎫 **Redmine Integration**: Extract ticket numbers from commit messages
- 🔍 **Smart Commit Parsing**: Automatic extraction of modules and metadata

## 📋 Prerequisites

- **Python 3.8+**
- **Git** (for repository access)
- **OAuth Applications** configured on GitHub/GitLab

## 🚀 Quick Start

### 1. Clone and Setup

```bash
# Clone the repository
git clone <your-repo-url>
cd release-notes-generator

# Create virtual environment
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate

# Install dependencies
pip install -r requirements.txt
```

### 2. Configure OAuth Applications

#### GitHub Setup
1. Go to [GitHub Developer Settings](https://github.com/settings/developers)
2. Click "New OAuth App"
3. Configure:
   - **Application name**: Release Notes Generator
   - **Homepage URL**: `http://localhost:3000`
   - **Authorization callback URL**: `http://localhost:3000/login/github/authorized`
4. Save and copy **Client ID** and **Client Secret**

#### GitLab Setup
1. Go to your GitLab instance → **Settings** → **Applications**
2. Create new application:
   - **Name**: Release Notes Generator
   - **Redirect URI**: `http://localhost:3000/login/gitlab/authorized`
   - **Scopes**: `api`, `read_user`, `read_repository`
3. Save and copy **Application ID** and **Secret**

### 3. Environment Configuration

Create a `.env` file in the project root:

```bash
# Copy from sample
cp .env.sample .env

# Edit .env with your credentials
GITHUB_ENABLED=true
GITHUB_CLIENT_ID=your_github_client_id
GITHUB_CLIENT_SECRET=your_github_client_secret

GITLAB_ENABLED=true
GITLAB_CLIENT_ID=your_gitlab_application_id
GITLAB_CLIENT_SECRET=your_gitlab_secret
GITLAB_URL=https://gitlab.com  # Change for self-hosted
```

### 4. Run the Application

```bash
# Using the startup script (recommended)
python run.py

# Or directly
python main.py
```

Visit: `http://localhost:3000`

## 📖 Usage Guide

### Commit Message Patterns

The application automatically categorizes commits based on patterns in commit messages:

| Category | Patterns | Example |
|----------|----------|---------|
| **Features** | `#feature`, `feat:`, `feature:` | `feat: Add user authentication` |
| **Bug Fixes** | `#bug`, `fix:`, `bug:` | `fix: Resolve login issue #123` |
| **Enhancements** | `#enhancement`, `enhance:` | `enhance: Improve UI performance` |
| **Hotfixes** | `#hotfix`, `hotfix:` | `hotfix: Critical security patch` |
| **Maintenance** | `#maintenance`, `maint:` | `maint: Update dependencies` |
| **RCA** | `#rca`, `rca:` | `rca: Database connection timeout` |


### Module Extraction

Extract impacted modules using:
- `@module_name` - e.g., `@auth`, `@payment`
- `[module_name]` - e.g., `[auth]`, `[payment]`

### Release Branch Naming

The application detects release branches with these patterns:
- `r_1.2.3` (recommended)
- `release/1.2.3`
- `r_2.0.0-beta`

## 🔧 Configuration Options

### Environment Variables

| Variable | Description | Default | Required |
|----------|-------------|---------|----------|
| `SECRET_KEY` | Flask secret key | `dev-secret-key...` | Yes |
| `DATABASE_URL` | Database connection string | `sqlite:///releases.db` | No |
| `PORT` | Application port | `3000` | No |
| `DEBUG` | Debug mode | `false` | No |
| `GITHUB_ENABLED` | Enable GitHub OAuth | `false` | No |
| `GITHUB_CLIENT_ID` | GitHub OAuth Client ID | - | If GitHub enabled |
| `GITHUB_CLIENT_SECRET` | GitHub OAuth Client Secret | - | If GitHub enabled |
| `GITLAB_ENABLED` | Enable GitLab OAuth | `false` | No |
| `GITLAB_CLIENT_ID` | GitLab OAuth Application ID | - | If GitLab enabled |
| `GITLAB_CLIENT_SECRET` | GitLab OAuth Secret | - | If GitLab enabled |
| `GITLAB_URL` | GitLab instance URL | `https://gitlab.com` | No |
| `GITLAB_VERIFY_SSL` | Verify SSL for GitLab | `true` | No |

### Database Configuration

**SQLite (Default)**:
```bash
DATABASE_URL=sqlite:///releases.db
```

**PostgreSQL (Production)**:
```bash
DATABASE_URL=postgresql://username:password@localhost/dbname
```

## 🐛 Troubleshooting

### Common Issues

**1. "No authentication providers are configured"**
- Check your `.env` file exists in the project root
- Verify `GITHUB_ENABLED=true` or `GITLAB_ENABLED=true`
- Ensure `CLIENT_ID` and `CLIENT_SECRET` are properly set

**2. OAuth authentication fails**
- Verify callback URLs match exactly:
  - GitHub: `http://localhost:3000/login/github/authorized`
  - GitLab: `http://localhost:3000/login/gitlab/authorized`
- Check that OAuth application is active
- Ensure client credentials are correct

**3. SSL/TLS errors with GitLab**
- For self-hosted GitLab with self-signed certificates:
  ```bash
  GITLAB_VERIFY_SSL=false
  ```
- Only use this for development environments

**4. PDF generation fails**
- Install system dependencies (Linux):
  ```bash
  sudo apt-get install build-essential python3-dev python3-pip python3-setuptools python3-wheel python3-cffi libcairo2 libpango-1.0-0 libpangocairo-1.0-0 libgdk-pixbuf2.0-0 libffi-dev shared-mime-info
  ```
- Ensure WeasyPrint is properly installed:
  ```bash
  pip install WeasyPrint
  ```

**5. Database connection issues**
- Check database file permissions (SQLite)
- Verify PostgreSQL connection string (Production)
- Reset database if corrupted:
  ```bash
  python main.py reset_db
  ```

### Debug Mode

Enable detailed error messages:
```bash
DEBUG=true
```

### Health Check

Check application status:
```
GET /health
```

Response:
```json
{
  "status": "healthy",
  "providers": ["github", "gitlab"],
  "database": "connected"
}
```

## 🏗️ Project Structure

```
release-notes-generator/
├── main.py                 # Main application file
├── run.py                  # Startup script
├── requirements.txt        # Python dependencies
├── .env                   # Environment configuration
├── .env.sample            # Environment template
├── README.md              # This file
├── templates/             # HTML templates
│   ├── index.html         # Landing page
│   ├── projects.html      # Projects listing
│   ├── project_details.html # Project details
│   ├── prepare_release.html # Release preparation
│   ├── history.html       # Release history
│   ├── release_note_pdf.html # PDF template
│   └── errors/            # Error pages
│       ├── 404.html
│       ├── 500.html
│       └── 403.html
└── releases.db            # SQLite database (auto-created)
```

## 🚀 Production Deployment

### Security Considerations

1. **Change SECRET_KEY**:
   ```bash
   SECRET_KEY=your-super-secure-random-key-here
   ```

2. **Disable Debug Mode**:
   ```bash
   DEBUG=false
   ```

3. **Use HTTPS**:
   - Update OAuth callback URLs to use `https://`
   - Configure SSL certificates

4. **Database**:
   - Use PostgreSQL instead of SQLite
   - Regular backups

5. **Environment Variables**:
   - Use secure environment variable management
   - Never commit `.env` to version control

### Example Production Configuration

```bash
# Production .env
SECRET_KEY=prod-secret-key-change-this
DATABASE_URL=postgresql://user:pass@localhost/releases_prod
DEBUG=false
PORT=8000

GITHUB_ENABLED=true
GITHUB_CLIENT_ID=prod_github_client_id
GITHUB_CLIENT_SECRET=prod_github_client_secret

# Update OAuth callback URLs to:
# https://yourdomain.com/login/github/authorized
# https://yourdomain.com/login/gitlab/authorized
```

## 📄 License

This project is licensed under the MIT License - see the LICENSE file for details.

## 🤝 Contributing

1. Fork the repository
2. Create a feature branch
3. Commit your changes
4. Push to the branch
5. Create a Pull Request

## 📞 Support

For issues and questions:
1. Check the troubleshooting section
2. Review error logs in debug mode
3. Create an issue in the repository

---

**Made with ❤️ for development teams who value good documentation**