import os
import json
import datetime
from io import BytesIO
from flask import Flask, render_template, redirect, url_for, session, request, flash, send_file, jsonify
from flask_sqlalchemy import SQLAlchemy
from authlib.integrations.flask_client import OAuth
import requests
import tempfile
from datetime import datetime
from typing import Dict, List, Optional, Any
import re
import urllib3
from dotenv import load_dotenv

# Load environment variables from .env file
load_dotenv()

# Suppress SSL warnings for development
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# Initialize Flask application
app = Flask(__name__)
app.secret_key = os.environ.get('SECRET_KEY', 'dev-secret-key-change-in-production')

# Database configuration
database_url = os.environ.get('DATABASE_URL', 'sqlite:///releases.db')
if database_url.startswith('postgres://'):
    database_url = database_url.replace('postgres://', 'postgresql://', 1)
app.config['SQLALCHEMY_DATABASE_URI'] = database_url
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

# Provider Configuration
def get_bool_env(env_var, default='false'):
    return os.environ.get(env_var, default).lower() in ('true', '1', 'yes', 'on')

PROVIDERS_CONFIG = {
    'github': {
        'enabled': get_bool_env('GITHUB_ENABLED'),
        'client_id': os.environ.get('GITHUB_CLIENT_ID'),
        'client_secret': os.environ.get('GITHUB_CLIENT_SECRET'),
        'api_base_url': 'https://api.github.com/',
        'access_token_url': 'https://github.com/login/oauth/access_token',
        'authorize_url': 'https://github.com/login/oauth/authorize',
        'scope': 'repo user:email',
        'name': 'GitHub'
    },
    'gitlab': {
        'enabled': get_bool_env('GITLAB_ENABLED'),
        'client_id': os.environ.get('GITLAB_CLIENT_ID'),
        'client_secret': os.environ.get('GITLAB_CLIENT_SECRET'),
        'api_base_url': os.environ.get('GITLAB_URL', 'https://gitlab.com').rstrip('/') + '/api/v4/',
        'access_token_url': os.environ.get('GITLAB_URL', 'https://gitlab.com').rstrip('/') + '/oauth/token',
        'authorize_url': os.environ.get('GITLAB_URL', 'https://gitlab.com').rstrip('/') + '/oauth/authorize',
        'scope': 'api read_user read_repository',
        'name': 'GitLab',
        'verify_ssl': get_bool_env('GITLAB_VERIFY_SSL', 'true')
    }
}

# Debug print to check environment variables
print("Environment variables loaded:")
for provider, config in PROVIDERS_CONFIG.items():
    print(f"{provider.upper()}_ENABLED: {config['enabled']}")
    print(f"{provider.upper()}_CLIENT_ID: {'***' if config['client_id'] else 'Not set'}")
    print(f"{provider.upper()}_CLIENT_SECRET: {'***' if config['client_secret'] else 'Not set'}")

# Get enabled providers - only include if all required fields are present
ENABLED_PROVIDERS = {}
for k, v in PROVIDERS_CONFIG.items():
    if v['enabled'] and v['client_id'] and v['client_secret']:
        ENABLED_PROVIDERS[k] = v
        print(f"✅ {v['name']} provider enabled")
    else:
        missing_fields = []
        if not v['enabled']:
            missing_fields.append('not enabled')
        if not v['client_id']:
            missing_fields.append('missing client_id')
        if not v['client_secret']:
            missing_fields.append('missing client_secret')
        print(f"❌ {v['name']} provider disabled: {', '.join(missing_fields)}")

# Initialize database
db = SQLAlchemy(app)

# Initialize OAuth
oauth = OAuth(app)

# Register OAuth providers dynamically
oauth_providers = {}
for provider_key, config in ENABLED_PROVIDERS.items():
    try:
        client_kwargs = {'scope': config['scope']}
        
        # Add SSL verification setting for GitLab
        if provider_key == 'gitlab' and not config.get('verify_ssl', True):
            client_kwargs['verify'] = False
            client_kwargs['token_endpoint_auth_method'] = 'client_secret_post'
        
        oauth_providers[provider_key] = oauth.register(
            name=provider_key,
            client_id=config['client_id'],
            client_secret=config['client_secret'],
            access_token_url=config['access_token_url'],
            authorize_url=config['authorize_url'],
            api_base_url=config['api_base_url'],
            client_kwargs=client_kwargs
        )
        print(f"✅ OAuth provider registered for {config['name']}")
    except Exception as e:
        print(f"❌ Failed to register OAuth provider for {config['name']}: {e}")

# Configure requests session for GitLab SSL verification
requests_session = requests.Session()
if 'gitlab' in ENABLED_PROVIDERS and not ENABLED_PROVIDERS['gitlab'].get('verify_ssl', True):
    requests_session.verify = False

# Database Models
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    provider = db.Column(db.String(20), nullable=False)
    provider_id = db.Column(db.String(100), nullable=False)
    username = db.Column(db.String(100), nullable=False)
    email = db.Column(db.String(200))
    name = db.Column(db.String(200))
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    
    __table_args__ = (db.UniqueConstraint('provider', 'provider_id'),)

class ReleaseNote(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    provider = db.Column(db.String(20), nullable=False)
    project_id = db.Column(db.String(100), nullable=False)
    project_name = db.Column(db.String(200), nullable=False)
    branch_name = db.Column(db.String(100), nullable=False)
    version = db.Column(db.String(50), nullable=False)
    team_name = db.Column(db.String(100), nullable=False)
    release_date = db.Column(db.DateTime, default=datetime.utcnow)
    release_data = db.Column(db.Text, nullable=False)  # Stored as JSON
    
    user = db.relationship('User', backref=db.backref('release_notes', lazy=True))

# Provider Strategy Pattern
class ProviderStrategy:
    def __init__(self, provider: str):
        self.provider = provider
        self.config = ENABLED_PROVIDERS[provider]
        self.base_url = self.config['api_base_url'].rstrip('/')
    
    def get_headers(self) -> Dict[str, str]:
        token = session.get(f'{self.provider}_token')
        if not token:
            return {}
        return self.get_auth_headers(token)
    
    def get_auth_headers(self, token: str) -> Dict[str, str]:
        if self.provider == 'github':
            return {'Authorization': f'Bearer {token}', 'Accept': 'application/vnd.github.v3+json'}
        elif self.provider == 'gitlab':
            return {'Authorization': f'Bearer {token}'}
        return {}
    
    def make_request(self, endpoint: str, params: Dict = None) -> Optional[Dict]:
        url = f"{self.base_url}/{endpoint.lstrip('/')}"
        headers = self.get_headers()
        
        try:
            verify_ssl = self.config.get('verify_ssl', True) if self.provider == 'gitlab' else True
            response = requests.get(url, headers=headers, params=params or {}, verify=verify_ssl)
            
            if response.status_code == 200:
                return response.json()
            else:
                app.logger.error(f"API request failed: {response.status_code} - {response.text}")
                return None
        except Exception as e:
            app.logger.error(f"Request error: {str(e)}")
        return None
    
    def get_user_info(self) -> Optional[Dict]:
        if self.provider == 'github':
            return self.make_request('/user')
        elif self.provider == 'gitlab':
            return self.make_request('/user')
        return None
    
    def get_user_projects(self) -> List[Dict]:
        projects = []
        page = 1
        per_page = 100
        
        while True:
            if self.provider == 'github':
                data = self.make_request('/user/repos', {
                    'page': page, 
                    'per_page': per_page, 
                    'sort': 'updated',
                    'type': 'all'
                })
            elif self.provider == 'gitlab':
                data = self.make_request('/projects', {
                    'membership': True, 
                    'page': page, 
                    'per_page': per_page,
                    'order_by': 'last_activity_at',
                    'sort': 'desc'
                })
            
            if not data:
                break
            
            if isinstance(data, list):
                if not data:
                    break
                projects.extend(data)
            else:
                break
            
            page += 1
            if len(data) < per_page:
                break
        
        return self.normalize_projects(projects)
    
    def normalize_projects(self, projects: List[Dict]) -> List[Dict]:
        normalized = []
        for project in projects:
            try:
                if self.provider == 'github':
                    normalized.append({
                        'id': project['full_name'],  # Use full_name for GitHub as ID
                        'name': project['name'],
                        'full_name': project['full_name'],
                        'description': project.get('description', ''),
                        'web_url': project['html_url'],
                        'default_branch': project.get('default_branch', 'main'),
                        'updated_at': project.get('updated_at', '')
                    })
                elif self.provider == 'gitlab':
                    normalized.append({
                        'id': str(project['id']),  # Keep as string for consistency
                        'name': project['name'],
                        'full_name': project['path_with_namespace'],
                        'description': project.get('description', ''),
                        'web_url': project['web_url'],
                        'default_branch': project.get('default_branch', 'main'),
                        'updated_at': project.get('last_activity_at', '')
                    })
            except KeyError as e:
                app.logger.warning(f"Missing key in project data: {e}")
                continue
        return normalized
    
    def get_project_info(self, project_id: str) -> Optional[Dict]:
        if self.provider == 'github':
            # For GitHub, project_id is owner/repo format
            data = self.make_request(f'/repos/{project_id}')
        elif self.provider == 'gitlab':
            # For GitLab, project_id is numeric
            data = self.make_request(f'/projects/{project_id}')
        
        if data:
            return self.normalize_projects([data])[0]
        return None
    
    def get_branches(self, project_id: str) -> List[Dict]:
        branches = []
        page = 1
        per_page = 100
        
        while True:
            if self.provider == 'github':
                data = self.make_request(f'/repos/{project_id}/branches', {
                    'page': page, 
                    'per_page': per_page
                })
            elif self.provider == 'gitlab':
                data = self.make_request(f'/projects/{project_id}/repository/branches', {
                    'page': page, 
                    'per_page': per_page
                })
            
            if not data or not isinstance(data, list):
                break
            
            branches.extend(data)
            page += 1
            if len(data) < per_page:
                break
        
        return self.normalize_branches(branches)
    
    def normalize_branches(self, branches: List[Dict]) -> List[Dict]:
        normalized = []
        for branch in branches:
            try:
                if self.provider == 'github':
                    normalized.append({
                        'name': branch['name'],
                        'commit': {
                            'id': branch['commit']['sha'],
                            'short_id': branch['commit']['sha'][:8],
                            'created_at': branch['commit'].get('commit', {}).get('author', {}).get('date', '')
                        }
                    })
                elif self.provider == 'gitlab':
                    normalized.append({
                        'name': branch['name'],
                        'commit': {
                            'id': branch['commit']['id'],
                            'short_id': branch['commit']['short_id'],
                            'created_at': branch['commit'].get('created_at', '')
                        }
                    })
            except KeyError as e:
                app.logger.warning(f"Missing key in branch data: {e}")
                continue
        return normalized
    
    def get_release_branches(self, project_id: str) -> List[Dict]:
        all_branches = self.get_branches(project_id)
        release_branches = []
        
        for branch in all_branches:
            branch_name = branch['name']
            if branch_name.startswith('r_') or branch_name.startswith('release/'):
                if branch_name.startswith('r_'):
                    version = branch_name[2:]  # Remove 'r_' prefix
                elif branch_name.startswith('release/'):
                    version = branch_name[8:]  # Remove 'release/' prefix
                else:
                    version = 'Unknown'
                
                branch['version'] = version
                release_branches.append(branch)
        
        # Sort by version (newest first)
        def version_sort_key(branch):
            try:
                parts = branch['version'].split('.')
                return tuple(-int(p) if p.isdigit() else 0 for p in parts)
            except:
                return (0,)
        
        release_branches.sort(key=version_sort_key)
        return release_branches
    
    def get_commits(self, project_id: str, branch_name: str) -> List[Dict]:
        commits = []
        page = 1
        per_page = 100
        
        while True:
            if self.provider == 'github':
                data = self.make_request(f'/repos/{project_id}/commits', {
                    'sha': branch_name,
                    'page': page,
                    'per_page': per_page
                })
            elif self.provider == 'gitlab':
                data = self.make_request(f'/projects/{project_id}/repository/commits', {
                    'ref_name': branch_name,
                    'page': page,
                    'per_page': per_page
                })
            
            if not data or not isinstance(data, list):
                break
            
            commits.extend(data)
            page += 1
            if len(data) < per_page:
                break
        
        return self.normalize_commits(commits)
    
    def normalize_commits(self, commits: List[Dict]) -> List[Dict]:
        normalized = []
        for commit in commits:
            try:
                if self.provider == 'github':
                    commit_data = commit.get('commit', {})
                    author_data = commit_data.get('author', {})
                    normalized.append({
                        'id': commit['sha'],
                        'short_id': commit['sha'][:8],
                        'title': commit_data.get('message', '').split('\n')[0],
                        'message': commit_data.get('message', ''),
                        'author_name': author_data.get('name', ''),
                        'author_email': author_data.get('email', ''),
                        'created_at': author_data.get('date', '')
                    })
                elif self.provider == 'gitlab':
                    normalized.append({
                        'id': commit['id'],
                        'short_id': commit.get('short_id', commit['id'][:8]),
                        'title': commit.get('title', ''),
                        'message': commit.get('message', ''),
                        'author_name': commit.get('author_name', ''),
                        'author_email': commit.get('author_email', ''),
                        'created_at': commit.get('created_at', '')
                    })
            except KeyError as e:
                app.logger.warning(f"Missing key in commit data: {e}")
                continue
        return normalized

# Utility Functions
def get_current_provider() -> Optional[str]:
    return session.get('current_provider')

def get_provider_strategy() -> Optional[ProviderStrategy]:
    provider = get_current_provider()
    if provider and provider in ENABLED_PROVIDERS:
        return ProviderStrategy(provider)
    return None

def categorize_commits(commits: List[Dict]) -> Dict[str, List[Dict]]:
    categories = {
        'feature': [],
        'bug': [],
        'enhancement': [],
        'hotfix': [],
        'maintenance': [],
        'rca': [],
        'other': []
    }
    
    for commit in commits:
        message = commit.get('message', '').lower()
        commit_info = {
            **commit,
            'redmine_no': extract_redmine_no(commit.get('message', '')),
            'impacted_modules': extract_modules(commit.get('message', ''))
        }
        
        # Categorize based on commit message patterns
        if any(pattern in message for pattern in ['#feature', 'feat:', 'feature:']):
            categories['feature'].append(commit_info)
        elif any(pattern in message for pattern in ['#bug', 'fix:', 'bug:']):
            categories['bug'].append(commit_info)
        elif any(pattern in message for pattern in ['#enhancement', 'enhance:', 'enhancement:']):
            categories['enhancement'].append(commit_info)
        elif any(pattern in message for pattern in ['#hotfix', 'hotfix:']):
            categories['hotfix'].append(commit_info)
        elif any(pattern in message for pattern in ['#maintenance', 'maint:', 'maintenance:']):
            categories['maintenance'].append(commit_info)
        elif any(pattern in message for pattern in ['#rca', 'rca:']):
            categories['rca'].append(commit_info)
        else:
            categories['other'].append(commit_info)
    
    return categories

def extract_redmine_no(message: str) -> str:
    if not message:
        return ''
    patterns = [r'RM[-\s]?(\d+)', r'#(\d+)', r'redmine[-\s]?(\d+)']
    for pattern in patterns:
        match = re.search(pattern, message, re.IGNORECASE)
        if match:
            return match.group(1)
    return ''

def extract_modules(message: str) -> str:
    if not message:
        return ''
    patterns = [r'@([a-zA-Z0-9_-]+)', r'\[([a-zA-Z0-9_-]+)\]']
    modules = []
    for pattern in patterns:
        matches = re.findall(pattern, message)
        modules.extend(matches)
    return ', '.join(modules)

# Routes
@app.route('/')
def index():
    # Check if user is already logged in
    for provider in ENABLED_PROVIDERS.keys():
        if f'{provider}_token' in session:
            return redirect(url_for('projects'))
    
    return render_template('index.html', providers=ENABLED_PROVIDERS)

@app.route('/login/<provider>')
def login(provider):
    if provider not in oauth_providers:
        flash(f'{provider.title()} authentication is not configured.', 'error')
        return redirect(url_for('index'))
    
    redirect_uri = url_for('authorized', provider=provider, _external=True)
    return oauth_providers[provider].authorize_redirect(redirect_uri)

@app.route('/login/<provider>/authorized')
def authorized(provider):
    if provider not in oauth_providers:
        flash('Invalid authentication provider.', 'error')
        return redirect(url_for('index'))
    
    try:
        token = oauth_providers[provider].authorize_access_token()
        if not token or 'access_token' not in token:
            flash('Authentication failed. Please try again.', 'error')
            return redirect(url_for('index'))
        
        session[f'{provider}_token'] = token['access_token']
        session['current_provider'] = provider
        
        # Get and store user information
        strategy = ProviderStrategy(provider)
        user_info = strategy.get_user_info()
        
        if user_info:
            # Store user in database
            provider_id = str(user_info.get('id'))
            user = User.query.filter_by(
                provider=provider,
                provider_id=provider_id
            ).first()
            
            if not user:
                user = User(
                    provider=provider,
                    provider_id=provider_id,
                    username=user_info.get('login') or user_info.get('username', ''),
                    email=user_info.get('email', ''),
                    name=user_info.get('name', '')
                )
                db.session.add(user)
                db.session.commit()
            
            session['user_id'] = user.id
            session['user_name'] = user.name or user.username
            
            flash(f'Successfully logged in with {ENABLED_PROVIDERS[provider]["name"]}!', 'success')
            return redirect(url_for('projects'))
        else:
            flash('Failed to get user information. Please try again.', 'error')
    
    except Exception as e:
        app.logger.error(f'Authentication error: {str(e)}')
        flash('Authentication failed. Please try again.', 'error')
    
    return redirect(url_for('index'))

@app.route('/logout')
def logout():
    provider = session.get('current_provider')
    session.clear()
    
    provider_name = ENABLED_PROVIDERS.get(provider, {}).get('name', 'the service') if provider else 'the service'
    flash(f'You have been logged out from {provider_name}.', 'info')
    return redirect(url_for('index'))

@app.route('/projects')
def projects():
    strategy = get_provider_strategy()
    if not strategy:
        flash('Please log in first.', 'warning')
        return redirect(url_for('index'))
    
    try:
        projects = strategy.get_user_projects()
        provider_name = ENABLED_PROVIDERS[get_current_provider()]['name']
        
        return render_template('projects.html', 
                              projects=projects, 
                              provider=get_current_provider(),
                              provider_name=provider_name)
    except Exception as e:
        app.logger.error(f"Error fetching projects: {e}")
        flash('Error fetching projects. Please try again.', 'error')
        return redirect(url_for('index'))

@app.route('/project/<path:project_id>')
def project_details(project_id):
    strategy = get_provider_strategy()
    if not strategy:
        flash('Please log in first.', 'warning')
        return redirect(url_for('index'))
    
    try:
        project_info = strategy.get_project_info(project_id)
        if not project_info:
            flash('Project not found.', 'error')
            return redirect(url_for('projects'))
        
        release_branches = strategy.get_release_branches(project_id)
        return render_template('project_details.html',
                              project=project_info,
                              release_branches=release_branches,
                              provider=get_current_provider())
    except Exception as e:
        app.logger.error(f"Error fetching project details: {e}")
        flash('Error fetching project details. Please try again.', 'error')
        return redirect(url_for('projects'))

@app.route('/prepare_release/<path:project_id>/<branch_name>')
def prepare_release(project_id, branch_name):
    strategy = get_provider_strategy()
    if not strategy:
        flash('Please log in first.', 'warning')
        return redirect(url_for('index'))
    
    try:
        project_info = strategy.get_project_info(project_id)
        if not project_info:
            flash('Project not found.', 'error')
            return redirect(url_for('projects'))
        
        commits = strategy.get_commits(project_id, branch_name)
        
        # Extract version from branch name
        if 'r_' in branch_name:
            version = branch_name.split('r_')[1]
        elif 'release/' in branch_name:
            version = branch_name.split('release/')[1]
        else:
            version = 'Unknown'
        
        categorized_commits = categorize_commits(commits)
        
        release_info = {
            'version': version,
            'team_name': project_info.get('name', ''),
            'dev_start_date': commits[-1]['created_at'][:10] if commits else '',
            'dev_end_date': commits[0]['created_at'][:10] if commits else '',
            'git_version': commits[0]['id'] if commits else '',
            'git_checksum': commits[0]['id'] if commits else ''
        }
        
        return render_template('prepare_release.html',
                              project=project_info,
                              branch_name=branch_name,
                              release_info=release_info,
                              commits=commits,
                              categorized_commits=categorized_commits,
                              provider=get_current_provider())
    except Exception as e:
        app.logger.error(f"Error preparing release: {e}")
        flash('Error preparing release. Please try again.', 'error')
        return redirect(url_for('projects'))

@app.route('/generate_release_note', methods=['POST'])
def generate_release_note():
    if 'user_id' not in session:
        flash('Please log in first.', 'warning')
        return redirect(url_for('index'))
    
    try:
        project_id = request.form.get('project_id')
        branch_name = request.form.get('branch_name')
        project_name = request.form.get('project_name', '')
        
        data = {
            'team_name': request.form.get('team_name', ''),
            'release_version': request.form.get('release_version', ''),
            'platform_details': request.form.get('platform_details', ''),
            'git_version': request.form.get('git_version', ''),
            'git_checksum': request.form.get('git_checksum', ''),
            'build_checksum': request.form.get('build_checksum', ''),
            'dev_start_date': request.form.get('dev_start_date', ''),
            'dev_end_date': request.form.get('dev_end_date', ''),
            'release_by': request.form.get('release_by', ''),
            'reviewed_by': request.form.get('reviewed_by', ''),
            'technical_changes': request.form.get('technical_changes', ''),
            'extra_checkpoints': request.form.get('extra_checkpoints', ''),
            'categories': {
                'feature': json.loads(request.form.get('features_json', '[]')),
                'bug': json.loads(request.form.get('bugs_json', '[]')),
                'enhancement': json.loads(request.form.get('enhancements_json', '[]')),
                'hotfix': json.loads(request.form.get('hotfixes_json', '[]')),
                'maintenance': json.loads(request.form.get('maintenance_json', '[]')),
                'rca': request.form.get('rca', '')
            }
        }
        
        # Generate PDF
        pdf_data = generate_release_note_pdf(data)
        
        # Determine file extension and MIME type based on what was generated
        if isinstance(pdf_data, bytes) and pdf_data.startswith(b'%PDF'):
            # It's a real PDF
            file_extension = 'pdf'
            mime_type = 'application/pdf'
        else:
            # It's HTML fallback
            file_extension = 'html'
            mime_type = 'text/html'
        
        # Save to database
        release_note = ReleaseNote(
            user_id=session['user_id'],
            provider=get_current_provider(),
            project_id=project_id,
            project_name=project_name,
            branch_name=branch_name,
            version=data['release_version'],
            team_name=data['team_name'],
            release_data=json.dumps(data)
        )
        db.session.add(release_note)
        db.session.commit()
        
        return send_file(
            BytesIO(pdf_data),
            mimetype=mime_type,
            download_name=f"{data['team_name']}_release_note_{data['release_version']}.{file_extension}",
            as_attachment=True
        )
    except Exception as e:
        app.logger.error(f"Error generating release note: {e}")
        flash('Error generating release note. Please try again.', 'error')
        return redirect(url_for('projects'))

@app.route('/history')
def release_history():
    if 'user_id' not in session:
        flash('Please log in first.', 'warning')
        return redirect(url_for('index'))
    
    releases = ReleaseNote.query.filter_by(user_id=session['user_id']).order_by(ReleaseNote.release_date.desc()).all()
    return render_template('history.html', releases=releases)

@app.route('/view_release/<int:release_id>')
def view_release(release_id):
    if 'user_id' not in session:
        flash('Please log in first.', 'warning')
        return redirect(url_for('index'))
    
    release = ReleaseNote.query.filter_by(id=release_id, user_id=session['user_id']).first()
    if not release:
        flash('Release note not found.', 'error')
        return redirect(url_for('release_history'))
    
    try:
        data = json.loads(release.release_data)
        pdf = generate_release_note_pdf(data)
        
        return send_file(
            BytesIO(pdf),
            mimetype='application/pdf',
            download_name=f"{release.team_name}_release_note_{release.version}.pdf"
        )
    except Exception as e:
        app.logger.error(f"Error viewing release: {e}")
        flash('Error viewing release note. Please try again.', 'error')
        return redirect(url_for('release_history'))

@app.route('/api/project/<path:project_id>/branches')
def get_all_branches_api(project_id):
    strategy = get_provider_strategy()
    if not strategy:
        return jsonify({'error': 'Authentication required'}), 401
    
    try:
        branches = strategy.get_branches(project_id)
        return jsonify(branches)
    except Exception as e:
        app.logger.error(f"Error fetching branches: {e}")
        return jsonify({'error': 'Failed to fetch branches'}), 500

def generate_release_note_pdf(data: Dict) -> bytes:
    """Generate a PDF release note document."""
    try:
        # Try WeasyPrint first
        from weasyprint import HTML, CSS
        from weasyprint.text.fonts import FontConfiguration
        
        with tempfile.NamedTemporaryFile(suffix='.html', delete=False) as temp_html:
            html_content = render_template('release_note_pdf.html', data=data)
            temp_html.write(html_content.encode('utf-8'))
            temp_html_path = temp_html.name
        
        font_config = FontConfiguration()
        css = CSS(string='''
            @page { 
                margin: 1cm; 
                size: A4;
                @bottom-center {
                    content: "Page " counter(page) " of " counter(pages);
                    font-size: 10px;
                    color: #666;
                }
            }
            body { 
                font-family: Arial, sans-serif; 
                font-size: 12px; 
                line-height: 1.4; 
                color: #333;
                margin: 0;
                padding: 0;
            }
            h1 { 
                font-size: 24px; 
                text-align: center; 
                margin-bottom: 20px; 
                color: #2c3e50; 
                border-bottom: 3px solid #3498db;
                padding-bottom: 10px;
            }
            h2 { 
                font-size: 18px; 
                margin-top: 25px; 
                margin-bottom: 15px; 
                background: linear-gradient(90deg, #3498db, #2980b9);
                color: white;
                padding: 8px 12px;
                border-radius: 4px;
            }
            h3 { 
                font-size: 16px; 
                margin-top: 20px; 
                margin-bottom: 10px; 
                color: #2c3e50;
                border-left: 4px solid #3498db;
                padding-left: 10px;
                background-color: #f8f9fa;
                padding: 8px 8px 8px 15px;
            }
            table { 
                width: 100%; 
                border-collapse: collapse; 
                margin-bottom: 20px;
                box-shadow: 0 2px 4px rgba(0,0,0,0.1);
            }
            th, td { 
                border: 1px solid #ddd; 
                padding: 10px 8px; 
                text-align: left;
                vertical-align: top;
            }
            th { 
                background: linear-gradient(90deg, #34495e, #2c3e50);
                color: white;
                font-weight: bold;
                font-size: 11px;
                text-transform: uppercase;
                letter-spacing: 0.5px;
            }
            .metadata th { 
                background: linear-gradient(90deg, #2980b9, #3498db);
                width: 25%; 
                font-size: 12px;
                text-transform: none;
                letter-spacing: normal;
            }
            .metadata td { 
                background-color: #f8f9fa;
                font-weight: 500;
            }
            tr:nth-child(even) td {
                background-color: #f9f9f9;
            }
            tr:hover td {
                background-color: #e8f4f8;
            }
            .section-content {
                margin-bottom: 25px;
            }
            .empty-section {
                font-style: italic;
                color: #7f8c8d;
                padding: 15px;
                background-color: #ecf0f1;
                border-radius: 4px;
                text-align: center;
            }
            code {
                background-color: #f1f2f6;
                padding: 2px 4px;
                border-radius: 3px;
                font-family: 'Courier New', monospace;
                font-size: 11px;
            }
        ''', font_config=font_config)
        
        pdf_buffer = BytesIO()
        HTML(filename=temp_html_path).write_pdf(pdf_buffer, stylesheets=[css], font_config=font_config)
        os.unlink(temp_html_path)
        
        pdf_buffer.seek(0)
        return pdf_buffer.getvalue()
    
    except Exception as weasy_error:
        # Fallback to reportlab if WeasyPrint fails
        app.logger.warning(f"WeasyPrint failed: {weasy_error}")
        app.logger.info("Falling back to ReportLab PDF generation")
        
        try:
            return generate_simple_pdf_with_reportlab(data)
        except ImportError:
            app.logger.error("ReportLab not available, trying xhtml2pdf")
            try:
                return generate_pdf_with_xhtml2pdf(data)
            except ImportError:
                # Final fallback - return HTML as text file
                app.logger.error("No PDF libraries available, returning HTML")
                return generate_html_fallback(data)

def generate_simple_pdf_with_reportlab(data: Dict) -> bytes:
    """Generate PDF using ReportLab (simpler, fewer dependencies)."""
    from reportlab.lib.pagesizes import letter, A4
    from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle
    from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
    from reportlab.lib.units import inch
    from reportlab.lib import colors
    
    buffer = BytesIO()
    doc = SimpleDocTemplate(buffer, pagesize=A4, rightMargin=72, leftMargin=72,
                           topMargin=72, bottomMargin=18)
    
    # Get styles
    styles = getSampleStyleSheet()
    title_style = ParagraphStyle(
        'CustomTitle',
        parent=styles['Heading1'],
        fontSize=24,
        spaceAfter=30,
        alignment=1,  # Center
        textColor=colors.HexColor('#2c3e50')
    )
    
    heading_style = ParagraphStyle(
        'CustomHeading',
        parent=styles['Heading2'],
        fontSize=16,
        spaceAfter=12,
        textColor=colors.HexColor('#34495e'),
        backColor=colors.HexColor('#ecf0f1'),
        leftIndent=10,
        spaceBefore=20
    )
    
    # Build the document
    story = []
    
    # Title
    story.append(Paragraph("Release Note", title_style))
    story.append(Spacer(1, 20))
    
    # Metadata table
    metadata_data = [
        ['Team Name', data.get('team_name', '')],
        ['Release Version', data.get('release_version', '')],
        ['Platform Details', data.get('platform_details', '')],
        ['Git Version', data.get('git_version', '')],
        ['Git Checksum', data.get('git_checksum', '')],
        ['Build Checksum', data.get('build_checksum', '')],
        ['Development Start Date', data.get('dev_start_date', '')],
        ['Development End Date', data.get('dev_end_date', '')],
        ['Release By', data.get('release_by', '')],
        ['Reviewed By', data.get('reviewed_by', '')],
    ]
    
    metadata_table = Table(metadata_data, colWidths=[2*inch, 4*inch])
    metadata_table.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (0, -1), colors.HexColor('#3498db')),
        ('TEXTCOLOR', (0, 0), (0, -1), colors.whitesmoke),
        ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
        ('FONTNAME', (0, 0), (0, -1), 'Helvetica-Bold'),
        ('FONTSIZE', (0, 0), (-1, -1), 10),
        ('GRID', (0, 0), (-1, -1), 1, colors.black),
        ('VALIGN', (0, 0), (-1, -1), 'TOP'),
    ]))
    
    story.append(metadata_table)
    story.append(Spacer(1, 30))
    
    # Release Details
    story.append(Paragraph("List of Release Details", heading_style))
    story.append(Spacer(1, 15))
    
    # Add each category
    categories = [
        ('rca', 'RCA'),
        ('hotfix', 'Hot Fixed'),
        ('maintenance', 'Maintenance Fixed'),
        ('feature', 'Feature'),
        ('enhancement', 'Enhancement'),
        ('bug', 'Bug Fixed')
    ]
    
    for category_id, category_name in categories:
        if category_id == 'rca':
            rca_content = data.get('categories', {}).get('rca', '')
            if rca_content:
                story.append(Paragraph(f"#{category_name}", heading_style))
                story.append(Paragraph(rca_content, styles['Normal']))
                story.append(Spacer(1, 15))
        else:
            items = data.get('categories', {}).get(category_id, [])
            if items:
                story.append(Paragraph(f"#{category_name}", heading_style))
                
                # Create table for items
                table_data = [['Redmine No', 'Description', 'Impacted Modules', 'Developed By']]
                for item in items:
                    table_data.append([
                        item.get('redmine_no', ''),
                        item.get('title', ''),
                        item.get('impacted_modules', ''),
                        item.get('author_name', '')
                    ])
                
                items_table = Table(table_data, colWidths=[1*inch, 2.5*inch, 1.5*inch, 1.5*inch])
                items_table.setStyle(TableStyle([
                    ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#34495e')),
                    ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
                    ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
                    ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
                    ('FONTSIZE', (0, 0), (-1, -1), 9),
                    ('GRID', (0, 0), (-1, -1), 1, colors.black),
                    ('VALIGN', (0, 0), (-1, -1), 'TOP'),
                    ('ROWBACKGROUNDS', (0, 1), (-1, -1), [colors.white, colors.HexColor('#f9f9f9')])
                ]))
                
                story.append(items_table)
                story.append(Spacer(1, 15))
    
    # Technical Changes
    tech_changes = data.get('technical_changes', '')
    if tech_changes:
        story.append(Paragraph("#Technical Changes", heading_style))
        story.append(Paragraph(tech_changes, styles['Normal']))
        story.append(Spacer(1, 15))
    
    # Extra Checkpoints
    extra_checkpoints = data.get('extra_checkpoints', '')
    if extra_checkpoints:
        story.append(Paragraph("Extra Checkpoints", heading_style))
        story.append(Paragraph(extra_checkpoints, styles['Normal']))
    
    # Build PDF
    doc.build(story)
    buffer.seek(0)
    return buffer.getvalue()

def generate_pdf_with_xhtml2pdf(data: Dict) -> bytes:
    """Generate PDF using xhtml2pdf (lightweight alternative)."""
    from xhtml2pdf import pisa
    
    # Generate HTML content
    html_content = render_template('release_note_pdf.html', data=data)
    
    # Create PDF
    result = BytesIO()
    pdf = pisa.pisaDocument(BytesIO(html_content.encode('utf-8')), result)
    
    if not pdf.err:
        result.seek(0)
        return result.getvalue()
    else:
        raise Exception("PDF generation failed with xhtml2pdf")

def generate_html_fallback(data: Dict) -> bytes:
    """Generate HTML file as fallback when no PDF library works."""
    html_content = f"""
    <!DOCTYPE html>
    <html>
    <head>
        <title>Release Note - {data.get('team_name', '')} v{data.get('release_version', '')}</title>
        <style>
            body {{ font-family: Arial, sans-serif; margin: 40px; }}
            h1 {{ color: #2c3e50; border-bottom: 2px solid #3498db; }}
            h2 {{ color: #34495e; background: #ecf0f1; padding: 8px; }}
            table {{ border-collapse: collapse; width: 100%; margin: 20px 0; }}
            th, td {{ border: 1px solid #ddd; padding: 8px; text-align: left; }}
            th {{ background: #34495e; color: white; }}
        </style>
    </head>
    <body>
        {render_template('release_note_pdf.html', data=data)}
        <p><em>Note: This is an HTML version. PDF generation is currently unavailable.</em></p>
    </body>
    </html>
    """
    return html_content.encode('utf-8')

# Error handlers
@app.errorhandler(404)
def not_found_error(error):
    return render_template('errors/404.html'), 404

@app.errorhandler(500)
def internal_error(error):
    db.session.rollback()
    return render_template('errors/500.html'), 500

@app.errorhandler(403)
def forbidden_error(error):
    return render_template('errors/403.html'), 403

# Health check endpoint
@app.route('/health')
def health_check():
    return jsonify({
        'status': 'healthy',
        'providers': list(ENABLED_PROVIDERS.keys()),
        'database': 'connected'
    })

# CLI commands for database management
@app.cli.command()
def init_db():
    """Initialize the database."""
    db.create_all()
    print('Database initialized successfully.')

@app.cli.command()
def reset_db():
    """Reset the database (WARNING: This will delete all data)."""
    db.drop_all()
    db.create_all()
    print('Database reset successfully.')

if __name__ == '__main__':
    with app.app_context():
        try:
            db.create_all()
            print("✅ Database tables created successfully")
        except Exception as e:
            print(f"❌ Error creating database tables: {e}")
    
    # Check if any providers are configured
    if not ENABLED_PROVIDERS:
        print("\n⚠️  WARNING: No authentication providers are configured!")
        print("Please set environment variables for at least one provider:")
        print("- GitHub: GITHUB_ENABLED=true, GITHUB_CLIENT_ID, GITHUB_CLIENT_SECRET")
        print("- GitLab: GITLAB_ENABLED=true, GITLAB_CLIENT_ID, GITLAB_CLIENT_SECRET")
        print("\nCheck your .env file and make sure it's in the same directory as this script.")
        print("Refer to .env.sample for the correct format.")
    else:
        print(f"\n🚀 Configured providers: {', '.join(ENABLED_PROVIDERS.keys())}")
        print("Ready to start!")
    
    debug_mode = get_bool_env('DEBUG', 'false')
    port = int(os.environ.get('PORT', 3000))
    
    print(f"\n🌐 Starting application on http://localhost:{port}")
    print(f"🔧 Debug mode: {'ON' if debug_mode else 'OFF'}")
    print("🛑 Press Ctrl+C to stop the application")
    print("-" * 50)
    
    try:
        app.run(host='0.0.0.0', port=port, debug=debug_mode)
    except KeyboardInterrupt:
        print("\n👋 Application stopped by user")
    except Exception as e:
        print(f"\n❌ Error starting application: {e}")
