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

# Suppress SSL warnings for development
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# Initialize Flask application
app = Flask(__name__)
app.secret_key = os.environ.get('SECRET_KEY', 'dev-secret-key-change-in-production')
app.config['SQLALCHEMY_DATABASE_URI'] = os.environ.get('DATABASE_URL', 'sqlite:///releases.db')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

# Provider Configuration
PROVIDERS_CONFIG = {
    'github': {
        'enabled': os.environ.get('GITHUB_ENABLED', 'true').lower() == 'true',
        'client_id': os.environ.get('GITHUB_CLIENT_ID','Ov23liaq1TnJ0byQTTLC'),
        'client_secret': os.environ.get('GITHUB_CLIENT_SECRET','07e36bfd8bcc9d3b9a92adc83cae87e8675853eb'),
        'api_base_url': 'https://api.github.com/',
        'access_token_url': 'https://github.com/login/oauth/access_token',
        'authorize_url': 'https://github.com/login/oauth/authorize',
        'scope': 'repo user:email',
        'name': 'GitHub'
    },
    'gitlab': {
        'enabled': os.environ.get('GITLAB_ENABLED', 'true').lower() == 'true',
        'client_id': os.environ.get('GITLAB_CLIENT_ID','test'),
        'client_secret': os.environ.get('GITLAB_CLIENT_SECRET','test'),
        'api_base_url': os.environ.get('GITLAB_URL', 'https://gitlab.com') + '/api/v4/',
        'access_token_url': os.environ.get('GITLAB_URL', 'https://gitlab.com') + '/oauth/token',
        'authorize_url': os.environ.get('GITLAB_URL', 'https://gitlab.com') + '/oauth/authorize',
        'scope': 'api read_user read_repository',
        'name': 'GitLab',
        'verify_ssl': os.environ.get('GITLAB_VERIFY_SSL', 'true').lower() == 'true'
    },
    'google': {
        'enabled': os.environ.get('GOOGLE_ENABLED', 'false').lower() == 'true',
        'client_id': os.environ.get('GOOGLE_CLIENT_ID'),
        'client_secret': os.environ.get('GOOGLE_CLIENT_SECRET'),
        'api_base_url': 'https://www.googleapis.com/',
        'access_token_url': 'https://oauth2.googleapis.com/token',
        'authorize_url': 'https://accounts.google.com/o/oauth2/v2/auth',
        'scope': 'openid email profile',
        'name': 'Google'
    }
}

print(f"this is os.environ: ",  os.environ.get('GITHUB_CLIENT_ID'))

# Get enabled providers
ENABLED_PROVIDERS = {k: v for k, v in PROVIDERS_CONFIG.items() if v['enabled'] and v['client_id'] and v['client_secret']}

# Initialize database
db = SQLAlchemy(app)

# Initialize OAuth
oauth = OAuth(app)

# Register OAuth providers dynamically
oauth_providers = {}
for provider_key, config in ENABLED_PROVIDERS.items():
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

# Configure requests session
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
            response = requests_session.get(url, headers=headers, params=params or {})
            if response.status_code == 200:
                return response.json()
            else:
                app.logger.error(f"API request failed: {response.status_code} - {response.text}")
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
                data = self.make_request('/user/repos', {'page': page, 'per_page': per_page, 'sort': 'updated'})
            elif self.provider == 'gitlab':
                data = self.make_request('/projects', {'membership': True, 'page': page, 'per_page': per_page})
            
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
            if self.provider == 'github':
                normalized.append({
                    'id': project['id'],
                    'name': project['name'],
                    'full_name': project['full_name'],
                    'description': project.get('description', ''),
                    'web_url': project['html_url'],
                    'default_branch': project['default_branch'],
                    'updated_at': project['updated_at']
                })
            elif self.provider == 'gitlab':
                normalized.append({
                    'id': project['id'],
                    'name': project['name'],
                    'full_name': project['path_with_namespace'],
                    'description': project.get('description', ''),
                    'web_url': project['web_url'],
                    'default_branch': project['default_branch'],
                    'updated_at': project['last_activity_at']
                })
        return normalized
    
    def get_project_info(self, project_id: str) -> Optional[Dict]:
        if self.provider == 'github':
            data = self.make_request(f'/repos/{project_id}')
        elif self.provider == 'gitlab':
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
                # For GitHub, project_id is owner/repo format
                data = self.make_request(f'/repos/{project_id}/branches', {'page': page, 'per_page': per_page})
            elif self.provider == 'gitlab':
                data = self.make_request(f'/projects/{project_id}/repository/branches', {'page': page, 'per_page': per_page})
            
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
            normalized.append({
                'name': branch['name'],
                'commit_id': branch['commit']['sha'] if self.provider == 'github' else branch['commit']['id'],
                'commit_message': branch['commit'].get('commit', {}).get('message', '') if self.provider == 'github' else branch['commit'].get('message', '')
            })
        return normalized
    
    def get_release_branches(self, project_id: str) -> List[Dict]:
        all_branches = self.get_branches(project_id)
        release_branches = [b for b in all_branches if b['name'].startswith('r_') or b['name'].startswith('release/')]
        
        for branch in release_branches:
            if branch['name'].startswith('r_'):
                branch['version'] = branch['name'].split('r_')[1]
            elif branch['name'].startswith('release/'):
                branch['version'] = branch['name'].split('release/')[1]
            else:
                branch['version'] = 'Unknown'
        
        # Sort by version
        def version_key(branch):
            parts = branch['version'].split('.')
            return [-int(p) if p.isdigit() else 0 for p in parts]
        
        release_branches.sort(key=version_key)
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
            if self.provider == 'github':
                normalized.append({
                    'id': commit['sha'],
                    'short_id': commit['sha'][:8],
                    'title': commit['commit']['message'].split('\n')[0],
                    'message': commit['commit']['message'],
                    'author_name': commit['commit']['author']['name'],
                    'author_email': commit['commit']['author']['email'],
                    'created_at': commit['commit']['author']['date']
                })
            elif self.provider == 'gitlab':
                normalized.append({
                    'id': commit['id'],
                    'short_id': commit['short_id'],
                    'title': commit['title'],
                    'message': commit['message'],
                    'author_name': commit['author_name'],
                    'author_email': commit['author_email'],
                    'created_at': commit['created_at']
                })
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
        message = commit['message'].lower()
        commit_info = {
            **commit,
            'redmine_no': extract_redmine_no(commit['message']),
            'impacted_modules': extract_modules(commit['message'])
        }
        
        if '#feature' in message or 'feat:' in message:
            categories['feature'].append(commit_info)
        elif '#bug' in message or 'fix:' in message:
            categories['bug'].append(commit_info)
        elif '#enhancement' in message or 'enhance:' in message:
            categories['enhancement'].append(commit_info)
        elif '#hotfix' in message or 'hotfix:' in message:
            categories['hotfix'].append(commit_info)
        elif '#maintenance' in message or 'maint:' in message:
            categories['maintenance'].append(commit_info)
        elif '#rca' in message or 'rca:' in message:
            categories['rca'].append(commit_info)
        else:
            categories['other'].append(commit_info)
    
    return categories

def extract_redmine_no(message: str) -> str:
    patterns = [r'RM[-\s]?(\d+)', r'#(\d+)', r'redmine[-\s]?(\d+)']
    for pattern in patterns:
        match = re.search(pattern, message, re.IGNORECASE)
        if match:
            return match.group(1)
    return ''

def extract_modules(message: str) -> str:
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
            user = User.query.filter_by(
                provider=provider,
                provider_id=str(user_info.get('id'))
            ).first()
            
            if not user:
                user = User(
                    provider=provider,
                    provider_id=str(user_info.get('id')),
                    username=user_info.get('login') or user_info.get('username'),
                    email=user_info.get('email'),
                    name=user_info.get('name')
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
    
    projects = strategy.get_user_projects()
    provider_name = ENABLED_PROVIDERS[get_current_provider()]['name']
    
    return render_template('projects.html', 
                          projects=projects, 
                          provider=get_current_provider(),
                          provider_name=provider_name)

@app.route('/project/<path:project_id>')
def project_details(project_id):
    strategy = get_provider_strategy()
    if not strategy:
        flash('Please log in first.', 'warning')
        return redirect(url_for('index'))
    
    project_info = strategy.get_project_info(project_id)
    if not project_info:
        flash('Project not found.', 'error')
        return redirect(url_for('projects'))
    
    release_branches = strategy.get_release_branches(project_id)
    return render_template('project_details.html',
                          project=project_info,
                          release_branches=release_branches,
                          provider=get_current_provider())

@app.route('/prepare_release/<path:project_id>/<branch_name>')
def prepare_release(project_id, branch_name):
    strategy = get_provider_strategy()
    if not strategy:
        flash('Please log in first.', 'warning')
        return redirect(url_for('index'))
    
    project_info = strategy.get_project_info(project_id)
    if not project_info:
        flash('Project not found.', 'error')
        return redirect(url_for('projects'))
    
    commits = strategy.get_commits(project_id, branch_name)
    version = branch_name.split('r_')[1] if 'r_' in branch_name else branch_name.split('release/')[1] if 'release/' in branch_name else 'Unknown'
    categorized_commits = categorize_commits(commits)
    
    release_info = {
        'version': version,
        'team_name': project_info.get('name', ''),
        'dev_start_date': commits[-1]['created_at'].split('T')[0] if commits else '',
        'dev_end_date': commits[0]['created_at'].split('T')[0] if commits else '',
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

@app.route('/generate_release_note', methods=['POST'])
def generate_release_note():
    if 'user_id' not in session:
        flash('Please log in first.', 'warning')
        return redirect(url_for('index'))
    
    project_id = request.form.get('project_id')
    branch_name = request.form.get('branch_name')
    project_name = request.form.get('project_name', '')
    
    data = {
        'team_name': request.form.get('team_name', ''),
        'release_version': request.form.get('release_version', ''),
        'platform_details': request.form.get('platform_details', ''),
        'redmine_target': request.form.get('redmine_target', ''),
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
    
    # Generate PDF (you'll need to implement this function)
    pdf = generate_release_note_pdf(data)
    
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
        BytesIO(pdf),
        mimetype='application/pdf',
        download_name=f"{data['team_name']}_release_note_{data['release_version']}.pdf",
        as_attachment=True
    )

@app.route('/history')
def release_history():
    if 'user_id' not in session:
        flash('Please log in first.', 'warning')
        return redirect(url_for('index'))
    
    releases = ReleaseNote.query.filter_by(user_id=session['user_id']).order_by(ReleaseNote.release_date.desc()).all()
    return render_template('history.html', releases=releases)

@app.route('/api/project/<path:project_id>/branches')
def get_all_branches_api(project_id):
    strategy = get_provider_strategy()
    if not strategy:
        return jsonify({'error': 'Authentication required'}), 401
    
    branches = strategy.get_branches(project_id)
    return jsonify(branches)

def generate_release_note_pdf(data: Dict) -> bytes:
    """Generate a PDF release note document."""
    try:
        from weasyprint import HTML, CSS
        from weasyprint.text.fonts import FontConfiguration
        
        with tempfile.NamedTemporaryFile(suffix='.html', delete=False) as temp_html:
            html_content = render_template('release_note_pdf.html', data=data)
            temp_html.write(html_content.encode('utf-8'))
            temp_html_path = temp_html.name
        
        font_config = FontConfiguration()
        css = CSS(string='''
            @page { margin: 1cm; }
            body { font-family: Arial, sans-serif; font-size: 12px; line-height: 1.4; }
            h1 { font-size: 24px; text-align: center; margin-bottom: 20px; }
            h2 { font-size: 18px; margin-top: 20px; margin-bottom: 10px; background-color: #f0f0f0; padding: 5px; }
            h3 { font-size: 16px; margin-top: 15px; margin-bottom: 8px; border-bottom: 1px solid #ddd; }
            table { width: 100%; border-collapse: collapse; margin-bottom: 20px; }
            th, td { border: 1px solid #ddd; padding: 8px; text-align: left; }
            th { background-color: #f0f0f0; font-weight: bold; }
        ''', font_config=font_config)
        
        pdf_buffer = BytesIO()
        HTML(filename=temp_html_path).write_pdf(pdf_buffer, stylesheets=[css], font_config=font_config)
        os.unlink(temp_html_path)
        
        pdf_buffer.seek(0)
        return pdf_buffer.getvalue()
    
    except ImportError:
        # Fallback to simple text-based PDF or error
        raise Exception("WeasyPrint not installed. Please install weasyprint package for PDF generation.")

if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    
    # Check if any providers are configured
    if not ENABLED_PROVIDERS:
        print("⚠️  WARNING: No authentication providers are configured!")
        print("Please set environment variables for at least one provider:")
        print("- GitHub: GITHUB_ENABLED=true, GITHUB_CLIENT_ID, GITHUB_CLIENT_SECRET")
        print("- GitLab: GITLAB_ENABLED=true, GITLAB_CLIENT_ID, GITLAB_CLIENT_SECRET")
        print("- Google: GOOGLE_ENABLED=true, GOOGLE_CLIENT_ID, GOOGLE_CLIENT_SECRET")
    else:
        print(f"🚀 Configured providers: {', '.join(ENABLED_PROVIDERS.keys())}")
    
    app.run(host='0.0.0.0', port=int(os.environ.get('PORT', 3000)), debug=os.environ.get('DEBUG', 'false').lower() == 'true')