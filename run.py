#!/usr/bin/env python3
"""
Release Notes Generator - Startup Script
This script provides a simple way to run the application with proper error handling.
"""

import os
import sys
import subprocess
from pathlib import Path

def check_python_version():
    """Check if Python version is supported."""
    if sys.version_info < (3, 8):
        print("❌ Error: Python 3.8 or higher is required.")
        print(f"Current version: {sys.version}")
        sys.exit(1)
    print(f"✅ Python version: {sys.version.split()[0]}")

def load_env_file():
    """Load environment variables from .env file."""
    env_file = Path('.env')
    if not env_file.exists():
        print("❌ Error: .env file not found!")
        print("Please copy .env.sample to .env and configure your OAuth credentials.")
        return False
    
    # Load the .env file manually
    env_vars = {}
    try:
        with open(env_file, 'r') as f:
            for line_num, line in enumerate(f, 1):
                line = line.strip()
                # Skip empty lines and comments
                if not line or line.startswith('#'):
                    continue
                
                # Parse key=value pairs
                if '=' in line:
                    key, value = line.split('=', 1)
                    key = key.strip()
                    value = value.strip()
                    
                    # Remove quotes if present
                    if value.startswith('"') and value.endswith('"'):
                        value = value[1:-1]
                    elif value.startswith("'") and value.endswith("'"):
                        value = value[1:-1]
                    
                    env_vars[key] = value
                    # Set in os.environ so the main app can use it
                    os.environ[key] = value
    
    except Exception as e:
        print(f"❌ Error reading .env file: {e}")
        return False
    
    print(f"📄 Loaded {len(env_vars)} environment variables from .env file")
    return env_vars

def check_env_configuration(env_vars):
    """Check if environment configuration is valid."""
    
    # Check SECRET_KEY
    secret_key = env_vars.get('SECRET_KEY', '')
    if not secret_key or secret_key == 'your-super-secret-key-change-this-in-production':
        print("⚠️  Warning: SECRET_KEY is using default value, consider changing it for production")
    
    # Check provider configurations
    github_enabled = env_vars.get('GITHUB_ENABLED', 'false').lower() in ('true', '1', 'yes', 'on')
    gitlab_enabled = env_vars.get('GITLAB_ENABLED', 'false').lower() in ('true', '1', 'yes', 'on')
    
    print(f"🔧 GitHub enabled: {github_enabled}")
    print(f"🔧 GitLab enabled: {gitlab_enabled}")
    
    if not github_enabled and not gitlab_enabled:
        print("❌ Error: No providers are enabled!")
        print("Please set GITHUB_ENABLED=true or GITLAB_ENABLED=true in your .env file")
        return False
    
    provider_configured = False
    missing_vars = []
    
    # Check GitHub configuration
    if github_enabled:
        github_client_id = env_vars.get('GITHUB_CLIENT_ID', '').strip()
        github_client_secret = env_vars.get('GITHUB_CLIENT_SECRET', '').strip()
        
        print(f"🔍 GitHub Client ID: {'✅ Set' if github_client_id else '❌ Missing'}")
        print(f"🔍 GitHub Client Secret: {'✅ Set' if github_client_secret else '❌ Missing'}")
        
        if not github_client_id:
            missing_vars.append('GITHUB_CLIENT_ID')
        elif not github_client_secret:
            missing_vars.append('GITHUB_CLIENT_SECRET')
        else:
            print("✅ GitHub configuration is valid")
            provider_configured = True
    
    # Check GitLab configuration
    if gitlab_enabled:
        gitlab_client_id = env_vars.get('GITLAB_CLIENT_ID', '').strip()
        gitlab_client_secret = env_vars.get('GITLAB_CLIENT_SECRET', '').strip()
        
        print(f"🔍 GitLab Client ID: {'✅ Set' if gitlab_client_id else '❌ Missing'}")
        print(f"🔍 GitLab Client Secret: {'✅ Set' if gitlab_client_secret else '❌ Missing'}")
        
        if not gitlab_client_id:
            missing_vars.append('GITLAB_CLIENT_ID')
        elif not gitlab_client_secret:
            missing_vars.append('GITLAB_CLIENT_SECRET')
        else:
            print("✅ GitLab configuration is valid")
            provider_configured = True
    
    if missing_vars:
        print(f"❌ Error: Missing environment variables: {', '.join(missing_vars)}")
        print("Please check your .env file and configure the OAuth credentials.")
        return False
    
    if not provider_configured:
        print("❌ Error: No valid provider configurations found")
        return False
    
    print("✅ Environment configuration looks good")
    return True

def install_dependencies():
    """Install required dependencies."""
    try:
        print("📦 Installing dependencies...")
        result = subprocess.run([sys.executable, '-m', 'pip', 'install', '-r', 'requirements.txt'], 
                              capture_output=True, text=True)
        if result.returncode != 0:
            print(f"❌ Error installing dependencies: {result.stderr}")
            return False
        print("✅ Dependencies installed successfully")
        return True
    except subprocess.CalledProcessError as e:
        print(f"❌ Error installing dependencies: {e}")
        print("Please run: pip install -r requirements.txt")
        return False
    except FileNotFoundError:
        print("❌ Error: requirements.txt not found!")
        return False

def run_application():
    """Run the Flask application."""
    try:
        print("🚀 Starting Release Notes Generator...")
        print("📍 Application will be available at: http://localhost:3000")
        print("💡 Press Ctrl+C to stop the application")
        print("-" * 50)
        
        # Import and run the main application
        from main import app
        
        # Get configuration from environment
        debug_mode = os.environ.get('DEBUG', 'false').lower() in ('true', '1', 'yes', 'on')
        port = int(os.environ.get('PORT', 3000))
        
        app.run(host='0.0.0.0', port=port, debug=debug_mode)
        
    except ImportError as e:
        print(f"❌ Error importing application: {e}")
        print("Please check that all dependencies are installed.")
        return False
    except KeyboardInterrupt:
        print("\n👋 Application stopped by user")
        return True
    except Exception as e:
        print(f"❌ Error starting application: {e}")
        return False

def main():
    """Main function to run the startup sequence."""
    print("🎯 Release Notes Generator - Startup")
    print("=" * 40)
    
    # Check Python version
    check_python_version()
    
    # Load .env file
    env_vars = load_env_file()
    if not env_vars:
        sys.exit(1)
    
    # Check environment configuration
    if not check_env_configuration(env_vars):
        sys.exit(1)
    
    # Install dependencies
    if not install_dependencies():
        sys.exit(1)
    
    # Run the application
    if not run_application():
        sys.exit(1)

if __name__ == '__main__':
    main()