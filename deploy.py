#!/usr/bin/env python3
"""
Deployment helper script for Phishing Detection App
"""

import os
import shutil
import subprocess
import sys

def check_requirements():
    """Check if all required files exist"""
    required_files = [
        'app.py',
        'requirements.txt',
        'models/__init__.py',
        'models/url_model.py',
        'models/sms_model.py',
        'models/email_model.py',
        'templates/index.html',
        'templates/dashboard.html',
        'dataset_phishing.csv',
        'SMSSpamCollection',
        'spam_assassin.csv'
    ]
    
    missing_files = []
    for file in required_files:
        if not os.path.exists(file):
            missing_files.append(file)
    
    if missing_files:
        print("❌ Missing required files:")
        for file in missing_files:
            print(f"   - {file}")
        return False
    
    print("✅ All required files found")
    return True

def create_models_directory():
    """Create models directory if it doesn't exist"""
    if not os.path.exists('models'):
        os.makedirs('models')
        print("✅ Created models directory")

def test_local_run():
    """Test if the app runs locally"""
    print("🧪 Testing local run...")
    try:
        # Test import
        import app
        print("✅ App imports successfully")
        return True
    except Exception as e:
        print(f"❌ App import failed: {e}")
        return False

def prepare_for_deployment():
    """Prepare the app for deployment"""
    print("🚀 Preparing for deployment...")
    
    # Check requirements
    if not check_requirements():
        return False
    
    # Create models directory
    create_models_directory()
    
    # Test local run
    if not test_local_run():
        return False
    
    print("✅ App is ready for deployment!")
    return True

def show_deployment_instructions():
    """Show deployment instructions"""
    print("\n" + "="*60)
    print("🚀 DEPLOYMENT INSTRUCTIONS")
    print("="*60)
    
    print("\n📋 Choose your deployment platform:")
    
    print("\n1️⃣  RENDER (Recommended - Free):")
    print("   • Go to https://render.com")
    print("   • Create account and connect GitHub")
    print("   • New Web Service → Connect this repo")
    print("   • Environment: Python")
    print("   • Build Command: pip install -r requirements.txt")
    print("   • Start Command: gunicorn app:app")
    
    print("\n2️⃣  RAILWAY (Alternative - Free):")
    print("   • Go to https://railway.app")
    print("   • Create account and connect GitHub")
    print("   • New Project → Deploy from GitHub repo")
    print("   • Select this repository")
    
    print("\n3️⃣  HEROKU (Paid but Reliable):")
    print("   • Install Heroku CLI")
    print("   • heroku create your-app-name")
    print("   • git push heroku main")
    
    print("\n📝 Before deploying:")
    print("   • Make sure your code is committed to GitHub")
    print("   • Ensure all datasets are in the repository")
    print("   • Models will be trained automatically on first run")
    
    print("\n🔗 Your app will be available at:")
    print("   • Render: https://your-app-name.onrender.com")
    print("   • Railway: https://your-app-name.railway.app")
    print("   • Heroku: https://your-app-name.herokuapp.com")

def main():
    """Main function"""
    print("🔍 Phishing Detection App - Deployment Helper")
    print("="*50)
    
    if len(sys.argv) > 1 and sys.argv[1] == '--deploy':
        if prepare_for_deployment():
            show_deployment_instructions()
        else:
            print("❌ Deployment preparation failed")
            sys.exit(1)
    else:
        print("Usage: python deploy.py --deploy")
        print("This will check your app and show deployment instructions")

if __name__ == "__main__":
    main() 