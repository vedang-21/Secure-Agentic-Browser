#!/usr/bin/env python3
"""
Configuration Setup Script
Helps users set up their environment configuration files.
"""

import os
import shutil
from pathlib import Path

def setup_configuration():
    """Set up configuration files for the Secure Agentic Browser."""
    
    print("🔧 Secure Agentic Browser Configuration Setup")
    print("=" * 50)
    
    # Get project root (parent of config directory)
    config_dir = Path(__file__).parent
    project_root = config_dir.parent
    
    # Check if .env already exists
    env_file = project_root / ".env"
    env_template = config_dir / ".env.template"
    
    if env_file.exists():
        print(f"✅ Configuration file already exists: {env_file}")
        response = input("🔄 Do you want to update it? (y/N): ").lower()
        if response != 'y':
            print("ℹ️ Keeping existing configuration")
            return
        
        # Backup existing .env
        backup_file = project_root / ".env.backup"
        shutil.copy2(env_file, backup_file)
        print(f"💾 Backed up existing .env to {backup_file}")
    
    # Copy template to .env
    if env_template.exists():
        shutil.copy2(env_template, env_file)
        print(f"📋 Created configuration file: {env_file}")
    else:
        print(f"❌ Template file not found: {env_template}")
        return
    
    # Get API key from user
    print("\n🔑 API Key Setup")
    print("You need a Google Gemini API key to use the AI functionality.")
    print("Get your key from: https://makersuite.google.com/app/apikey")
    
    api_key = input("\nEnter your Google Gemini API key (or press Enter to skip): ").strip()
    
    if api_key:
        # Update .env file with API key
        with open(env_file, 'r') as f:
            content = f.read()
        
        # Replace the placeholder API key
        content = content.replace(
            'GOOGLE_API_KEY=your_actual_gemini_api_key_here',
            f'GOOGLE_API_KEY={api_key}'
        )
        
        with open(env_file, 'w') as f:
            f.write(content)
        
        print("✅ API key configured successfully!")
    else:
        print("⚠️ Skipping API key setup. You can edit .env file manually later.")
    
    # Configuration options
    print("\n⚙️ Optional Configuration")
    
    # Browser headless mode
    headless = input("Run browser in headless mode? (y/N): ").lower() == 'y'
    if headless:
        with open(env_file, 'r') as f:
            content = f.read()
        content = content.replace('BROWSER_HEADLESS=false', 'BROWSER_HEADLESS=true')
        with open(env_file, 'w') as f:
            f.write(content)
        print("✅ Browser set to headless mode")
    
    # External firewall
    external_firewall = input("Enable external firewall integration? (y/N): ").lower() == 'y'
    if not external_firewall:
        with open(env_file, 'r') as f:
            content = f.read()
        content = content.replace('USE_EXTERNAL_FIREWALL=true', 'USE_EXTERNAL_FIREWALL=false')
        with open(env_file, 'w') as f:
            f.write(content)
        print("✅ External firewall disabled (using local rules only)")
    
    print("\n🎉 Configuration Setup Complete!")
    print(f"📄 Configuration file: {env_file}")
    print(f"📚 Documentation: {project_root / 'docs'}")
    print(f"🔧 Requirements: {config_dir / 'requirements.txt'}")
    
    print("\n🚀 Next Steps:")
    print("1. Install dependencies: pip install -r config/requirements.txt")
    print("2. Install Playwright: playwright install")
    print("3. Start the server: python main.py")

if __name__ == "__main__":
    setup_configuration()
