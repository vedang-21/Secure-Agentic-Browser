#!/usr/bin/env python3
"""
Migration Script for Folder Reorganization
Helps users migrate from old file structure to new organized structure.
"""

import os
import shutil
from pathlib import Path

def migrate_project_structure():
    """Migrate project to new organized structure."""
    
    print("🔄 Project Structure Migration")
    print("=" * 40)
    
    project_root = Path.cwd()
    config_dir = project_root / "config"
    docs_dir = project_root / "docs"
    
    # Ensure directories exist
    config_dir.mkdir(exist_ok=True)
    docs_dir.mkdir(exist_ok=True)
    
    migrations = []
    
    # Files to migrate to config/
    config_files = [
        "requirements.txt",
        ".env.template"
    ]
    
    # Files to migrate to docs/
    doc_files = [
        "ENVIRONMENT_SETUP.md",
        "FIREWALL_INTEGRATION.md", 
        "QUICKSTART.md"
    ]
    
    # Check and migrate config files
    print("📋 Checking configuration files...")
    for file in config_files:
        src = project_root / file
        dst = config_dir / file
        
        if src.exists() and not dst.exists():
            shutil.move(str(src), str(dst))
            migrations.append(f"✅ Moved {file} to config/")
        elif src.exists() and dst.exists():
            migrations.append(f"ℹ️ {file} already in config/ (keeping both)")
        elif not src.exists() and dst.exists():
            migrations.append(f"✅ {file} already in config/")
        else:
            migrations.append(f"⚠️ {file} not found in either location")
    
    # Check and migrate documentation files
    print("📚 Checking documentation files...")
    for file in doc_files:
        src = project_root / file
        dst = docs_dir / file
        
        if src.exists() and not dst.exists():
            shutil.move(str(src), str(dst))
            migrations.append(f"✅ Moved {file} to docs/")
        elif src.exists() and dst.exists():
            migrations.append(f"ℹ️ {file} already in docs/ (keeping both)")
        elif not src.exists() and dst.exists():
            migrations.append(f"✅ {file} already in docs/")
        else:
            migrations.append(f"⚠️ {file} not found in either location")
    
    # Check for .env file (should stay in root)
    env_file = project_root / ".env"
    if env_file.exists():
        migrations.append("✅ .env file correctly in project root")
    else:
        migrations.append("ℹ️ .env file not found (will be created from template)")
    
    # Report results
    print("\n📊 Migration Results:")
    for migration in migrations:
        print(f"   {migration}")
    
    print(f"\n📁 New structure:")
    print(f"   config/ - Configuration files and templates")
    print(f"   docs/   - Documentation and guides") 
    print(f"   .env    - Environment variables (stays in root)")
    
    # Update instructions
    print(f"\n🔧 Updated commands:")
    print(f"   Install deps: pip install -r config/requirements.txt")
    print(f"   Setup config: python config/setup_config.py")
    print(f"   Read docs: ls docs/")
    
    print(f"\n✅ Migration complete!")

if __name__ == "__main__":
    migrate_project_structure()
