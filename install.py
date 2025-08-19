#!/usr/bin/env python3
"""
Installation script for PanOS Evaluator
"""

import sys
import subprocess
import os
from pathlib import Path

def check_python_version():
    """Check if Python version is compatible"""
    if sys.version_info < (3, 8):
        print("❌ Error: Python 3.8 or higher is required")
        print(f"   Current version: {sys.version}")
        return False
    print(f"✅ Python version: {sys.version.split()[0]}")
    return True

def install_dependencies():
    """Install required dependencies"""
    print("\n📦 Installing dependencies...")
    
    try:
        # Install core dependencies
        subprocess.check_call([sys.executable, "-m", "pip", "install", "-r", "requirements.txt"])
        print("✅ Dependencies installed successfully")
        return True
    except subprocess.CalledProcessError as e:
        print(f"❌ Error installing dependencies: {e}")
        return False

def create_sample_config():
    """Create a sample configuration file if it doesn't exist"""
    config_file = Path("evaluator.conf")
    if not config_file.exists():
        print("\n⚙️  Creating sample configuration file...")
        sample_config = {
            "api_url": "",
            "api_key": "",
            "vsys": "vsys1",
            "output_dir": "",
            "window_geometry": "1200x800",
            "csv_file": "",
            "mode": "csv"
        }
        
        import json
        with open(config_file, 'w') as f:
            json.dump(sample_config, f, indent=2)
        print("✅ Sample configuration file created: evaluator.conf")
    else:
        print("✅ Configuration file already exists")

def main():
    """Main installation function"""
    print("🚀 PanOS Evaluator Installation")
    print("=" * 40)
    
    # Check Python version
    if not check_python_version():
        sys.exit(1)
    
    # Install dependencies
    if not install_dependencies():
        sys.exit(1)
    
    # Create sample config
    create_sample_config()
    
    print("\n🎉 Installation completed successfully!")
    print("\n📋 Next steps:")
    print("1. Run the application: python evaluator.py")
    print("2. Configure your settings in evaluator.conf (optional)")
    print("3. Import your CSV file or configure API access")
    print("\n📖 For more information, see README.md")

if __name__ == "__main__":
    main()
