#!/usr/bin/env python3
"""
E-Gov Guardian Web Interface Launcher
Simple script to start the security scanner web interface
"""

import os
import sys
import webbrowser
import time
from pathlib import Path

def check_dependencies():
    """Check if required dependencies are installed"""
    required_packages = [
        'flask', 'flask_wtf', 'wtforms', 'reportlab', 
        'requests', 'bs4', 'psutil'
    ]
    
    missing_packages = []
    for package in required_packages:
        try:
            __import__(package.replace('-', '_'))
        except ImportError:
            missing_packages.append(package)
    
    if missing_packages:
        print("❌ Missing required packages:")
        for package in missing_packages:
            print(f"   - {package}")
        print("\n💡 Install missing packages with:")
        print(f"   pip install {' '.join(missing_packages)}")
        return False
    
    return True

def setup_environment():
    """Setup necessary directories and environment"""
    # Check necessary directories exist
    directories = ['templates', 'scanner']
    for directory in directories:
        os.makedirs(directory, exist_ok=True)
    
    print("✅ Environment setup complete")

def main():
    """Main launcher function"""
    print("🚀 E-Gov Guardian Web Interface Launcher")
    print("=" * 50)
    
    # Check current directory
    if not Path('web_app.py').exists():
        print("❌ Error: web_app.py not found in current directory")
        print("💡 Make sure you're in the E-Gov_Guardian directory")
        sys.exit(1)
    
    # Check dependencies
    print("🔍 Checking dependencies...")
    if not check_dependencies():
        sys.exit(1)
    
    print("✅ All dependencies found")
    
    # Setup environment
    print("⚙️  Setting up environment...")
    setup_environment()
    
    # Start the web application
    print("🌐 Starting web interface...")
    print("📍 URL: http://localhost:5000")
    print("🔒 Security Scanner ready for use")
    print("\n" + "=" * 50)
    print("Press Ctrl+C to stop the server")
    print("=" * 50 + "\n")
    
    try:
        # Import and start the Flask app
        from web_app import app
        
        # Open browser automatically (optional)
        time.sleep(1)
        try:
            webbrowser.open('http://localhost:5000')
            print("🌍 Browser opened automatically")
        except:
            print("💡 Manually open: http://localhost:5000")
        
        # Start the Flask development server
        app.run(
            debug=False,  # Set to False for production
            host='0.0.0.0',
            port=5000,
            use_reloader=False  # Prevent double startup
        )
        
    except KeyboardInterrupt:
        print("\n\n🛑 Server stopped by user")
        print("👋 Thank you for using E-Gov Guardian!")
    
    except Exception as e:
        print(f"\n❌ Error starting server: {e}")
        print("💡 Check the logs above for more details")
        sys.exit(1)

if __name__ == '__main__':
    main() 