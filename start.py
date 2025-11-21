#starts server and backend
import subprocess
import sys
import os
import time
import webbrowser

def check_dependencies():
    #requriment checks
    required = ['flask', 'streamlit', 'cryptography', 'requests']
    missing = []
    
    for package in required:
        try:
            __import__(package)
        except ImportError:
            missing.append(package)
    
    if missing:
        print("Missing packages:", ', '.join(missing))
        print("\nInstalling dependencies...")
        subprocess.run([sys.executable, '-m', 'pip', 'install', '-r', 'requirements.txt'])
        print("Dependencies installed!\n")

def start_server():
    """Start the Flask server in background"""
    print("Starting Flask server...")
    
    if sys.platform == 'win32':
        # Windows
        server_process = subprocess.Popen(
            [sys.executable, 'server.py'],
            creationflags=subprocess.CREATE_NEW_CONSOLE
        )
    else:
        print("Use Windows because our dev don't know how to code for mac or linux")
        # Mac/Linux
        # server_process = subprocess.Popen(
        #     [sys.executable, 'server.py'],
        #     stdout=subprocess.DEVNULL,
        #     stderr=subprocess.DEVNULL
    
    # Wait for server to start
    print("Waiting for server to initialize...")
    time.sleep(3)
    
    # Check if server is running
    import requests
    try:
        response = requests.get('http://localhost:5000/api/health', timeout=2)
        if response.status_code == 200:
            print("✓ Server is running!\n")
            return server_process
    except:
        pass
    
    print("Server might be taking longer to start...")
    return server_process

def start_webapp():
    """Start the Streamlit web app"""
    print("Starting web application...")
    print("\n" + "="*60)
    print("APPLICATION READY!")
    print("="*60)
    print("\nOpening browser...")
    print("   URL: http://localhost:8501")
    print("\nTips:")
    print("   • Register 2 users to test file sharing")
    print("   • Use different browsers for each user")
    print("   • Press Ctrl+C to stop\n")
    
    # Open browser after short delay
    time.sleep(2)
    webbrowser.open('http://localhost:8501')
    
    # Start streamlit
    subprocess.run([sys.executable, '-m', 'streamlit', 'run', 'web_app.py'])

def main():
    """Main entry point"""
    print("\n" + "="*60)
    print("SECURE FILE SHARING SYSTEM")
    print("="*60 + "\n")
    
    # Check files exist
    if not os.path.exists('server.py'):
        print("Error: server.py not found!")
        print("Make sure you're in the project directory")
        return
    
    if not os.path.exists('web_app.py'):
        print("Error: web_app.py not found!")
        return
    
    # Check dependencies
    print("Checking dependencies...")
    check_dependencies()
    
    try:
        # Start server
        server_process = start_server()
        
        # Start web app (blocking)
        start_webapp()
        
    except KeyboardInterrupt:
        print("\n\nShutting down...")
        if 'server_process' in locals():
            server_process.terminate()
        print("✓ Goodbye!")
    except Exception as e:
        print(f"\nError: {e}")
        import traceback
        traceback.print_exc()

if __name__ == "__main__":
    main()