import subprocess
import sys
import os
import time
import webbrowser

def check_dependencies():
    required = ['flask', 'streamlit', 'cryptography', 'requests', 'pycryptodome']
    missing = []
    
    for package in required:
        try:
            if package == 'pycryptodome':
                __import__('Crypto')
            else:
                __import__(package)
        except ImportError:
            missing.append(package)
    
    if missing:
        print("Missing packages:", ', '.join(missing))
        print("\nInstalling dependencies...")
        subprocess.run([sys.executable, '-m', 'pip', 'install'] + missing)
        print("Dependencies installed!\n")

def check_port(port):
    import socket
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    result = sock.connect_ex(('localhost', port))
    sock.close()
    return result == 0

def start_server():
    print("Starting Flask server...")
    
    if sys.platform == 'win32':
        server_process = subprocess.Popen(
            [sys.executable, 'server.py'],
            creationflags=subprocess.CREATE_NEW_CONSOLE
        )
    else:
        server_process = subprocess.Popen(
            [sys.executable, 'server.py'],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL
        )
    
    print("Waiting for server to initialize...")
    time.sleep(3)
    
    import requests
    try:
        response = requests.get('http://localhost:5000/api/health', timeout=2)
        if response.status_code == 200:
            print("Server is running!\n")
            return server_process
    except:
        pass
    
    print("Server might be taking longer to start...")
    return server_process

def start_webapp():
    print("Starting web application...")
    print("\n" + "="*60)
    print("SECURE FILE SHARING SYSTEM - WEB INTERFACE")
    print("="*60)
    print("\nOpening browser...")
    print("   URL: http://localhost:8501")
    print("\nHow to use:")
    print("   • Login with username and password")
    print("   • Select a partner from dropdown")
    print("   • Connection established automatically")
    print("   • Send/receive files securely!")
    print("\n   Press Ctrl+C to stop\n")
    
    time.sleep(2)
    webbrowser.open('http://localhost:8501')
    
    subprocess.run([
        sys.executable, '-m', 'streamlit', 'run', 'web_app.py',
        '--server.headless=true',
        '--browser.gatherUsageStats=false'
    ])

def main():
    print("\n" + "="*60)
    print("SECURE FILE SHARING SYSTEM")
    print("Team Cryptics - TCS-392")
    print("="*60 + "\n")
    
    if not os.path.exists('server.py'):
        print("Error: server.py not found!")
        print("Make sure you're in the project directory")
        return
    
    if not os.path.exists('web_app.py'):
        print("Error: web_app.py not found!")
        return
    
    if check_port(5000):
        print("Warning: Port 5000 already in use")
        print("Server might already be running")
        print("\nStarting web interface only...\n")
        start_webapp()
        return
    
    print("Checking dependencies...")
    check_dependencies()
    
    try:
        server_process = start_server()
        start_webapp()
        
    except KeyboardInterrupt:
        print("\n\nShutting down...")
        if 'server_process' in locals():
            server_process.terminate()
        print("Goodbye!")
    except Exception as e:
        print(f"\nError: {e}")
        import traceback
        traceback.print_exc()

if __name__ == "__main__":
    main()