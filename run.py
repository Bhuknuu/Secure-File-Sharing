import subprocess
import sys
import time
import webbrowser
import os

def check_port(port):
    import socket
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    result = sock.connect_ex(('localhost', port))
    sock.close()
    return result == 0

print("\n" + "="*60)
print("🔒 SECURE FILE SHARING SYSTEM")
print("Team Cryptics - TCS-392")
print("="*60 + "\n")

if check_port(5000):
    print("⚠️  Warning: Port 5000 is already in use")
    print("   Either a server is already running, or another app is using the port")
    print("\n   To continue:")
    print("   1. Close any existing server instances")
    print("   2. Or change the port in server.py")
    sys.exit(1)

print("Starting Flask server...")
try:
    if sys.platform == 'win32':
        server = subprocess.Popen(
            [sys.executable, 'server.py'],
            creationflags=subprocess.CREATE_NEW_CONSOLE
        )
    else:
        server = subprocess.Popen(
            [sys.executable, 'server.py'],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL
        )
    
    print("Waiting for server to start...")
    time.sleep(3)
    
    if check_port(5000):
        print("✅ Server started successfully!")
    else:
        print("❌ Server failed to start")
        print("   Check server.py for errors")
        sys.exit(1)
    
except FileNotFoundError:
    print("❌ Error: server.py not found!")
    print("   Make sure you're in the project directory")
    sys.exit(1)
except Exception as e:
    print(f"❌ Error starting server: {e}")
    sys.exit(1)

print("\nOpening web interface...")
print("\n📱 Access the application at: http://localhost:8501")
print("\n💡 Tips:")
print("   • Open in 2 different browsers to test")
print("   • Exchange public keys between users")
print("   • Send files securely!")
print("\n⚠️  Press Ctrl+C to stop both server and app\n")

time.sleep(2)
webbrowser.open('http://localhost:8501')

try:
    subprocess.run([
        sys.executable, '-m', 'streamlit', 'run', 'web_app.py',
        '--server.headless=true',
        '--browser.gatherUsageStats=false'
    ])
except KeyboardInterrupt:
    print("\n\n🛑 Shutting down...")
    server.terminate()
    print("✅ Goodbye!")
except FileNotFoundError:
    print("\n❌ Error: Streamlit not installed or web_app.py not found")
    print("   Run: pip install streamlit")
    server.terminate()
except Exception as e:
    print(f"\n❌ Error: {e}")
    server.terminate()