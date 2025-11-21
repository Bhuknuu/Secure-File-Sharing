from flask import Flask, request, jsonify, send_file
import os
import uuid
from datetime import datetime
import json

app = Flask(__name__)

UPLOAD_FOLDER = 'server_storage'
USERS_FILE = 'users_db.json'
os.makedirs(UPLOAD_FOLDER, exist_ok=True)

files_db = {}
users_db = {}

def load_users():
    global users_db
    if os.path.exists(USERS_FILE):
        with open(USERS_FILE, 'r') as f:
            users_db = json.load(f)

def save_users():
    with open(USERS_FILE, 'w') as f:
        json.dump(users_db, f, indent=2)

load_users()

@app.route('/api/health', methods=['GET'])
def health_check():
    return jsonify({"status": "healthy", "timestamp": datetime.now().isoformat()})

@app.route('/api/auth/register', methods=['POST'])
def register():
    try:
        data = request.json
        username = data.get('username')
        password_hash = data.get('password_hash')
        public_key = data.get('public_key')
        
        if username in users_db:
            return jsonify({"error": "User already exists"}), 400
        
        users_db[username] = {
            'password_hash': password_hash,
            'public_key': public_key,
            'created_at': datetime.now().isoformat()
        }
        save_users()
        
        print(f"[+] New user registered: {username}")
        return jsonify({"message": "User registered successfully", "public_key": public_key}), 200
    
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route('/api/auth/login', methods=['POST'])
def login():
    try:
        data = request.json
        username = data.get('username')
        password_hash = data.get('password_hash')
        
        if username not in users_db:
            return jsonify({"error": "User not found"}), 404
        
        if users_db[username]['password_hash'] != password_hash:
            return jsonify({"error": "Invalid password"}), 401
        
        print(f"[+] User logged in: {username}")
        return jsonify({
            "message": "Login successful",
            "public_key": users_db[username]['public_key']
        }), 200
    
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route('/api/users/<username>/public_key', methods=['GET'])
def get_user_public_key(username):
    if username in users_db:
        return jsonify({"public_key": users_db[username]['public_key']}), 200
    return jsonify({"error": "User not found"}), 404

@app.route('/api/users/list', methods=['GET'])
def list_users():
    return jsonify({"users": list(users_db.keys())}), 200

@app.route('/api/upload', methods=['POST'])
def upload_file():
    try:
        if 'file' not in request.files or 'signature' not in request.files:
            return jsonify({"error": "Missing file or signature"}), 400
        
        file = request.files['file']
        signature = request.files['signature']
        sender = request.form.get('sender', 'anonymous')
        recipient = request.form.get('recipient', 'anyone')
        
        file_id = str(uuid.uuid4())
        
        file_path = os.path.join(UPLOAD_FOLDER, f"{file_id}.enc")
        sig_path = os.path.join(UPLOAD_FOLDER, f"{file_id}.sig")
        
        file.save(file_path)
        signature.save(sig_path)
        
        files_db[file_id] = {
            'sender': sender,
            'recipient': recipient,
            'filename': file.filename,
            'uploaded_at': datetime.now().isoformat(),
            'file_path': file_path,
            'sig_path': sig_path
        }
        
        print(f"[+] File uploaded: {file_id} from {sender} to {recipient}")
        
        return jsonify({
            "file_id": file_id,
            "message": "File uploaded successfully"
        }), 200
        
    except Exception as e:
        print(f"[!] Upload error: {e}")
        return jsonify({"error": str(e)}), 500

@app.route('/api/files/<recipient>', methods=['GET'])
def list_files(recipient):
    user_files = [
        {
            'file_id': fid,
            'sender': info['sender'],
            'filename': info['filename'],
            'uploaded_at': info['uploaded_at']
        }
        for fid, info in files_db.items()
        if info['recipient'] == recipient or info['recipient'] == 'anyone'
    ]
    return jsonify({"files": user_files})

@app.route('/api/download/<file_id>', methods=['GET'])
def download_file(file_id):
    if file_id not in files_db:
        return jsonify({"error": "File not found"}), 404
    
    file_info = files_db[file_id]
    return send_file(file_info['file_path'], as_attachment=True)

@app.route('/api/download/<file_id>/signature', methods=['GET'])
def download_signature(file_id):
    if file_id not in files_db:
        return jsonify({"error": "Signature not found"}), 404
    
    file_info = files_db[file_id]
    return send_file(file_info['sig_path'], as_attachment=True)

@app.route('/api/delete/<file_id>', methods=['DELETE'])
def delete_file(file_id):
    if file_id not in files_db:
        return jsonify({"error": "File not found"}), 404
    
    file_info = files_db[file_id]
    
    try:
        os.remove(file_info['file_path'])
        os.remove(file_info['sig_path'])
        del files_db[file_id]
        print(f"[+] File deleted: {file_id}")
        return jsonify({"message": "File deleted successfully"})
    except Exception as e:
        return jsonify({"error": str(e)}), 500

if __name__ == '__main__':
    print("\n" + "="*50)
    print("SECURE FILE SHARING SERVER")
    print("="*50)
    print("Server starting on http://localhost:5000")
    print("Storage location:", UPLOAD_FOLDER)
    print("Users database:", USERS_FILE)
    print("="*50 + "\n")
    
    try:
        app.run(host='0.0.0.0', port=5000, debug=False, threaded=True)
    except Exception as e:
        print(f"[!] Error starting server: {e}")
        print("[!] Make sure port 5000 is not already in use")