from flask import Flask, request, jsonify, send_file
import os
import uuid
from datetime import datetime

app = Flask(__name__)

UPLOAD_FOLDER = 'server_storage'
os.makedirs(UPLOAD_FOLDER, exist_ok=True)

files_db = {}

@app.route('/api/health', methods=['GET'])
def health_check():
    return jsonify({"status": "healthy", "timestamp": datetime.now().isoformat()})

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
        return jsonify({"message": "File deleted successfully"})
    except Exception as e:
        return jsonify({"error": str(e)}), 500

if __name__ == '__main__':
    print("\n" + "="*50)
    print("SECURE FILE SHARING SERVER")
    print("="*50)
    print("Server starting on http://localhost:5000")
    print("Storage location:", UPLOAD_FOLDER)
    print("="*50 + "\n")
    
    try:
        app.run(host='0.0.0.0', port=5000, debug=False, threaded=True)
    except Exception as e:
        print(f"[!] Error starting server: {e}")
        print("[!] Make sure port 5000 is not already in use")