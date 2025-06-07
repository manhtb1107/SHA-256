import socket
import threading
import hashlib
import os
import json
from datetime import datetime
from flask import Flask, render_template, request, jsonify, session, redirect, url_for, send_file
from werkzeug.utils import secure_filename
from functools import wraps

app = Flask(__name__)
app.secret_key = 'your-secret-key'  # Change this

def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            return jsonify({'status': 'error', 'message': 'Not logged in'})
        return f(*args, **kwargs)
    return decorated_function

# Configuration
UPLOAD_FOLDER = 'uploads'
DOWNLOAD_FOLDER = 'downloads'
ALLOWED_EXTENSIONS = {'txt', 'pdf', 'png', 'jpg', 'jpeg', 'doc', 'docx'}

app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
app.config['DOWNLOAD_FOLDER'] = DOWNLOAD_FOLDER
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024  # 16MB max file size

# Create directories if not exist
os.makedirs(UPLOAD_FOLDER, exist_ok=True)
os.makedirs(DOWNLOAD_FOLDER, exist_ok=True)

class FileTransferServer:
    def __init__(self, host='localhost', port=8888):
        self.host = host
        self.port = port
        self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

    def start(self):
        self.socket.bind((self.host, self.port))
        self.socket.listen(5)
        print(f"File transfer server running on {self.host}:{self.port}")
        
        while True:
            client, addr = self.socket.accept()
            thread = threading.Thread(target=self.handle_client, args=(client, addr))
            thread.start()

    def handle_client(self, client, addr):
        try:
            # Receive file metadata
            metadata_size = int.from_bytes(client.recv(4), 'big')
            metadata = json.loads(client.recv(metadata_size).decode())
            
            filename = metadata['filename']
            file_size = metadata['file_size']
            original_hash = metadata['hash']
            
            # Receive file data
            filepath = os.path.join(DOWNLOAD_FOLDER, filename)
            received_size = 0
            
            with open(filepath, 'wb') as f:
                while received_size < file_size:
                    chunk = client.recv(min(4096, file_size - received_size))
                    if not chunk:
                        break
                    f.write(chunk)
                    received_size += len(chunk)

            # Verify integrity
            received_hash = calculate_sha256(filepath)
            is_valid = received_hash == original_hash
            
            # Send response
            response = {
                'status': 'success' if is_valid else 'error',
                'message': 'File integrity verified' if is_valid else 'File integrity check failed',
                'hash': received_hash
            }
            response_json = json.dumps(response).encode()
            client.send(len(response_json).to_bytes(4, 'big'))
            client.send(response_json)
            
        except Exception as e:
            print(f"Error handling client {addr}: {e}")
        finally:
            client.close()

# Utility functions
def calculate_sha256(filepath):
    sha256_hash = hashlib.sha256()
    with open(filepath, "rb") as f:
        for byte_block in iter(lambda: f.read(4096), b""):
            sha256_hash.update(byte_block)
    return sha256_hash.hexdigest()

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

# Memory storage for users and files
class MemoryStorage:
    def __init__(self):
        self.users = []
        self.files = []
        self.shares = []
        self.shared_files = []  # Add shared files list
        self.next_user_id = 1
        self.next_file_id = 1
        self.next_share_id = 1
        self.online_users = set()
        self.user_profiles = {}  # Lưu thông tin profile của user

    def add_user(self, username, password, avatar=None):
        # Kiểm tra username đã tồn tại chưa
        if any(u['username'] == username for u in self.users):
            return None
        
        user = {
            'id': self.next_user_id,
            'username': username,
            'password': password,
            'avatar': avatar or 'default.png',  # Ảnh mặc định
            'created_at': datetime.now(),
            'last_login': None
        }
        self.users.append(user)
        self.next_user_id += 1
        return user

    def get_user(self, username, password):
        return next((u for u in self.users if u['username'] == username and u['password'] == password), None)

    def get_online_users(self, except_id=None):
        """Lấy danh sách users đang online (trừ user hiện tại)"""
        online = [u for u in self.users if u['id'] in self.online_users]
        if except_id:
            online = [u for u in online if u['id'] != except_id]
        return online

    def add_file(self, file_info):
        file_info['id'] = self.next_file_id
        self.files.append(file_info)
        self.next_file_id += 1
        return file_info

    def add_share(self, share_info):
        share_info['id'] = self.next_share_id
        self.shares.append(share_info)
        self.next_share_id += 1
        return share_info

    def share_file(self, file_id, from_user_id, to_user_id):
        """Share a file between users"""
        file = next((f for f in self.files if f['id'] == file_id), None)
        if not file:
            return None
            
        share_info = {
            'id': len(self.shared_files) + 1,
            'file_id': file_id,
            'from_user_id': from_user_id,
            'to_user_id': to_user_id,
            'timestamp': datetime.now(),
            'status': 'pending',  # pending, accepted, rejected
            'verified': False
        }
        self.shared_files.append(share_info)
        return share_info

    def get_user_files(self, user_id):
        """Lấy danh sách file của user (đã gửi hoặc nhận)"""
        return [f for f in self.files if f['sender_id'] == user_id or f['receiver_id'] == user_id]

    def get_shared_files(self, user_id):
        """Get files shared with/by the user"""
        return [
            {**share, 'file': next((f for f in self.files if f['id'] == share['file_id']), None)}
            for share in self.shared_files 
            if share['from_user_id'] == user_id or share['to_user_id'] == user_id
        ]

    def verify_shared_file(self, share_id, user_id):
        """Verify a shared file"""
        share = next((s for s in self.shared_files if s['id'] == share_id), None)
        if not share or share['to_user_id'] != user_id:
            return False
            
        file = next((f for f in self.files if f['id'] == share['file_id']), None)
        if not file:
            return False
            
        current_hash = calculate_sha256(file['download_path'])
        is_valid = current_hash == file['hash']
        
        if is_valid:
            share['verified'] = True
            share['status'] = 'accepted'
            
        return is_valid

    def get_sent_files(self, user_id):
        """Lấy danh sách file đã gửi"""
        return [
            {**f, 'file': next((file for file in self.files if file['id'] == f['file_id']), None)}
            for f in self.shares 
            if f['from_user_id'] == user_id
        ]

    def get_received_files(self, user_id):
        """Lấy danh sách file đã nhận"""
        return [
            {**f, 'file': next((file for file in self.files if file['id'] == f['file_id']), None)}
            for f in self.shares 
            if f['to_user_id'] == user_id
        ]

    def update_last_login(self, user_id):
        """Cập nhật thời gian đăng nhập cuối"""
        user = next((u for u in self.users if u['id'] == user_id), None)
        if user:
            user['last_login'] = datetime.now()

storage = MemoryStorage()

# Routes
@app.route('/')
def index():
    if 'user_id' in session:
        return redirect(url_for('dashboard'))
    return render_template('index.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'GET':
        return render_template('register.html')
        
    # POST request handling
    data = request.get_json()
    username = data.get('username')
    password = data.get('password')
    
    if storage.get_user(username, password):
        return jsonify({'status': 'error', 'message': 'Username already exists'})
    
    user = storage.add_user(username, password)
    return jsonify({'status': 'success', 'message': 'Registration successful'})

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'GET':
        return render_template('login.html')
    
    # POST request handling
    data = request.get_json()
    username = data.get('username')
    password = data.get('password')
    
    user = storage.get_user(username, password)
    if user:
        session['user_id'] = user['id']
        storage.online_users.add(user['id'])
        storage.update_last_login(user['id'])  # Cập nhật thời gian đăng nhập
        return jsonify({'status': 'success'})
    return jsonify({'status': 'error', 'message': 'Invalid credentials'})

@app.route('/dashboard')
def dashboard():
    if 'user_id' not in session:
        return redirect(url_for('index'))
    return render_template('dashboard.html')

@app.route('/users')
@login_required
def get_users():
    """Lấy danh sách người dùng online"""
    current_user_id = session.get('user_id')
    users = storage.get_online_users(except_id=current_user_id)
    return jsonify([{
        'id': u['id'], 
        'username': u['username']
    } for u in users])

@app.route('/upload', methods=['POST'])
@login_required
def upload_file():
    try:
        if 'file' not in request.files:
            return jsonify({'status': 'error', 'message': 'Không có file được chọn'})
        
        file = request.files['file']
        receiver_id = request.form.get('receiver_id')  # Single receiver
        
        if not receiver_id:
            return jsonify({'status': 'error', 'message': 'Chưa chọn người nhận'})
        
        receiver_id = int(receiver_id)
        
        # Check if recipient exists and is online
        receiver = next((u for u in storage.users if u['id'] == receiver_id), None)
        if not receiver:
            return jsonify({
                'status': 'error',
                'message': 'Không tìm thấy người nhận'
            })
            
        if receiver_id not in storage.online_users:
            return jsonify({
                'status': 'error',
                'message': f'Người nhận {receiver["username"]} không online'
            })

        # Process file upload
        timestamp = int(datetime.now().timestamp())
        filename = f"{timestamp}_{secure_filename(file.filename)}"
        
        upload_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
        download_path = os.path.join(app.config['DOWNLOAD_FOLDER'], filename)
        
        file.save(upload_path)
        
        # Copy file
        with open(upload_path, 'rb') as src:
            with open(download_path, 'wb') as dst:
                dst.write(src.read())
        
        file_hash = calculate_sha256(upload_path)
        file_size = os.path.getsize(upload_path)
        
        # Create file record
        file_info = {
            'id': storage.next_file_id,
            'sender_id': session['user_id'],
            'filename': filename,
            'original_filename': file.filename,
            'upload_path': upload_path,
            'download_path': download_path,
            'hash': file_hash,
            'size': file_size,
            'timestamp': datetime.now(),
            'status': 'completed'
        }
        
        stored_file = storage.add_file(file_info)
        
        # Create share record
        share_info = {
            'file_id': stored_file['id'],
            'from_user_id': session['user_id'],
            'to_user_id': receiver_id,
            'status': 'pending',
            'verified': False,
            'timestamp': datetime.now()
        }
        share = storage.add_share(share_info)

        return jsonify({
            'status': 'success',
            'message': f'File đã được gửi thành công tới {receiver["username"]}',
            'file_info': {
                'id': stored_file['id'],
                'filename': stored_file['original_filename'],
                'hash': file_hash,
                'size': file_size,
                'share_id': share['id']
            }
        })

    except Exception as e:
        print(f"Upload error: {str(e)}")
        return jsonify({'status': 'error', 'message': str(e)})

@app.route('/download/<int:file_id>')
def download(file_id):
    if 'user_id' not in session:
        return jsonify({'status': 'error', 'message': 'Not logged in'})
        
    file = next((f for f in storage.files if f['id'] == file_id), None)
    if not file:
        return jsonify({'status': 'error', 'message': 'File not found'})
        
    # Verify integrity before download
    current_hash = calculate_sha256(file['filepath'])
    if current_hash != file['hash']:
        return jsonify({
            'status': 'error',
            'message': 'File integrity check failed'
        })
        
    return send_file(
        file['filepath'],
        as_attachment=True,
        download_name=file['filename']
    )

@app.route('/logout')
def logout():
    """Đăng xuất và đánh dấu user offline"""
    if 'user_id' in session:
        storage.online_users.discard(session['user_id'])
    session.clear()
    return redirect(url_for('login'))

@app.route('/verify/<int:file_id>')
@login_required
def verify_file(file_id):
    try:
        file = next((f for f in storage.files if f['id'] == file_id), None)
        if not file:
            return jsonify({'status': 'error', 'message': 'File không tồn tại'})
            
        current_hash = calculate_sha256(file['filepath'])
        is_valid = current_hash == file['hash']
        
        return jsonify({
            'status': 'success',
            'is_valid': is_valid,
            'original_hash': file['hash'],
            'current_hash': current_hash
        })
    except Exception as e:
        return jsonify({'status': 'error', 'message': str(e)})

@app.route('/files')
@login_required
def get_files():
    """Lấy danh sách file của user hiện tại"""
    user_id = session['user_id']
    files = storage.get_user_files(user_id)
    return jsonify([{
        'id': f['id'],
        'filename': f['original_filename'],
        'file_size': f['size'],
        'original_hash': f['hash'],
        'is_sender': f['sender_id'] == user_id,
        'status': f['status'],
        'created_at': f['timestamp'].isoformat(),
        'is_valid': calculate_sha256(f['download_path']) == f['hash']
    } for f in files])

@app.route('/share/<int:file_id>/<int:to_user_id>', methods=['POST'])
@login_required
def share_file(file_id, to_user_id):
    try:
        from_user_id = session['user_id']
        
        # Check if recipient exists and is online
        if to_user_id not in storage.online_users:
            return jsonify({
                'status': 'error',
                'message': 'Người nhận không online'
            })
            
        share = storage.add_share({
            'file_id': file_id,
            'from_user_id': from_user_id,
            'to_user_id': to_user_id,
            'status': 'pending',
            'timestamp': datetime.now()
        })
        
        if not share:
            return jsonify({
                'status': 'error',
                'message': 'Không thể chia sẻ file'
            })
            
        return jsonify({
            'status': 'success',
            'message': 'File đã được chia sẻ thành công',
            'share_id': share['id']
        })
        
    except Exception as e:
        return jsonify({'status': 'error', 'message': str(e)})

@app.route('/shared')
@login_required
def get_shared_files():
    """Get list of shared files"""
    user_id = session['user_id']
    shares = storage.get_shared_files(user_id)
    
    return jsonify([{
        'id': s['id'],
        'file_id': s['file_id'],
        'filename': s['file']['original_filename'],
        'from_user': next(u['username'] for u in storage.users if u['id'] == s['from_user_id']),
        'to_user': next(u['username'] for u in storage.users if u['id'] == s['to_user_id']),
        'status': s['status'],
        'verified': s['verified'],
        'timestamp': s['timestamp'].isoformat(),
        'is_sender': s['from_user_id'] == user_id
    } for s in shares])

@app.route('/verify-share/<int:share_id>', methods=['POST'])
@login_required
def verify_shared_file(share_id):
    """Verify and accept a shared file"""
    try:
        user_id = session['user_id']
        is_valid = storage.verify_shared_file(share_id, user_id)
        
        return jsonify({
            'status': 'success' if is_valid else 'error',
            'message': 'File verified successfully' if is_valid else 'File verification failed',
            'verified': is_valid
        })
        
    except Exception as e:
        return jsonify({'status': 'error', 'message': str(e)})

@app.route('/history/sent')
@login_required
def get_sent_history():
    """Lấy lịch sử file đã gửi"""
    user_id = session['user_id']
    sent_files = storage.get_sent_files(user_id)
    
    return jsonify([{
        'id': s['id'],
        'file_id': s['file_id'],
        'filename': s['file']['original_filename'],
        'receiver': next(u['username'] for u in storage.users if u['id'] == s['to_user_id']),
        'status': s['status'],
        'verified': s.get('verified', False),
        'timestamp': s['timestamp'].isoformat(),
        'size': s['file']['size'],
        'hash': s['file']['hash']
    } for s in sent_files])

@app.route('/history/received') 
@login_required
def get_received_history():
    """Lấy lịch sử file đã nhận"""
    user_id = session['user_id']
    received_files = storage.get_received_files(user_id)
    
    return jsonify([{
        'id': s['id'],
        'file_id': s['file_id'],
        'filename': s['file']['original_filename'],
        'sender': next(u['username'] for u in storage.users if u['id'] == s['from_user_id']),
        'status': s['status'],
        'verified': s.get('verified', False),
        'timestamp': s['timestamp'].isoformat(),
        'size': s['file']['size'],
        'hash': s['file']['hash'],
        'can_download': s.get('verified', False)
    } for s in received_files])

@app.route('/download/<int:share_id>')
@login_required
def download_file(share_id):
    """Download shared file after verification"""
    try:
        user_id = session['user_id']
        
        # Tìm thông tin chia sẻ
        share = next((s for s in storage.shares if s['id'] == share_id), None)
        if not share:
            return jsonify({
                'status': 'error',
                'message': 'Không tìm thấy file được chia sẻ'
            })
            
        # Kiểm tra người dùng có quyền tải file không
        if share['to_user_id'] != user_id:
            return jsonify({
                'status': 'error',
                'message': 'Bạn không có quyền tải file này'
            })
            
        # Kiểm tra file đã được xác thực chưa
        if not share.get('verified', False):
            return jsonify({
                'status': 'error',
                'message': 'File chưa được xác thực. Vui lòng xác thực trước khi tải.'
            })
            
        # Lấy thông tin file
        file = next((f for f in storage.files if f['id'] == share['file_id']), None)
        if not file:
            return jsonify({
                'status': 'error',
                'message': 'Không tìm thấy file'
            })
            
        # Kiểm tra lại tính toàn vẹn trước khi tải
        current_hash = calculate_sha256(file['download_path'])
        if current_hash != file['hash']:
            return jsonify({
                'status': 'error',
                'message': 'File có thể đã bị thay đổi. Vui lòng xác thực lại.'
            })
            
        return send_file(
            file['download_path'],
            as_attachment=True,
            download_name=file['original_filename']
        )

    except Exception as e:
        print(f"Download error: {str(e)}")
        return jsonify({'status': 'error', 'message': str(e)})

def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            return jsonify({'status': 'error', 'message': 'Not logged in'})
        return f(*args, **kwargs)
    return decorated_function

if __name__ == '__main__':
    # Start file transfer server in background thread
    transfer_server = FileTransferServer()
    server_thread = threading.Thread(target=transfer_server.start)
    server_thread.daemon = True
    server_thread.start()
    
    # Start web server
    app.run(debug=True, host='0.0.0.0', port=5000)