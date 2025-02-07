from flask import Flask, render_template, request, session, redirect, url_for, flash, jsonify
from werkzeug.utils import secure_filename
from werkzeug.security import generate_password_hash, check_password_hash
from pymongo import MongoClient
from bson import ObjectId
from shared.blockchain import Blockchain
from datetime import datetime
import gridfs
import hashlib
import ecdsa
import os
import mimetypes
import qrcode
from PyPDF2 import PdfReader, PdfWriter
from reportlab.pdfgen import canvas
from reportlab.lib.pagesizes import letter
from PIL import Image
from io import BytesIO
import json
import sys
import os
import requests

# Tambahkan folder shared ke sys.path
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '../shared')))

from blockchain import Blockchain


app = Flask(__name__, template_folder='templates')
app.secret_key = 'your_secret_key'

# Koneksi ke MongoDB
client = MongoClient("mongodb://localhost:27017/")
db = client['blockchain_db']
users_collection = db['users']
documents_collection = db['documents']

# GridFS untuk menyimpan file di MongoDB
fs = gridfs.GridFS(db)

# Folder upload
UPLOAD_FOLDER = 'uploads'
os.makedirs(UPLOAD_FOLDER, exist_ok=True)

blockchain = Blockchain()

@app.route('/login', methods=['GET', 'POST'])
def login_page():
    if request.method == 'POST':
        data = request.form
        username = data.get('username')
        password = data.get('password')

        user = users_collection.find_one({"username": username})
        if not user or not check_password_hash(user['password'], password):
            flash('Invalid username or password.', 'error')
            return redirect(url_for('login_page'))

        session['user'] = username
        flash('Welcome back!', 'success')
        return redirect(url_for('dashboard_page'))

    return render_template('login.html')


@app.route('/register', methods=['GET', 'POST'])
def register_page():
    if request.method == 'POST':
        data = request.form
        username = data.get('username')
        password = data.get('password')
        confirm_password = data.get('confirm_password')

        if not username or not password:
            flash('Username and password are required.', 'error')
            return redirect(url_for('register_page'))

        if password != confirm_password:
            flash('Passwords do not match.', 'error')
            return redirect(url_for('register_page'))

        if users_collection.find_one({"username": username}):
            flash('Username already exists.', 'error')
            return redirect(url_for('register_page'))

        hashed_password = generate_password_hash(password)
        users_collection.insert_one({"username": username, "password": hashed_password})
        flash('Registration successful. Please login.', 'success')
        return redirect(url_for('login_page'))

    return render_template('register.html')


@app.route('/logout', methods=['GET'])
def logout_page():
    session.pop('user', None)
    flash('Logged out successfully.', 'success')
    return redirect(url_for('login_page'))


@app.route('/dashboard', methods=['GET'])
def dashboard_page():
    if 'user' not in session:
        flash('Please login to access the dashboard.', 'error')
        return redirect(url_for('login_page'))

    documents = list(documents_collection.find({
        '$or': [
            {'username': session['user']},
            {'sender': session['user']}
        ]
    }))

    user_info = users_collection.find_one({'username': session['user']}, {'_id': 0, 'username': 1})
    users = list(users_collection.find({'username': {'$ne': session['user']}}, {'_id': 0, 'username': 1}))

    return render_template('dashboard.html', documents=documents, users=users, user_info=user_info)


@app.route('/upload', methods=['GET', 'POST'])
def upload_page():
    if 'user' not in session:
        flash('Please login to upload files.', 'error')
        return redirect(url_for('login_page'))

    if request.method == 'POST':
        if 'file' not in request.files:
            flash('No file uploaded.', 'error')
            return redirect(url_for('upload_page'))

        file = request.files['file']
        if file.filename == '':
            flash('No file selected.', 'error')
            return redirect(url_for('upload_page'))

        filename = secure_filename(file.filename)
        file_content = file.read()
        file_id = fs.put(file_content, filename=filename)
        file_hash = hashlib.sha256(file_content).hexdigest()

        documents_collection.insert_one({
            'username': session['user'],
            'sender': session['user'],
            'filename': filename,
            'file_hash': file_hash,
            'file_id': file_id,
            'status': 'Uploaded'
        })

        # Tambahkan ke blockchain
        blockchain.create_block(data={
            "action": "Upload",
            "username": session['user'],
            "filename": filename,
            "file_hash": file_hash,
            "status": "Uploaded"
        }, previous_hash=blockchain.get_previous_block()['hash'])

        flash('Document uploaded successfully.', 'success')
        return redirect(url_for('dashboard_page'))

    return render_template('upload.html')


@app.route('/create_incomplete_signature/<file_id>', methods=['POST'])
def create_incomplete_signature(file_id):
    if 'user' not in session:
        flash('Unauthorized access.', 'error')
        return redirect(url_for('login_page'))

    try:
        document = documents_collection.find_one({'file_id': ObjectId(file_id), 'sender': session['user']})
        if not document:
            flash('You can only create signatures for documents you uploaded.', 'error')
            return redirect(url_for('dashboard_page'))

        file = fs.get(ObjectId(file_id))
        file_content = file.read()

        private_key = ecdsa.SigningKey.generate(curve=ecdsa.SECP256k1)
        incomplete_signature = private_key.sign(file_content)

        documents_collection.update_one(
            {'file_id': ObjectId(file_id)},
            {'$set': {
                'incomplete_signature': incomplete_signature.hex(),
                'status': 'Incomplete Signature'
            }}
        )

        # Tambahkan ke blockchain
        blockchain.create_block(data={
            "action": "Create Incomplete Signature",
            "username": session['user'],
            "filename": document['filename'],
            "file_hash": document['file_hash'],
            "incomplete_signature": incomplete_signature.hex(),
            "status": "Incomplete Signature"
        }, previous_hash=blockchain.get_previous_block()['hash'])

        flash('Incomplete Signature created successfully.', 'success')
        return redirect(url_for('dashboard_page'))
    except Exception as e:
        flash(f'Error creating incomplete signature: {e}', 'error')
        return redirect(url_for('dashboard_page'))

@app.route('/complete_signature/<file_id>', methods=['POST'])
def complete_signature(file_id):
    if 'user' not in session:
        flash('Unauthorized access.', 'error')
        return redirect(url_for('login_page'))

    current_user = session['user']
    witness = request.form.get('witness')
    if not witness:
        flash('Witness is required to complete the signature.', 'error')
        return redirect(url_for('dashboard_page'))

    try:
        document = documents_collection.find_one({'file_id': ObjectId(file_id), 'username': current_user})
        if not document:
            flash('You are not authorized to complete this signature.', 'error')
            return redirect(url_for('dashboard_page'))

        completed_signature = document['incomplete_signature'] + f"-witness-{witness}"

        # Ambil file PDF dari GridFS
        file = fs.get(ObjectId(file_id))
        pdf_content = file.read()

        # Buat barcode
        block_data = blockchain.get_previous_block()
        barcode_data = json.dumps ({
            "block_number": block_data['index'],
            "block_hash": block_data['hash'],
            "filename": document['filename'],
            "file_hash": document['file_hash'],
            "signature_status": "Signature Completed"
        })

        qr = qrcode.QRCode(
            version=1,
            error_correction=qrcode.constants.ERROR_CORRECT_H,
            box_size=20,
            border=4,
        )
        qr.add_data(barcode_data)
        qr.make(fit=True)


        # Simpan barcode sebagai file sementara
        barcode_file_path = "barcode_temp.png"
        barcode_img = qr.make_image(fill_color="black", back_color="white")
        barcode_img.save(barcode_file_path)

        # Tambahkan barcode ke PDF
        barcode_pdf = BytesIO()
        can = canvas.Canvas(barcode_pdf, pagesize=letter)

        # Gunakan path file untuk menggambar barcode
        can.drawImage(barcode_file_path, 400, 50, width=100, height=100)  # Atur posisi barcode
        can.save()

        # Hapus file barcode sementara
        os.remove(barcode_file_path)

        # Gabungkan barcode ke PDF asli
        barcode_pdf.seek(0)
        barcode_reader = PdfReader(barcode_pdf)
        original_reader = PdfReader(BytesIO(pdf_content))
        writer = PdfWriter()

        for index, page in enumerate(original_reader.pages):
            # Tambahkan barcode hanya di halaman pertama
            if index == 0:
                barcode_page = barcode_reader.pages[0]
                page.merge_page(barcode_page)
            writer.add_page(page)

        # Simpan hasil PDF baru dengan barcode ke GridFS
        updated_pdf = BytesIO()
        writer.write(updated_pdf)
        updated_pdf.seek(0)


        updated_file_id = fs.put(updated_pdf, filename=f"{document['filename']}_signed.pdf")

        # Update status dokumen di MongoDB
        documents_collection.update_one(
            {'file_id': ObjectId(file_id)},
            {'$set': {
                'completed_signature': completed_signature,
                'status': 'Complete Signature',
                'updated_file_id': updated_file_id
            }}
        )

        # Tambahkan ke blockchain
        blockchain.create_block(data={
            "action": "Complete Signature",
            "username": current_user,
            "filename": document['filename'],
            "file_hash": document['file_hash'],
            "incomplete_signature": document['incomplete_signature'],
            "completed_signature": completed_signature,
            "barcode_file_id": str(updated_file_id),
            "status": "Signature Completed"
        }, previous_hash=blockchain.get_previous_block()['hash'])

        flash('Signature completed and barcode embedded into the PDF successfully.', 'success')
        return redirect(url_for('dashboard_page'))
    except Exception as e:
        flash(f'Error completing signature: {e}', 'error')
        return redirect(url_for('dashboard_page'))


@app.route('/send_document/<file_id>', methods=['POST'])
def send_document(file_id):
    if 'user' not in session:
        flash('Unauthorized access.', 'error')
        return redirect(url_for('login_page'))

    recipient = request.form.get('recipient')
    if not recipient:
        flash('Recipient username is required.', 'error')
        return redirect(url_for('dashboard_page'))

    recipient_user = users_collection.find_one({'username': recipient})
    if not recipient_user:
        flash('Recipient user does not exist.', 'error')
        return redirect(url_for('dashboard_page'))

    try:
        document = documents_collection.find_one({'file_id': ObjectId(file_id)})
        if not document:
            flash('Document not found.', 'error')
            return redirect(url_for('dashboard_page'))

        if document.get('username') == recipient:
            flash('Document is already assigned to this user.', 'warning')
            return redirect(url_for('dashboard_page'))

        # Update penerima dokumen
        documents_collection.update_one(
            {'file_id': ObjectId(file_id)},
            {'$set': {
                'username': recipient,
                'status': 'Incomplete Signature'
            }}
        )

        # Tambahkan ke blockchain
        blockchain.create_block(data={
            "action": "Send Document",
            "sender": session['user'],
            "recipient": recipient,
            "filename": document['filename'],
            "status": "Incomplete Signature"
        }, previous_hash=blockchain.get_previous_block()['hash'])

        flash('Document sent successfully.', 'success')
        return redirect(url_for('dashboard_page'))
    except Exception as e:
        flash(f'Error while sending document: {e}', 'error')
        return redirect(url_for('dashboard_page'))

@app.route('/validate_blockchain', methods=['GET'])
def validate_blockchain():
    if blockchain.validate_chain():
        return "Blockchain is valid!", 200
    else:
        return "Blockchain is invalid!", 400

from datetime import datetime

@app.route('/view_blockchain', methods=['GET'])
def view_blockchain_ui():
    # Ambil blockchain dari objek blockchain
    blockchain_data = []
    for block in blockchain.chain:
        # Convert timestamp to human-readable format
        block_copy = block.copy()
        block_copy['timestamp'] = datetime.fromtimestamp(block['timestamp']).strftime('%Y-%m-%d %H:%M:%S')
        blockchain_data.append(block_copy)
    return render_template('view_blockchain.html', blockchain=blockchain_data)




@app.route('/download/<file_id>', methods=['GET'])
def download_file(file_id):
    try:
        file = fs.get(ObjectId(file_id))
        response = app.response_class(file.read(), mimetype="application/octet-stream")
        response.headers.set('Content-Disposition', f'attachment; filename={file.filename}')
        return response
    except gridfs.errors.NoFile:
        flash('File not found.', 'error')
        return redirect(url_for('dashboard_page'))


@app.route('/preview/<file_id>', methods=['GET'])
def preview_file(file_id):
    try:
        # Cek apakah file sudah diperbarui
        document = documents_collection.find_one({'file_id': ObjectId(file_id)})
        if 'updated_file_id' in document:
            file_id = document['updated_file_id']  # Gunakan file yang sudah diperbarui

        file = fs.get(ObjectId(file_id))
        mime_type, _ = mimetypes.guess_type(file.filename)
        mime_type = mime_type or "application/pdf"

        response = app.response_class(file.read(), mimetype=mime_type)
        response.headers.set('Content-Disposition', f'inline; filename={file.filename}')
        return response
    except gridfs.errors.NoFile:
        flash('File not found.', 'error')
        return redirect(url_for('dashboard_page'))



@app.route('/delete/<file_id>', methods=['POST'])
def delete_file(file_id):
    if 'user' not in session:
        flash('Unauthorized access.', 'error')
        return redirect(url_for('login_page'))

    try:
        fs.delete(ObjectId(file_id))
        documents_collection.delete_one({'file_id': ObjectId(file_id)})
        flash('File deleted successfully.', 'success')
        return redirect(url_for('dashboard_page'))
    except Exception as e:
        flash(f'Error while deleting file: {e}', 'error')
        return redirect(url_for('dashboard_page'))

@app.route('/add_validator', methods=['POST'])
def add_validator():
    node_address = request.json.get('node_address')
    blockchain.add_node(node_address)
    return jsonify({"message": f"Validator {node_address} added."}), 200


@app.route('/sync', methods=['POST'])
def sync():
    chain_data = request.json.get('chain')
    new_chain = [dict(block) for block in chain_data]
    replaced = blockchain.replace_chain(new_chain)
    if replaced:
        return jsonify({"message": "Blockchain replaced with the longest chain."}), 200
    else:
        return jsonify({"message": "Current chain is already the longest."}), 200

@app.route('/add_block', methods=['POST'])
def add_block():
    """Hanya validator yang bisa menambang blok baru."""
    data = request.json.get('data')
    validator = request.json.get('validator')

    if validator not in blockchain.validators:
        return jsonify({"error": "Validator not authorized"}), 403

    try:
        block = blockchain.create_block(validator, data)
        return jsonify(block), 201
    except ValueError as e:
        return jsonify({"error": str(e)}), 403


@app.route('/register_validator', methods=['POST'])
def register_validator():
    """Menambahkan validator baru ke blockchain."""
    node_address = request.json.get('node_address')
    public_key = request.json.get('public_key')

    if not node_address or not public_key:
        return jsonify({"error": "Node address and public key are required"}), 400

    blockchain.register_validator(node_address, public_key)
    return jsonify({"message": f"Validator {node_address} added successfully."}), 200

@app.route('/sync_chain', methods=['GET'])
def sync_chain():
    """Sinkronisasi blockchain dengan node lain di jaringan."""
    for node in blockchain.nodes:
        try:
            response = requests.get(f'http://{node}/get_chain')
            if response.status_code == 200:
                new_chain = response.json()['chain']
                blockchain.replace_chain(new_chain)
        except requests.exceptions.RequestException:
            continue

    return jsonify({"message": "Blockchain synchronized"}), 200


@app.route('/get_chain', methods=['GET'])
def get_chain():
    """Mengambil seluruh blockchain."""
    return jsonify({"chain": blockchain.chain}), 200


if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0', port=5001)
