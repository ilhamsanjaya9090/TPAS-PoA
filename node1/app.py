from flask import Flask, render_template, request, session, redirect, url_for, flash, jsonify
from werkzeug.utils import secure_filename
from werkzeug.security import generate_password_hash, check_password_hash
from pymongo import MongoClient
from bson import ObjectId
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
from reportlab.lib.utils import ImageReader
from PIL import Image
from io import BytesIO
import json
import sys
import os
import requests


sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '../shared')))
from shared.blockchain import Blockchain
app = Flask(__name__, template_folder='templates')
app.secret_key = 'your_secret_key'
client = MongoClient("mongodb://localhost:27017/")
db = client['blockchain_db']
users_collection = db['users']
documents_collection = db['documents']
fs = gridfs.GridFS(db)

blockchain = Blockchain()
def load_validators_from_db():
    """Muat kembali validator dari MongoDB ke Blockchain saat server Flask dimulai."""
    validators = users_collection.find({"is_validator": True}, {"username": 1, "_id": 0})
    for validator in validators:
        blockchain.register_validator(validator['username'], "Public_Key_Placeholder")

UPLOAD_FOLDER = 'uploads'
os.makedirs(UPLOAD_FOLDER, exist_ok=True)

# Panggil fungsi saat server mulai
load_validators_from_db()


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

@app.route('/login', methods=['GET', 'POST'])
def login_page():
    if request.method == 'POST':
        data = request.form
        username = data.get('username')
        password = data.get('password')

        user = users_collection.find_one({"username": username})

        if user:
            print(f"🛠️ DEBUG: User found: {user}")  # Menampilkan data user di terminal

        if not user or not check_password_hash(user['password'], password):
            flash('Invalid username or password.', 'error')
            return redirect(url_for('login_page'))

        # Simpan user ke session tanpa admin
        session['user'] = username

        flash('Welcome back!', 'success')
        return redirect(url_for('dashboard_page'))

    return render_template('login.html')


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

    current_user = session['user']
    
    # Ambil semua dokumen yang dimiliki atau dibagikan kepada user
    documents = list(documents_collection.find(
        {'$or': [{'username': current_user}, {'shared_with': {"$in": [current_user]}}]},
        projection={'_id': 1, 'filename': 1, 'status': 1, 'shared_with': 1, 'file_id': 1}
    ))


    for doc in documents:
        if 'file_id' in doc:
            doc['file_id'] = str(doc['file_id'])  # ✅ Konversi ObjectId ke string
    
    user_info = users_collection.find_one(
        {'username': current_user},
        {'_id': 0, 'username': 1, 'is_validator': 1}
    )

    return render_template(
        'dashboard.html',
        documents=documents,
        user_info=user_info
    )

@app.route('/upload', methods=['GET', 'POST'])
def upload_page():
    if 'user' not in session:
        flash('Please login to upload files.', 'error')
        return redirect(url_for('login_page'))

    # Cek apakah user adalah validator
    user = users_collection.find_one({"username": session['user']})
    if not user.get("is_validator", False):
        flash('Only validators can upload files.', 'error')
        return redirect(url_for('dashboard_page'))

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
        file_id = fs.put(file_content, filename=filename)  # ✅ Pastikan file masuk ke GridFS
        file_hash = hashlib.sha256(file_content).hexdigest()

        # Simpan metadata file ke database
        result = documents_collection.insert_one({
            'username': session['user'],
            'sender': session['user'],
            'filename': filename,
            'file_hash': file_hash,
            'file_id': file_id,  # ✅ Pastikan ini tersimpan
            'status': 'Uploaded'
        })

        if result.inserted_id:
            flash('Document uploaded successfully.', 'success')
        else:
            flash('Error saving document to database.', 'error')

        return redirect(url_for('dashboard_page'))

    return render_template('upload.html')

@app.route('/create_incomplete_signature/<file_id>', methods=['POST'])
def create_incomplete_signature(file_id):
    if 'user' not in session:
        flash('Unauthorized access.', 'error')
        return redirect(url_for('login_page'))

    current_user = session['user']
    user_info = users_collection.find_one({'username': current_user})

    if not user_info or not user_info.get('is_validator', False):
        flash('Only validators can sign documents.', 'error')
        return redirect(url_for('dashboard_page'))

    try:
        document = documents_collection.find_one({'file_id': ObjectId(file_id)})
        if not document:
            flash('Document not found.', 'error')
            return redirect(url_for('dashboard_page'))

        if document['status'] != 'Uploaded':
            flash('Document must be in "Uploaded" status to sign.', 'error')
            return redirect(url_for('dashboard_page'))

        file = fs.get(ObjectId(file_id))
        file_content = file.read()

        # 🔑 Buat tanda tangan digital ECDSA
        private_key = ecdsa.SigningKey.generate(curve=ecdsa.SECP256k1)
        incomplete_signature = private_key.sign(file_content).hex()

        # 📝 Simpan tanda tangan dalam database
        documents_collection.update_one(
            {'file_id': ObjectId(file_id)},
            {'$set': {
                'incomplete_signature': incomplete_signature,
                'status': 'Incomplete Signature'
            }}
        )

        # 🔗 Tambahkan ke Blockchain
        blockchain.create_block(
            validator=current_user,
            data={
                "action": "Create Incomplete Signature",
                "username": session['user'],
                "filename": document['filename'],
                "file_hash": document['file_hash'],
                "incomplete_signature": incomplete_signature,
                "status": "Incomplete Signature"
            },
            previous_hash=blockchain.get_previous_block()['hash']
        )

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
    user = users_collection.find_one({"username": current_user})

    if not user.get("is_validator", False):
        flash('Only validators can complete signatures.', 'error')
        return redirect(url_for('dashboard_page'))

    witness = request.form.get('witness')
    if not witness:
        flash('Witness is required to complete the signature.', 'error')
        return redirect(url_for('dashboard_page'))

    try:
        document = documents_collection.find_one({'file_id': ObjectId(file_id)})
        if not document:
            flash('Document not found.', 'error')
            return redirect(url_for('dashboard_page'))

        if 'incomplete_signature' not in document:
            flash('This document has no incomplete signature to complete.', 'error')
            return redirect(url_for('dashboard_page'))

        completed_signature = document['incomplete_signature'] + f"-witness-{witness}"

        # 🔍 Ambil file PDF dari GridFS
        file = fs.get(ObjectId(file_id))
        pdf_content = file.read()

        # 🔍 Buat QR Code dengan data blockchain
        block_data = blockchain.get_previous_block()
        qr_data = json.dumps({
            "block_number": block_data['index'],
            "block_hash": block_data['hash'],
            "filename": document['filename'],
            "file_hash": document['file_hash'],
            "signature_status": "Signature Completed"
        }, indent=4)

        qr = qrcode.QRCode(
            version=1,
            error_correction=qrcode.constants.ERROR_CORRECT_H,
            box_size=10,
            border=4,
        )
        qr.add_data(qr_data)
        qr.make(fit=True)

        # 🔍 Simpan QR Code ke dalam BytesIO
        qr_code_buffer = BytesIO()
        qr_image = qr.make_image(fill_color="black", back_color="white")
        qr_image.save(qr_code_buffer, format="PNG")
        qr_code_buffer.seek(0)

        # 🔍 Tambahkan QR Code ke dalam halaman pertama PDF
        pdf_reader = PdfReader(BytesIO(pdf_content))
        pdf_writer = PdfWriter()

        overlay_buffer = BytesIO()
        can = canvas.Canvas(overlay_buffer, pagesize=letter)
        qr_image_reader = ImageReader(qr_code_buffer)

        # Atur posisi barcode pada halaman pertama
        can.drawImage(qr_image_reader, 400, 50, width=150, height=150)
        can.showPage()
        can.save()

        overlay_buffer.seek(0)
        overlay_reader = PdfReader(overlay_buffer)

        for index, page in enumerate(pdf_reader.pages):
            if index == 0:  
                page.merge_page(overlay_reader.pages[0])  # Gabungkan halaman QR dengan PDF asli

            pdf_writer.add_page(page)

        # 🔍 Simpan PDF yang telah diperbarui ke GridFS
        updated_pdf_buffer = BytesIO()
        pdf_writer.write(updated_pdf_buffer)
        updated_pdf_buffer.seek(0)

        updated_file_id = fs.put(updated_pdf_buffer.getvalue(), filename=f"{document['filename']}_signed.pdf")

        # 🔍 Perbarui dokumen di MongoDB
        documents_collection.update_one(
            {'file_id': ObjectId(file_id)},
            {'$set': {
                'completed_signature': completed_signature,
                'status': 'Complete Signature',
                'updated_file_id': updated_file_id
            }}
        )

        # 🔍 Tambahkan ke Blockchain
        blockchain.create_block(
            validator=current_user,
            data={
                "action": "Complete Signature",
                "username": current_user,
                "filename": document['filename'],
                "file_hash": document['file_hash'],
                "incomplete_signature": document['incomplete_signature'],
                "completed_signature": completed_signature,
                "barcode_file_id": str(updated_file_id),
                "status": "Signature Completed"
            },
            block_type="Complete Signature"
        )

        print(f"✅ Signature Completed: {completed_signature}")
        print(f"✅ Updated File ID: {updated_file_id}")

        flash('Signature completed and barcode embedded into the PDF successfully.', 'success')
        return redirect(url_for('dashboard_page'))

    except Exception as e:
        print(f"❌ Error completing signature: {e}")
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
        flash('Recipient not found.', 'error')
        return redirect(url_for('dashboard_page'))

    document = documents_collection.find_one({'file_id': ObjectId(file_id)})
    if not document:
        flash('Document not found.', 'error')
        return redirect(url_for('dashboard_page'))

    sender = session['user']

    # ✅ Jika dokumen masih "Incomplete Signature", hanya bisa dikirim ke Validator
    if document['status'] == 'Incomplete Signature':
        if not recipient_user.get('is_validator', False):
            flash('Recipient must be a validator.', 'error')
            return redirect(url_for('dashboard_page'))
        new_status = "Incomplete Signature"  # Status tetap agar tombol "Complete Signature" muncul

    # ✅ Jika dokumen sudah "Complete Signature", bisa dikirim ke Non-Validator
    elif document['status'] == 'Complete Signature':
        new_status = "Sent to Non-Validator"

    else:
        flash('Document cannot be sent.', 'error')
        return redirect(url_for('dashboard_page'))

    # ✅ Perbarui shared_with agar penerima bisa melihat dokumen
    documents_collection.update_one(
        {'file_id': ObjectId(file_id)},
        {
            '$addToSet': {'shared_with': recipient},  # Tambahkan penerima ke daftar shared_with
            '$set': {'status': new_status}
        }
    )

    # ✅ Tambahkan ke Blockchain
    blockchain.create_block(
        validator=sender,
        data={
            "action": "Send Document",
            "sender": sender,
            "recipient": recipient,
            "filename": document['filename'],
            "status": new_status
        }
    )

    flash(f'Document sent successfully to {recipient}.', 'success')
    return redirect(url_for('dashboard_page'))


@app.route('/validate_blockchain', methods=['GET'])
def validate_blockchain():
    if blockchain.validate_chain():
        return "Blockchain is valid!", 200
    else:
        return "Blockchain is invalid!", 400


@app.route('/view_blockchain', methods=['GET'])
def view_blockchain_ui():
    blockchain_data = []
    for block in blockchain.chain:
        block_copy = block.copy()
        block_copy['timestamp'] = datetime.fromtimestamp(block['timestamp']).strftime('%Y-%m-%d %H:%M:%S')
        blockchain_data.append(block_copy)
        
    if not blockchain_data:
        flash('No blocks found in the blockchain.', 'info')
        
    return render_template('view_blockchain.html', blockchain=blockchain_data)

@app.route('/download/<file_id>', methods=['GET'])
def download_file(file_id):
    print(f"🔍 Download request received for file_id: {file_id}")  # Debugging

    try:
        # ✅ Ambil dokumen berdasarkan file_id
        document = documents_collection.find_one({'file_id': ObjectId(file_id)})

        # ✅ Gunakan updated_file_id jika ada
        if document and 'updated_file_id' in document:
            file_id = document['updated_file_id']  # Ambil file yang telah diperbarui

        # ✅ Ambil file dari GridFS berdasarkan file_id yang telah diperbarui
        file = fs.get(ObjectId(file_id))

        response = app.response_class(file.read(), mimetype="application/pdf")
        response.headers.set('Content-Disposition', f'attachment; filename={file.filename}')
        return response

    except Exception as e:
        print(f"❌ Error: {e}")  # Debugging
        flash(f'Error while downloading file: {e}', 'error')
        return redirect(url_for('dashboard_page'))


@app.route('/preview/<file_id>', methods=['GET'])
def preview_file(file_id):
    print(f"🔍 Preview request received for file_id: {file_id}")  # Debugging
    try:
        document = documents_collection.find_one({'file_id': ObjectId(file_id)})
        
        if 'updated_file_id' in document:
            file_id = document['updated_file_id']  # Gunakan file yang telah diperbarui
        
        file = fs.get(ObjectId(file_id))
        mime_type, _ = mimetypes.guess_type(file.filename)
        mime_type = mime_type or "application/pdf"
        response = app.response_class(file.read(), mimetype=mime_type)
        response.headers.set('Content-Disposition', f'inline; filename={file.filename}')
        return response
    except Exception as e:
        print(f"❌ Error: {e}")  # Debugging
        flash('File not found.', 'error')
        return redirect(url_for('dashboard_page'))


@app.route('/delete/<file_id>', methods=['POST'])
def delete_file(file_id):
    print(f"🔍 Delete request received for file_id: {file_id}")  # Debugging
    if 'user' not in session:
        flash('Unauthorized access.', 'error')
        return redirect(url_for('login_page'))
    try:
        fs.delete(ObjectId(file_id))
        documents_collection.delete_one({'file_id': ObjectId(file_id)})
        flash('File deleted successfully.', 'success')
    except Exception as e:
        print(f"❌ Error: {e}")  # Debugging
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
    """Menambahkan validator baru ke blockchain dan MongoDB."""
    node_address = request.json.get('node_address')
    public_key = request.json.get('public_key')

    if not node_address or not public_key:
        return jsonify({"error": "Node address and public key are required"}), 400

    # Cek apakah validator sudah ada di database
    if users_collection.find_one({"username": node_address, "is_validator": True}):
        return jsonify({"message": f"Validator {node_address} is already registered."}), 200

    # Simpan validator ke database
    users_collection.update_one(
        {"username": node_address},
        {"$set": {"is_validator": True}},
        upsert=True
    )

    # Tambahkan ke blockchain
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

@app.route('/get_validators', methods=['GET'])
def get_validators():
    return jsonify({"validators": list(blockchain.validators.keys())}), 200

@app.route('/get_validators_from_db', methods=['GET'])
def get_validators_from_db():
    """Mengambil validator dari MongoDB dan mengupdate blockchain."""
    validators = users_collection.find({"is_validator": True}, {"username": 1, "_id": 0})
    validators_list = [v['username'] for v in validators]

    # Pastikan semua validator dari database juga ada di blockchain
    for validator in validators_list:
        if validator not in blockchain.validators:
            blockchain.register_validator(validator, "Public_Key_Placeholder")

    return jsonify({"validators": list(blockchain.validators.keys())}), 200


if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0', port=5000)




