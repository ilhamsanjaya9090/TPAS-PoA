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
import requests
import uuid
from getmac import get_mac_address
from shared.tpas_crypto import generate_keypair
import threading
import time
import bson
import psutil
import re

sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from shared import tpas_crypto
from shared.blockchain import Blockchain
from shared.config import PEER_NODES, MY_NODE_URL, MONGO_URL



app = Flask(__name__, template_folder='templates')
app.secret_key = 'your_secret_key'
app.config['UPLOAD_FOLDER'] = os.path.join(os.getcwd(), 'uploads')
# MongoDB config
client = MongoClient(MONGO_URL)
db = client['blockchain_db']
users_collection = db['users']
documents_collection = db['documents']
fs = gridfs.GridFS(db)

blocks_collection = db['blocks']
blockchain = Blockchain(users_collection=users_collection)
UPLOAD_FOLDER = 'uploads'
os.makedirs(UPLOAD_FOLDER, exist_ok=True)



def get_mac_address():
    """
    
    """
    for interface, addrs in psutil.net_if_addrs().items():
        if re.search(r"vmware|virtual|loopback|bluetooth", interface, re.IGNORECASE):
            continue  # lewati interface virtual

        for addr in addrs:
            if addr.family == psutil.AF_LINK:
                mac = addr.address.upper()
                if re.match(r"^([0-9A-F]{2}[:-]){5}([0-9A-F]{2})$", mac, re.IGNORECASE):
                    return mac
    raise ValueError("Tidak ditemukan MAC address dari interface aktif.")


def get_user_role(username):
    user = users_collection.find_one({'username': username})
    return user.get("role", "non-validator") if user else "non-validator"

def load_validators_from_db():
    validators = users_collection.find({"role": "validator"}, {"username": 1, "public_key": 1})
    for v in validators:
        if 'public_key' in v:
            blockchain.register_validator(v['username'], v['public_key'])


load_validators_from_db()


def sync_with_peer():
    while True:
        try:
            for node in PEER_NODES:
                if node != MY_NODE_URL:
                    response = requests.get(f"{node}/get_blocks")
                    peer_chain = response.json()

                    if blockchain.replace_chain(peer_chain):
                        blockchain.chain = peer_chain
                        blockchain.save_chain()  # opsional
                        print(f"🔄 Synced chain from {node}")
        except Exception as e:
            print(f"⚠️ Sync error: {e}")
        time.sleep(10)  # Sync setiap 10 detik

# Jalankan thread di background
sync_thread = threading.Thread(target=sync_with_peer, daemon=True)
sync_thread.start()

def serialize_block(block):
    if isinstance(block, dict):
        return {k: serialize_block(v) for k, v in block.items()}
    elif isinstance(block, list):
        return [serialize_block(i) for i in block]
    elif isinstance(block, bson.ObjectId):
        return str(block)
    else:
        return block

@app.route('/register', methods=['GET', 'POST'])
def register_page():
    if request.method == 'POST':
        username = request.form.get('username') 
        password = request.form.get('password')
        confirm = request.form.get('confirm_password')
        role = request.form.get('role', 'non-validator')
        mac_address = get_mac_address()

        if not username or not password or not confirm:
            flash('All fields are required.', 'error')
            return redirect(url_for('register_page'))

        if password != confirm:
            flash('Passwords do not match.', 'error')
            return redirect(url_for('register_page'))

        existing_user = users_collection.find_one({'username': username})
        if existing_user:
            flash('Username already exists.', 'error')
            return redirect(url_for('register_page'))

        # Hash password
        hashed_pw = generate_password_hash(password)

        # Generate Key Pair
        private_key, public_key = generate_keypair()

        # Simpan ke database
        users_collection.insert_one({
            'username': username,
            'password': hashed_pw,
            'role': role,
            'mac_address': mac_address,
            'private_key': private_key.to_string().hex(),
            'public_key': public_key.to_string().hex()
        })

        flash('Registration successful. Please login.', 'success')
        return redirect(url_for('login_page'))

    return render_template('register.html')


@app.route('/login', methods=['GET', 'POST'])
def login_page():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        mac_address = get_mac_address()

        user = users_collection.find_one({'username': username})

        if not user:
            flash('Username not found.', 'error')
            return redirect(url_for('login_page'))

        if not check_password_hash(user['password'], password):
            flash('Incorrect password.', 'error')
            return redirect(url_for('login_page'))       

        
        ## if user.get('mac_address') != mac_address:
        ##    flash('Unauthorized device.', 'error')
        ##    return redirect(url_for('login_page'))

        session['user'] = user['username']
        flash('Login successful.', 'success')

        # ✅ Jika role validator, daftar ke blockchain jika belum
        if user.get("role") == "validator" and user['username'] not in blockchain.validators:
            blockchain.register_validator(user['username'], user['public_key'])
        return redirect(url_for('dashboard_page'))

    return render_template('login.html')

@app.route('/logout')
def logout():
    session.pop('user', None)
    flash('Logged out.', 'success')
    session.clear()
    return redirect(url_for('login_page'))

@app.route('/dashboard', methods=['GET'])
def dashboard_page():
    if 'user' not in session:
        flash('Please login to access the dashboard.', 'error')
        return redirect(url_for('login_page'))

    current_user = session['user']

    documents = list(documents_collection.find(
        {'$or': [{'username': current_user}, {'shared_with': {"$in": [current_user]}}]},
        projection={'_id': 1, 'filename': 1, 'status': 1, 'shared_with': 1, 'file_id': 1, 'username': 1}
    ))

    for doc in documents:
        if 'file_id' in doc:
            doc['file_id'] = str(doc['file_id'])

    user_info = users_collection.find_one({'username': current_user})
    role = user_info.get('role', 'non-validator')  # default kalau tidak ada

    # Untuk dropdown user
    all_users = users_collection.find({"username": {"$ne": current_user}}, {"_id": 0, "username": 1})
    user_list = [u["username"] for u in all_users]

    return render_template(
        'dashboard.html',
        documents=documents,
        user=current_user,         # ⬅️ penting!
        role=role,                 # ⬅️ penting!
        user_list=user_list
    )

@app.route('/upload', methods=['GET', 'POST'])
def upload():
    if request.method == 'POST':
        username = request.form.get('uploader') or session.get('username')
        if not username:
            return jsonify({'error': 'Unauthorized'}), 401

        user = users_collection.find_one({'username': username})
        if not user:
            return jsonify({'error': 'User not found'}), 404

        file = request.files.get('file')
        recipient = request.form.get('recipient')
        if not file or not recipient:
            return jsonify({'error': 'File or recipient missing'}), 400

        filename = secure_filename(file.filename)
        file_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
        file.save(file_path)

        doc_data = {
            'filename': filename,
            'filepath': file_path,
            'doc_id': str(doc_id),
            'uploader': username,
            'recipient': recipient,
            'status': 'pending',
            'timestamp': datetime.now(),
            'shared_with': [recipient]
        }

        result = documents_collection.insert_one(doc_data)
        doc_id = str(result.inserted_id)

        # Tambahkan block ke blockchain
        blockchain.create_block(
            block_type='upload',
            data={**doc_data, '_id': doc_id, "doc_id": str(doc_id)},
            username=username
        )

        return jsonify({'message': 'Upload success', 'doc_id': doc_id}), 200

    # Jika GET
    users = users_collection.find({'username': {'$ne': session.get('username')}})
    return render_template('upload.html', users=users)



@app.route('/send_document/<file_id>', methods=['POST'])
def send_document(file_id):
    if 'user' not in session:
        return redirect(url_for('login_page'))

    sender = session['user']
    recipient = request.form.get('recipient')
    if not recipient:
        flash('Recipient is required.', 'error')
        return redirect(url_for('dashboard_page'))

    document = documents_collection.find_one({'file_id': ObjectId(file_id)})
    if not document:
        flash('Document not found.', 'error')
        return redirect(url_for('dashboard_page'))

    status = document['status']
    if status in ['Uploaded', 'Incomplete Signature'] and get_user_role(recipient) != "validator":
        flash('Can only send to validator at this stage.', 'error')
        return redirect(url_for('dashboard_page'))

    new_status = "Incomplete Signature" if status == 'Incomplete Signature' else \
                 "Sent to Non-Validator" if status == 'Complete Signature' else status

    documents_collection.update_one(
        {'file_id': ObjectId(file_id)},
        {'$addToSet': {'shared_with': recipient}, '$set': {'status': new_status}}
    )

    blockchain.create_block(
        validator=sender,
        data={"action": "Send Document", "sender": sender, "recipient": recipient,
              "filename": document['filename'], "status": new_status}
    )

    flash(f'Document sent to {recipient}.', 'success')
    return redirect(url_for('dashboard_page'))

from shared import tpas_crypto  # pastikan sudah di-import di atas




from shared import tpas_crypto  # import module baru

@app.route('/create_incomplete_signature/<file_id>', methods=['POST'])
def create_incomplete_signature(file_id):
    if 'user' not in session:
        return redirect(url_for('login_page'))

    username = session['user']
    if get_user_role(username) != "validator":
        flash('Only validators can sign.', 'error')
        return redirect(url_for('dashboard_page'))

    doc = documents_collection.find_one({"_id": ObjectId(file_id)})
    doc_id = doc['_id']

    document = documents_collection.find_one({'file_id': ObjectId(file_id)})
    if not document or document.get('status') != 'Uploaded':
        flash('Document not valid for pre-signing.', 'error')
        return redirect(url_for('dashboard_page'))

    # Pastikan user saat ini adalah PENERIMA (file dikirim ke dia)
    if username not in document.get('shared_with', []):
        flash('You are not authorized to sign this document.', 'error')
        return redirect(url_for('dashboard_page'))

    sender_username = document['username']
    recipient_username = username
    content = fs.get(ObjectId(file_id)).read()

    signer_sk, signer_pk = tpas_crypto.generate_keypair()

    # Ambil public key pengirim
    sender_user = users_collection.find_one({'username': sender_username})
    if not sender_user or 'public_key' not in sender_user:
        flash('Sender public key not found.', 'error')
        return redirect(url_for('dashboard_page'))

    adaptor_pk = ecdsa.VerifyingKey.from_string(bytes.fromhex(sender_user['public_key']), curve=ecdsa.SECP256k1)
    # Generate keypair adaptor (recipient)
    adaptor_sk, adaptor_pk = tpas_crypto.generate_keypair()
    adaptor_sig = tpas_crypto.generate_adaptor_signature(
        message=content,
        signer_sk=signer_sk,
        adaptor_pk=adaptor_pk
    )

    documents_collection.update_one(
        {'file_id': ObjectId(file_id)},
        {'$set': {
            'incomplete_signature': adaptor_sig.hex(),
            'signer_private_key': signer_sk.to_string().hex(),
            'signer_public_key': signer_pk.to_string().hex(),
            'adaptor_private_key': adaptor_sk.to_string().hex(),
            'adaptor_public_key': adaptor_pk.to_string().hex(),
            'recipient': recipient_username,
            'status': 'Incomplete Signature'
        }}
    )

    blockchain.create_block(
        validator=recipient_username,
        data={
            "action": "Pre-Sign (TPAS)",
            "doc_id": str(doc_id),
            "filename": document['filename'],
            "file_hash": document['file_hash'],
            "recipient": recipient_username,
            "incomplete_signature": adaptor_sig.hex(),
            "status": "Incomplete Signature"
        },
        block_type="Pre-Signature"
    )

    flash('Adaptor signature created.', 'success')
    return redirect(url_for('dashboard_page'))



@app.route('/download/<file_id>')
def download_file(file_id):
    try:
        doc = documents_collection.find_one({'file_id': ObjectId(file_id)})
        if doc and 'updated_file_id' in doc:
            file_id = doc['updated_file_id']

        file = fs.get(ObjectId(file_id))
        response = app.response_class(file.read(), mimetype="application/pdf")
        response.headers.set('Content-Disposition', f'attachment; filename={file.filename}')
        return response

    except Exception as e:
        flash(f'Download failed: {e}', 'error')
        return redirect(url_for('dashboard_page'))

@app.route('/complete_signature/<file_id>', methods=['POST'])
def complete_signature(file_id):
    if 'user' not in session:
        return redirect(url_for('login_page'))

    username = session['user']
    if get_user_role(username) != "validator":
        flash('Only validators can complete signature.', 'error')
        return redirect(url_for('dashboard_page'))

    doc = documents_collection.find_one({"_id": ObjectId(file_id)})
    doc_id = doc['_id']

    document = documents_collection.find_one({'file_id': ObjectId(file_id)})    
    if not document or 'incomplete_signature' not in document:
        flash('Document not valid for completion.', 'error')
        return redirect(url_for('dashboard_page'))

    # 🔐 Ambil data dari database
    adaptor_sig = bytes.fromhex(document['incomplete_signature'])
    signer_pk = tpas_crypto.str_to_key(document['signer_public_key'])
    adaptor_sk = tpas_crypto.str_to_key(document['adaptor_private_key'], is_private=True)

    # 🔍 Ekstrak secret dari adaptor signature
    secret = tpas_crypto.extract_secret(adaptor_sig, signer_pk, adaptor_sk)

    # 🔒 Hasil Complete Signature (finalisasi)
    complete_signature = adaptor_sig + secret

    # 🔁 Simpan signature lengkap dan status baru
    documents_collection.update_one(
        {'file_id': ObjectId(file_id)},
        {'$set': {
            'completed_signature': complete_signature.hex(),
            'status': 'Complete Signature'
        }}
    )

    # 📦 Tambahkan ke Blockchain
    blockchain.create_block(
        validator=username,
        data={
            "action": "Complete Signature",
            "doc_id": str(doc_id),
            "filename": document['filename'],
            "file_hash": document['file_hash'],
            "status": "Complete Signature",
            "complete_signature": complete_signature.hex()
        },
        block_type="Complete Signature"
    )

    # 📤 Ambil konten file asli
    content = fs.get(ObjectId(file_id)).read()

    # 📎 Siapkan data untuk QR Code
    qr_data = json.dumps({
        "filename": document['filename'],
        "file_hash": document['file_hash'],
        "status": "Complete Signature",
        "extracted_secret": secret.hex()
    }, indent=4)

    qr = qrcode.make(qr_data)
    qr_io = BytesIO()
    qr.save(qr_io, format='PNG')
    qr_io.seek(0)

    # 🧩 Tambahkan QR ke PDF halaman pertama
    pdf_reader = PdfReader(BytesIO(content))
    pdf_writer = PdfWriter()

    overlay = BytesIO()
    can = canvas.Canvas(overlay, pagesize=letter)
    can.drawImage(ImageReader(qr_io), 400, 50, width=150, height=150)
    can.showPage()
    can.save()
    overlay.seek(0)

    overlay_pdf = PdfReader(overlay)
    for i, page in enumerate(pdf_reader.pages):
        if i == 0:
            page.merge_page(overlay_pdf.pages[0])
        pdf_writer.add_page(page)

    # 💾 Simpan file final ke GridFS
    final_buffer = BytesIO()
    pdf_writer.write(final_buffer)
    final_buffer.seek(0)
    signed_file_id = fs.put(final_buffer.getvalue(), filename=f"{document['filename']}_signed.pdf")

    # 📌 Update MongoDB
    documents_collection.update_one(
        {'file_id': ObjectId(file_id)},
        {'$set': {
            'updated_file_id': signed_file_id
        }}
    )

    flash('Adaptor signature completed & QR code embedded.', 'success')
    return redirect(url_for('dashboard_page'))


@app.route('/delete/<file_id>', methods=['POST'])
def delete_file(file_id):
    if 'user' not in session:
        flash('Unauthorized access.', 'error')
        return redirect(url_for('login_page'))

    current_user = session['user']

    try:
        # Ambil dokumen
        document = documents_collection.find_one({'file_id': ObjectId(file_id)})

        if not document:
            flash('Document not found.', 'error')
            return redirect(url_for('dashboard_page'))

        # Hanya pemilik & dokumen belum dikirim yang boleh hapus
        if document['username'] != current_user or document['status'] != 'Uploaded':
            flash('You cannot delete this document.', 'error')
            return redirect(url_for('dashboard_page'))

        # Hapus dari GridFS dan database
        fs.delete(ObjectId(file_id))
        documents_collection.delete_one({'file_id': ObjectId(file_id)})

        flash('File deleted successfully.', 'success')
    except Exception as e:
        print(f"❌ Delete Error: {e}")
        flash(f'Error deleting file: {e}', 'error')

    return redirect(url_for('dashboard_page'))


@app.route('/preview/<file_id>')
def preview_file(file_id):
    try:
        doc = documents_collection.find_one({'file_id': ObjectId(file_id)})
        if doc and 'updated_file_id' in doc:
            file_id = doc['updated_file_id']

        file = fs.get(ObjectId(file_id))
        mime_type, _ = mimetypes.guess_type(file.filename)
        response = app.response_class(file.read(), mimetype=mime_type or "application/pdf")
        response.headers.set('Content-Disposition', f'inline; filename={file.filename}')
        return response

    except Exception as e:
        flash(f'Preview failed: {e}', 'error')
        return redirect(url_for('dashboard_page'))
@app.route('/validate_blockchain')
def validate_blockchain():
    if blockchain.validate_chain():
        return "Blockchain is valid.", 200
    return "Blockchain is invalid!", 400

@app.route('/view_blockchain')
def view_blockchain_ui():
    blocks = []
    for block in blockchain.chain:
        block_copy = block.copy()
        block_copy['timestamp'] = datetime.fromtimestamp(block['timestamp']).strftime('%Y-%m-%d %H:%M:%S')
        blocks.append(block_copy)

    if not blocks:
        flash('No blocks found.', 'info')
    return render_template('view_blockchain.html', blockchain=blocks)

@app.route('/sync_chain')
def sync_chain():
    for node in blockchain.nodes:
        try:
            response = requests.get(f'http://{node}/get_chain')
            if response.status_code == 200:
                new_chain = response.json()['chain']
                blockchain.replace_chain(new_chain)
        except requests.exceptions.RequestException:
            continue

    return jsonify({"message": "Blockchain synchronized"}), 200

@app.route('/get_chain')
def get_chain():
    return jsonify({"chain": blockchain.chain}), 200

@app.route('/add_validator', methods=['POST'])
def add_validator():
    node_address = request.json.get('node_address')
    blockchain.add_node(node_address)
    return jsonify({"message": f"Validator {node_address} added."}), 200

@app.route('/register_validator', methods=['POST'])
def register_validator():
    node_address = request.json.get('node_address')
    public_key = request.json.get('public_key')

    if not node_address or not public_key:
        return jsonify({"error": "Node address and public key are required."}), 400

    if users_collection.find_one({"username": node_address, "role": "validator"}):
        return jsonify({"message": f"{node_address} already registered."}), 200

    users_collection.update_one(
        {"username": node_address},
        {"$set": {"role": "validator"}},
        upsert=True
    )
    blockchain.register_validator(node_address, public_key)
    return jsonify({"message": f"Validator {node_address} registered."}), 200

@app.route('/get_validators')
def get_validators():
    return jsonify({"validators": list(blockchain.validators.keys())}), 200

@app.route('/get_validators_from_db')
def get_validators_from_db():
    validators = users_collection.find({"role": "validator"}, {"username": 1})
    validator_list = [v['username'] for v in validators]
    for val in validator_list:
        if val not in blockchain.validators:
            blockchain.register_validator(val, "Public_Key_Placeholder")

    return jsonify({"validators": list(blockchain.validators.keys())}), 200

@app.route('/receive_block', methods=['POST'])
def receive_block():
    data = request.get_json()
    received_block = data.get('block')

    if not received_block:
        return jsonify({'message': 'Block data not found'}), 400

    last_block = blockchain.get_previous_block()
    if received_block['previous_hash'] != last_block['hash']:
        return jsonify({'message': 'Invalid previous hash'}), 400

    # Cek apakah block sudah ada di chain
    for block in blockchain.chain:
        if block['hash'] == received_block['hash']:
            return jsonify({'message': 'Block already exists'}), 200

    blockchain.chain.append(received_block)
    blockchain.save_chain()

    print(f"✅ Block #{received_block['index']} diterima dari peer.")
    return jsonify({'message': 'Block received successfully'}), 200

@app.route('/get_blocks', methods=['GET'])
def get_blocks():
    serialized_chain = [serialize_block(block) for block in blockchain.chain]
    return jsonify(serialized_chain), 200

@app.route('/documents/last', methods=['GET'])
def get_last_document():
    last_doc = documents_collection.find().sort([('_id', -1)]).limit(1)
    last_doc = list(last_doc)
    if not last_doc:
        return jsonify({'error': 'No document found'}), 404
    return jsonify({
        'doc_id': str(last_doc[0]['_id']),
        'filename': last_doc[0]['filename']
    })

@app.route('/upload_direct', methods=['POST'])
def upload_direct():
    file = request.files.get('file')
    recipient = request.form.get('recipient')
    uploader = request.form.get('uploader')

    if not file or not recipient or not uploader:
        return jsonify({'error': 'Missing required fields'}), 400

    filename = secure_filename(file.filename)
    file_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
    file.save(file_path)

    doc_data = {
        'filename': filename,
        'filepath': file_path,
        'uploader': uploader,
        'recipient': recipient,
        'status': 'pending',
        'timestamp': datetime.now(),
        'shared_with': [recipient]
    }

    result = documents_collection.insert_one(doc_data)
    doc_id = str(result.inserted_id)

    blockchain.create_block(
        validator=uploader,
        block_type='upload',
        data={**doc_data, '_id': doc_id, "doc_id": str(doc_id)},
        username=uploader
    )

    return jsonify({"message": "Upload success", "doc_id": doc_id}), 200

@app.route("/last_block")
def get_last_block():
    last_block = blockchain.get_previous_block()
    return jsonify(last_block), 200

@app.route("/get_block_by_doc/<doc_id>")
def get_block_by_doc(doc_id):
    block = blocks_collection.find_one({"data.doc_id": doc_id})
    if block:
        return jsonify({"found": True})
    else:
        return jsonify({"found": False})

if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0', port=5000)
