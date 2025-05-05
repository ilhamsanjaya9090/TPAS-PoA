import hashlib
import json
import time
import ecdsa
import os
import csv
from pymongo import MongoClient
from shared.config import PEER_NODES, MY_NODE_URL
from shared.utils import serialize_block  # Pastikan sudah tersedia
import requests
from shared.config import MONGO_URL
from datetime import datetime
from bson import ObjectId  # hanya jika kamu pakai MongoDB

def convert_objectids_to_str(data):
    if isinstance(data, dict):
        return {k: convert_objectids_to_str(v) for k, v in data.items()}
    elif isinstance(data, list):
        return [convert_objectids_to_str(i) for i in data]
    elif isinstance(data, ObjectId):
        return str(data)
    return data

class Blockchain:
    def __init__(self, users_collection=None):
        self.chain = []
        self.users_collection = users_collection
        self.nodes = set()
        self.validators = self.validators = ["ilham", "sanjaya"]

        self.load_chain()

        if not self.chain:
            genesis_block = {
                "index": 1,
                "timestamp": time.time(),
                "data": {"message": "Genesis Block"},
                "previous_hash": "0",
                "validator": "Genesis"
            }
            genesis_block["hash"] = self.calculate_hash(genesis_block)
            self.chain.append(genesis_block)
            print("✅ Genesis Block created.")
            self.save_chain()
    
    def register_validator(self, node_address, public_key):
        if node_address in self.validators:
            print(f"⚠️ Validator {node_address} already registered.")
            return False

        private_key = ecdsa.SigningKey.generate(curve=ecdsa.SECP256k1)
        self.validators[node_address] = {
            "public_key": public_key,
            "private_key": private_key.to_string().hex()
        }
        print(f"✅ Validator registered: {node_address}")
        return True

    def add_node(self, address):
        self.nodes.add(address)
        print(f"✅ Node added: {address}")
    
    def create_block(self, validator, username=None, data=None, previous_hash=None, block_type="General"):
        # Validasi apakah validator sah
        if validator not in self.validators:
            raise ValueError("❌ Validator tidak sah")

        # Ambil previous hash dari blok terakhir jika belum diberikan
        previous_hash = previous_hash or self.get_previous_block()["hash"]

        # Cegah duplikasi block berdasarkan data dan previous_hash
        for block in self.chain:
            if block["data"] == data and block["previous_hash"] == previous_hash:
                print("⚠️ Block already exists, skipping creation.")
                return block

        # ⏱️ MULAI PENGUKURAN WAKTU PEMBUATAN BLOK
        start_time = time.time()

        # Struktur dasar blok
        block = {
            "index": len(self.chain) + 1,
            "timestamp": time.time(),
            "data": data or {},
            "previous_hash": previous_hash,
            "validator": validator,
            "username": username,
            "block_type": block_type,
             "generation_time": round(time.time() - start_time, 4)
        }

        # Tanda tangan dan hash blok
        block["signature"] = self.sign_block(block, validator)
        block["hash"] = self.calculate_hash(block)

        # Simpan ke rantai lokal (JSON)
        self.chain.append(block)
        self.save_chain()

        # Simpan ke MongoDB
        client = MongoClient(MONGO_URL)
        db = client["blockchain_db"]
        blocks_collection = db["blocks"]
        blocks_collection.insert_one(block)

        # ⏱️ SELESAI PENGUKURAN WAKTU
        end_time = time.time()
        gen_time = round(end_time - start_time, 4)  # Waktu pembuatan blok (dalam detik)

        # 📝 SIMPAN HASILNYA KE CSV UNTUK BENCHMARK
        log_file = "block_generation_log.csv"
        file_exists = os.path.isfile(log_file)
        with open(log_file, "a", newline="") as f:
            writer = csv.writer(f)
            if not file_exists:
                writer.writerow(["Block Index", "Generation Time (s)", "Block Type", "Validator"])
            writer.writerow([block["index"], gen_time, block_type, validator])

        # 📡 Broadcast block ke node lain (jika ada)
        try:
            for node in PEER_NODES:
                if node != MY_NODE_URL:
                    try:
                        response = requests.post(f"{node}/receive_block", json=convert_objectids_to_str(block), timeout=3)
                        print(f"📡 Broadcast to {node}: {response.status_code}")
                    except Exception as e:
                        print(f"⚠️ Gagal broadcast ke {node}: {e}")
        except Exception as e:
            print(f"⚠️ Gagal broadcast block ke peer: {e}")

        # ✅ Kembalikan block yang telah dibuat
        return block

    def get_previous_block(self):
        return self.chain[-1] if self.chain else None
        
    def validate_chain(self):
        for i in range(1, len(self.chain)):
            block = self.chain[i]
            prev_block = self.chain[i - 1]

            if block["previous_hash"] != prev_block["hash"]:
                print(f"⛔ Blockchain invalid at block #{block['index']} - Previous hash mismatch!")
                return False

            validator = block["validator"]
            if validator not in self.validators:
                print(f"⛔ Validator {validator} not recognized.")
                return False

            try:
                public_key_hex = self.validators[validator]["public_key"]
                public_key = ecdsa.VerifyingKey.from_string(bytes.fromhex(public_key_hex), curve=ecdsa.SECP256k1)

                message = json.dumps({
                    "index": block["index"],
                    "timestamp": block["timestamp"],
                    "data": block["data"],
                    "previous_hash": block["previous_hash"],
                    "validator": block["validator"],
                    "block_type": block["block_type"]
                }, sort_keys=True).encode()

                public_key.verify(bytes.fromhex(block["signature"]), message)
            except ecdsa.BadSignatureError:
                print(f"⛔ Block #{block['index']} signature verification failed!")
                return False
        print("✅ Blockchain is valid.")
        return True

    def replace_chain(self, new_chain):
        if len(new_chain) > len(self.chain):
            self.chain = new_chain
            self.save_chain()
            print("✅ Local chain replaced with longer chain.")
            return True
        else:
            print("⚠️ Received chain is not longer. No replacement made.")
            return False
           

    def load_chain(self, filename="blockchain.json"):
        if os.path.exists(filename):
            with open(filename, 'r') as f:
                self.chain = json.load(f)
            print("🔁 Blockchain loaded from file.")

        if not self.chain:
            try:
                client = MongoClient(MONGO_URL)
                db = client["blockchain_db"]
                blocks_collection = db["blocks"]
                self.chain = list(blocks_collection.find({}, {"_id": 0}))  # _id tidak diperlukan
                print("🔁 Blockchain loaded from MongoDB.")
            except Exception as e:
               print(f"❌ Failed to load blockchain from MongoDB: {e}")

    def sign_block(self, block, validator):
        user_info = self.users_collection.find_one({"username": validator})
        if not user_info:
            raise ValueError("❌ Validator tidak ditemukan di database")
        private_key_hex = user_info['private_key']
        private_key = ecdsa.SigningKey.from_string(bytes.fromhex(private_key_hex), curve=ecdsa.SECP256k1)

        # Buat salinan block["data"] dan ubah datetime ke string
        data_serializable = block["data"].copy()
        for key, value in data_serializable.items():
            if isinstance(value, datetime):
                data_serializable[key] = value.isoformat()

        message = json.dumps({
            "index": block["index"],
            "timestamp": block["timestamp"],  # biasanya string, aman
            "data": data_serializable,        # sudah aman
            "previous_hash": block["previous_hash"],
            "validator": block["validator"]
        })

        signature = private_key.sign(message.encode()).hex()
        return signature
    
    def calculate_hash(self, block):
        block_string = json.dumps(block, sort_keys=True, default=str).encode()
        return hashlib.sha256(block_string).hexdigest()


    def save_chain(self):
        with open("blockchain.json", "w") as f:
            json.dump([self.serialize_block(block) for block in self.chain], f, indent=4)

    @staticmethod
    def serialize_block(block):
        def convert(obj):
            if isinstance(obj, datetime):
                return obj.isoformat()
            elif isinstance(obj, ObjectId):  # Jika pakai MongoDB
                return str(obj)
            elif isinstance(obj, dict):
                return {k: convert(v) for k, v in obj.items()}
            elif isinstance(obj, list):
                return [convert(item) for item in obj]
            else:
                return obj
        return convert(block)
