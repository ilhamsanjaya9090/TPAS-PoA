import hashlib
import json
import time
import ecdsa
from flask import Flask, request, jsonify
import requests

class Blockchain:
    def __init__(self):
        self.chain = []
        self.nodes = set()
        self.validators = {}

        # ✅ Tambahkan blok genesis hanya jika chain kosong
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

    def register_validator(self, node_address, public_key):
        """✅ Menyimpan validator secara persisten"""
        if node_address in self.validators:
            print(f"⚠️ Validator {node_address} already registered.")
            return False
        
        private_key = ecdsa.SigningKey.generate(curve=ecdsa.SECP256k1)
        self.validators[node_address] = {
            "public_key": public_key,
            "private_key": private_key.to_string().hex()  # ✅ Simpan sebagai HEX
        }
        print(f"✅ Validator registered: {node_address} -> {public_key}")
        return True

    def create_block(self, validator, data=None, previous_hash=None, block_type="General"):
        """✅ Pastikan blok dengan `Complete Signature` tidak duplikat"""
        if validator not in self.validators:
            raise ValueError("⛔ Validator tidak sah")

        previous_hash = previous_hash or self.get_previous_block()["hash"]

        # ✅ Cek apakah blok dengan data ini sudah ada
        for block in self.chain:
            if block["data"] == data and block["previous_hash"] == previous_hash:
                print("⚠️ Block already exists, skipping creation.")
                return block

        block = {
            "index": len(self.chain) + 1,
            "timestamp": time.time(),
            "data": data or {},
            "previous_hash": previous_hash,
            "validator": validator,
            "block_type": block_type
        }
        block["signature"] = self.sign_block(block, validator)
        block["hash"] = self.calculate_hash(block)
        self.chain.append(block)
        print(f"✅ Block #{block['index']} created by {validator} - Type: {block_type}")
        return block

    def get_previous_block(self):
        return self.chain[-1] if self.chain else None

    def calculate_hash(self, block):
        """✅ Pastikan hash tetap unik"""
        block_string = json.dumps(block, sort_keys=True).encode()
        return hashlib.sha256(block_string).hexdigest()

    def sign_block(self, block, validator):
        """✅ Pastikan private key tersimpan dalam format yang benar"""
        private_key_hex = self.validators[validator]["private_key"]
        private_key = ecdsa.SigningKey.from_string(bytes.fromhex(private_key_hex), curve=ecdsa.SECP256k1)
        
        message = json.dumps(block, sort_keys=True).encode()
        return private_key.sign(message).hex()

    def validate_chain(self):
        """✅ Validasi setiap blok dan tanda tangan"""
        for i in range(1, len(self.chain)):
            block = self.chain[i]
            previous_block = self.chain[i - 1]

            if block["previous_hash"] != previous_block["hash"]:
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
                    "validator": block["validator"]
                }, sort_keys=True).encode()

                public_key.verify(bytes.fromhex(block["signature"]), message)
            except ecdsa.BadSignatureError:
                print(f"⛔ Block #{block['index']} signature verification failed!")
                return False
        print("✅ Blockchain is valid.")
        return True
