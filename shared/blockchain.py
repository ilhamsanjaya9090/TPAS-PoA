import hashlib
import json
import time
import ecdsa
from flask import Flask, request, jsonify
import requests

class Blockchain:
    def __init__(self):
        self.chain = []
        self.pending_transactions = []
        self.nodes = set()
        self.validators = {}  # Menyimpan validator dengan public key mereka

        # Buat blok genesis
        self.create_block(validator="Genesis", data={"message": "Genesis Block"}, previous_hash="0")

    def register_validator(self, node_address, public_key):
        """Mendaftarkan validator baru ke jaringan."""
        self.validators[node_address] = public_key
        return True

    def create_block(self, validator, data=None):
        """Hanya validator yang bisa membuat blok baru."""
        if validator not in self.validators:
            raise ValueError("Validator tidak sah")

        # Ambil hash blok terakhir
        previous_hash = self.get_previous_block()["hash"]
        
        block = {
            "index": len(self.chain) + 1,
            "timestamp": time.time(),
            "data": data or [],
            "previous_hash": previous_hash,
            "validator": validator
        }

        # Tandatangani blok dengan private key validator
        block_signature = self.sign_block(block, validator)
        block["signature"] = block_signature

        self.chain.append(block)
        return block

    def get_previous_block(self):
        return self.chain[-1]

    def sign_block(self, block, validator):
        """Validator menandatangani blok menggunakan ECDSA."""
        private_key = ecdsa.SigningKey.generate(curve=ecdsa.SECP256k1)
        message = json.dumps(block, sort_keys=True).encode()
        return private_key.sign(message).hex()

    def validate_chain(self):
        """Memeriksa apakah blockchain valid dengan memverifikasi tanda tangan blok."""
        for i in range(1, len(self.chain)):
            block = self.chain[i]
            previous_block = self.chain[i - 1]

            if block["previous_hash"] != previous_block["hash"]:
                return False

            # Verifikasi tanda tangan validator
            validator = block["validator"]
            if validator not in self.validators:
                return False

        return True

    def add_node(self, node_address):
        """Menambahkan node ke jaringan."""
        self.nodes.add(node_address)

    def replace_chain(self, new_chain):
        """Mengganti blockchain dengan chain yang lebih panjang jika ditemukan."""
        if len(new_chain) > len(self.chain):
            self.chain = new_chain
            return True
        return False
