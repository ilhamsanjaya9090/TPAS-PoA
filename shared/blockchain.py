import hashlib
import json
import time
import ecdsa
import os

class Blockchain:
    def __init__(self):
        self.chain = []
        self.nodes = set()
        self.validators = {}

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
    
    def create_block(self, validator, data=None, previous_hash=None, block_type="General"):
        # Validasi bahwa hanya validator yang sah yang boleh membuat blok
        if validator not in self.validators:
            raise ValueError("❌ Validator tidak sah")

        previous_hash = previous_hash or self.get_previous_block()["hash"]

        # Cegah duplikasi blok berdasarkan data dan previous_hash
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
            "block_type": block_type,
        }

        # Tanda tangan digital oleh validator
        block["signature"] = self.sign_block(block, validator)

        # Hitung hash blok
        block["hash"] = self.calculate_hash(block)

        # Tambahkan ke rantai dan simpan
        self.chain.append(block)
        self.save_chain()

        # Broadcast ke node lain (peer-to-peer)
        # Broadcast ke node lain (peer-to-peer)
        try:
            from shared.config import PEER_NODES, MY_NODE_URL
            import requests

            for node in PEER_NODES:
                if node != MY_NODE_URL:
                    try:
                        response = requests.post(
                            f"{node}/receive_block", 
                            json={"block": block}, 
                            timeout=3  # Tambahkan timeout
                        )
                        print(f"📡 Broadcast to {node}: {response.status_code}")
                    except Exception as e:
                        print(f"⚠️ Gagal broadcast ke {node}: {e}")

        except Exception as e:
            print(f"⚠️ Gagal broadcast block ke peer: {e}")


        # Di bawah class Blockchain:
    def broadcast_block_to_peers(block):
        from shared.config import PEER_NODES, MY_NODE_URL
        import requests

        for node_url in PEER_NODES:
            try:
                if node_url != MY_NODE_URL:  # Hindari broadcast ke diri sendiri
                    requests.post(f"{node_url}/receive_block", json={"block": block})
            except Exception as e:
                print(f"Gagal kirim block ke {node_url}: {e}")


    def get_previous_block(self):
        return self.chain[-1] if self.chain else None

    def calculate_hash(self, block):
        block_string = json.dumps(block, sort_keys=True).encode()
        return hashlib.sha256(block_string).hexdigest()

    def sign_block(self, block, validator):
        private_key_hex = self.validators[validator]["private_key"]
        private_key = ecdsa.SigningKey.from_string(bytes.fromhex(private_key_hex), curve=ecdsa.SECP256k1)

        message = json.dumps({
            "index": block["index"],
            "timestamp": block["timestamp"],
            "data": block["data"],
            "previous_hash": block["previous_hash"],
            "validator": block["validator"],
            "block_type": block["block_type"]
        }, sort_keys=True).encode()

        return private_key.sign(message).hex()

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
        print("⚠️ Received chain is not longer. No replacement made.")
        return False

    def save_chain(self, filename="blockchain.json"):
        with open(filename, 'w') as f:
            json.dump(self.chain, f, indent=4)
        print("💾 Blockchain saved to file.")

    def load_chain(self, filename="blockchain.json"):
        if os.path.exists(filename):
            with open(filename, 'r') as f:
                self.chain = json.load(f)
            print("🔁 Blockchain loaded from file.")
