import sys
import os
import datetime
import time

sys.path.append(os.path.join(os.path.dirname(__file__), 'shared'))
from blockchain import Blockchain
from pymongo import MongoClient
client = MongoClient("mongodb://localhost:27017/")
db = client["blockchain_db"]
users_collection = db["users"]

# Inisialisasi Blockchain dengan users_collection
blockchain = Blockchain(users_collection=users_collection)


# Dummy validator (pastikan sesuai dengan yang ada di validators list kamu)
validator = "ilham"

# Loop untuk generate 30 blok
for i in range(2):
    dummy_data = {
        "action": "test_batch_block",
        "value": i,
        "timestamp": str(datetime.datetime.now())
    }
    
    previous_hash = blockchain.get_previous_block()["hash"]
    
    # Buat blok dengan tipe khusus "Benchmark"
    block = blockchain.create_block(
        validator=validator,
        username=validator,
        data=dummy_data,
        previous_hash=previous_hash,
        block_type="Benchmark"
    )
    
    print(f"✅ Block {block['index']} generated in {block['generation_time']}s")
    
    # Tambahkan delay kecil jika perlu
    time.sleep(0.2)
