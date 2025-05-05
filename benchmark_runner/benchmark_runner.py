import requests
import time
import csv
import os
import psutil
from shared.blockchain import Blockchain
from pymongo import MongoClient

# Koneksi MongoDB
client = MongoClient("mongodb://localhost:27017/")
db = client["blockchain_db"]
users_collection = db["users"]

# Inisialisasi Blockchain dengan users_collection
blockchain = Blockchain(users_collection=users_collection)

BASE_URL = "http://localhost:5000"
USERNAME = "ilham"
PASSWORD ="password123"
RECIPIENT = "sanjaya"
PASSWORD_SANJAYA = "password321"
ITERATIONS = 2
PDF_FILE = "sample.pdf"
CSV_FILENAME = "benchmark_results.csv"


def login(session, username, password):
    print(f"🔐 Login sebagai {username}...")
    data = {
        "username": username,
        "password": password,
        "mac_address": "auto-detect-backend"
    }
    res = session.post(f"{BASE_URL}/login", data=data)
    print("Status:", res.status_code)
    print("Redirected to:", res.url)
    if res.url.endswith("/dashboard"):
        print("✅ Login berhasil.")
        return True
    else:
        print("❌ Login gagal.")
        print(res.text)
        return False


def logout(session):
    session.get(f"{BASE_URL}/logout")
    session.cookies.clear()


def benchmark_upload(session):
    with open(PDF_FILE, "rb") as file:
        files = {"file": (PDF_FILE, file, "application/pdf")}
        data = {"recipient": RECIPIENT, "uploader": USERNAME}
        start_time = time.time()
        res = session.post(f"{BASE_URL}/upload_direct", files=files, data=data)
        end_time = time.time()

    try:
        json_data = res.json()
        doc_id = json_data.get("doc_id")
        print(f"📄 Upload berhasil. doc_id = {doc_id}")
        log_resource_usage("upload")
        return round(end_time - start_time, 4), doc_id
    except Exception as e:
        print("❌ Upload gagal:", e)
        print("Res:", res.text)
        return None, None


def benchmark_incomplete_signature(session, doc_id):
    start_time = time.time()
    res = session.post(f"{BASE_URL}/create_incomplete_signature/{doc_id}")
    end_time = time.time()

    if res.status_code == 200 or "Adaptor signature created" in res.text:
        log_resource_usage("incomplete_signature")
        return round(end_time - start_time, 4)
    else:
        print("❌ Incomplete signature gagal.")
        print(res.text)
        return None


def benchmark_complete_signature(session, doc_id):
    start_time = time.time()
    res = session.post(f"{BASE_URL}/complete_signature/{doc_id}")
    end_time = time.time()
    if res.status_code in [200, 302]:
        log_resource_usage("complete_signature") 
        return round(end_time - start_time, 4)
    else:
        print("❌ Complete signature gagal.")
        print(res.text)
        return None


def run_benchmark(iterations=2):
    print(f"🧪 Benchmark dimulai ({iterations} iterasi)...")

    with open(CSV_FILENAME, "w", newline="") as csvfile:
        writer = csv.writer(csvfile)
        writer.writerow([
            "Iteration",
            "Upload_Time(s)",
            "Incomplete_Signature_Time(s)",
            "Complete_Signature_Time(s)",
            "Sync_Time(s)"
        ])

        for i in range(1, iterations + 1):
            print(f"\n🔁 Iterasi {i}...")

            session_ilham = requests.Session()
            if not login(session_ilham, USERNAME, PASSWORD):
                print("❌ Login gagal untuk ilham.")
                continue

            upload_time, doc_id = benchmark_upload(session_ilham)
            if not doc_id:
                print("❌ Gagal upload dokumen.")
                continue

            session_sanjaya = requests.Session()
            if not login(session_sanjaya, RECIPIENT, PASSWORD_SANJAYA):
                print("❌ Login gagal untuk sanjaya.")
                continue

            incomplete_sign_time = benchmark_incomplete_signature(session_sanjaya, doc_id)

            logout(session_sanjaya)

            logout(session_ilham)
            session_ilham = requests.Session()
            login(session_ilham, USERNAME, PASSWORD)

            complete_sign_time = benchmark_complete_signature(session_ilham, doc_id)
            time.sleep(1.5)
            sync_time = benchmark_sync_time(doc_id, "http://192.168.1116.165:5000")  #  Node 2
            writer.writerow([i, upload_time, incomplete_sign_time, complete_sign_time, sync_time])           
            print(
                f"✅ Iterasi {i} selesai - "
                f"Upload: {upload_time:.4f}s, "
                f"Incomplete: {incomplete_sign_time:.4f}s, "
                f"Complete: {complete_sign_time:.4f}s"
            )

    print(f"📊 Benchmark selesai. Hasil disimpan di {CSV_FILENAME}")

def benchmark_sync_time(doc_id, target_node_url):
    start_time = time.time()
    max_wait = 5  # detik
    while time.time() - start_time < max_wait:
        try:
            res = requests.get(f"{target_node_url}/get_block_by_doc/{doc_id}")
            if res.status_code == 200:
                try:
                    json_data = res.json()
                    print("📡 Response JSON:", json_data)
                    if json_data.get("found") == True:
                        received_time = time.time()
                        log_resource_usage("sync")
                        return round(received_time - start_time, 4)
                except Exception as e:
                    print("❌ JSON parse error:", e)
        except Exception as e:
            print("❌ Request error:", e)
        time.sleep(0.1)  # tunggu 100ms sebelum cek lagi

    print(f"⚠️ Timeout: Block dengan doc_id {doc_id} tidak ditemukan dalam {max_wait} detik")
    return None



def log_resource_usage(label, log_file="resource_usage_log.csv"):
    usage = {
        "label": label,
        "cpu_percent": psutil.cpu_percent(interval=1),
        "ram_percent": psutil.virtual_memory().percent
    }
    write_header = not os.path.exists(log_file)
    with open(log_file, "a", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=["label", "cpu_percent", "ram_percent"])
        if write_header:
            writer.writeheader()
        writer.writerow(usage)


if __name__ == "__main__":
    if not os.path.exists(PDF_FILE):
        print(f"📄 File {PDF_FILE} tidak ditemukan.")
    else:
        run_benchmark()
