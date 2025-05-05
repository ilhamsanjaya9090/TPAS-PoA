import requests
import time
import csv
import os

BASE_URL = "http://localhost:5000"
USERNAME = "ilham"
PASSWORD = "sanjaya"
RECIPIENT = "sanjaya"
ITERATIONS = 100
PDF_FILE = "sample.pdf"
CSV_FILENAME = "benchmark_results.csv"

def login(session, username, password):
    print(f"🔐 Login sebagai {username}...")
    res = session.post(f"{BASE_URL}/login", data={"username": username, "password": password})
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
        return round(end_time - start_time, 4), doc_id
    except Exception as e:
        print("❌ Upload gagal:", e)
        print("Res:", res.text)
        return None, None

def benchmark_complete_signature(session, doc_id):
    start_time = time.time()
    res = session.post(f"{BASE_URL}/complete_signature/{doc_id}")
    end_time = time.time()
    if res.status_code in [200, 302]:
        return round(end_time - start_time, 4)
    else:
        print("❌ Complete signature gagal.")
        print(res.text)
        return None

def run_benchmark():
    with open(CSV_FILENAME, "w", newline="") as csvfile:
        writer = csv.writer(csvfile)
        writer.writerow(["Iteration", "Upload_Time(s)", "Complete_Signature_Time(s)"])

        for i in range(1, ITERATIONS + 1):
            print(f"\n🔁 Iterasi {i}...")

            # Session untuk Ilham
            session_ilham = requests.Session()
            if not login(session_ilham, USERNAME, PASSWORD):
                continue

            upload_time, doc_id = benchmark_upload(session_ilham)
            logout(session_ilham)

            if not doc_id:
                continue

            time.sleep(1)

            # Session baru untuk Sanjaya
            session_sanjaya = requests.Session()
            if not login(session_sanjaya, RECIPIENT, PASSWORD):
                continue

            sign_time = benchmark_complete_signature(session_sanjaya, doc_id)
            logout(session_sanjaya)

            if sign_time is None:
                continue

            writer.writerow([i, upload_time, sign_time])
            print(f"✅ Iterasi {i} selesai - Upload: {upload_time}s, Sign: {sign_time}s")
            time.sleep(1)

if __name__ == "__main__":
    if not os.path.exists(PDF_FILE):
        print(f"📄 File {PDF_FILE} tidak ditemukan.")
    else:
        print(f"🧪 Benchmark dimulai ({ITERATIONS} iterasi)...")
        run_benchmark()
        print(f"📊 Benchmark selesai. Hasil disimpan di {CSV_FILENAME}")
