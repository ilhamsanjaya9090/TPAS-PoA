# Two-Party Adaptor Signature in PoA-Based Private Blockchain

This project implements a secure document signing system using a Two-Party Adaptor Signature (TPAS) mechanism on a private blockchain based on Proof of Authority (PoA). The system is designed to ensure multi-party authentication and tamper-evident document integrity within a permissioned environment.

## 🔐 Features

- **Two-Party Signature Protocol (TPAS):** Involves a designated sender and recipient to cooperatively complete a digital signature.
- **Role-Specific Consensus:** Based on PoA, where only authorized validators finalize and record blocks.
- **Document Workflow:**
  - Upload and store documents with incomplete signatures.
  - Forward to validator for signature completion.
  - Finalized documents are recorded and synchronized across nodes.
- **Node Synchronization:** Blocks are synchronized automatically between nodes to maintain ledger consistency.
- **Benchmarking:** Includes scripts to measure communication time, synchronization latency, and resource usage.

## 🧱 Architecture

- **Node Roles:**
  - Validator: Signs and validates transactions.
  - Non-Validator: Can view and download only finalized documents.
- **Modules:**
  - `shared/`: Core blockchain logic, signature handling, and cryptographic operations.
  - `node1/`, `system_main/`: Sample node configurations.
  - `templates/`: Frontend HTML interface (Flask-based).
  - `benchmark_runner.py`: Execution time and performance logger.

## ⚙️ Technologies Used

- Python (Flask)
- MongoDB (GridFS for file storage)
- ECDSA (Elliptic Curve Digital Signature Algorithm)
- Local Area Network (LAN) for multi-node interaction

## 📊 Benchmark Results

- **Communication Time:** 8.16 seconds
- **Block Generation Time:** 0.0249 seconds
- **Synchronization Latency:** 0.004 seconds
- **CPU Usage:** 6.2%
- **RAM Usage:** 63.4%

## 📁 Repository Structure

