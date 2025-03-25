from ecdsa import SigningKey, VerifyingKey, SECP256k1
from hashlib import sha256

# ----------------------------------------
# 🔑 Keypair Generation
# ----------------------------------------

def generate_keypair():
    sk = SigningKey.generate(curve=SECP256k1)
    pk = sk.verifying_key
    return sk, pk

# ----------------------------------------
# 🔐 Adaptor Signature Generation
# ----------------------------------------

def generate_adaptor_signature(message: bytes, signer_sk: SigningKey, adaptor_pk: VerifyingKey):
    """
    Generate adaptor signature = ECDSA signature + public tweak
    This is simulation: we append the adaptor public key
    """
    signature = signer_sk.sign(message)
    adaptor = adaptor_pk.to_string()  # Public part (tweak)
    return signature + adaptor

# ----------------------------------------
# 🧠 Extract Secret from Adaptor Signature
# ----------------------------------------

def extract_secret(adaptor_sig: bytes, signer_pk: VerifyingKey, adaptor_sk: SigningKey):
    """
    Extract secret scalar from adaptor signature using private key (simulated)
    """
    sig_len = len(adaptor_sig) - 64  # 64 = typical ECDSA signature length
    secret = adaptor_sig[sig_len:]  # Ambil bagian adaptor
    # In real scenario, we'd derive scalar using DL / tweak recovery
    return adaptor_sk.to_string()  # Simulasi: anggap secret = sk adaptor

# ----------------------------------------
# 🔁 Convert Key to/from String for DB
# ----------------------------------------

def key_to_string(key):
    return key.to_string().hex()

def str_to_key(hex_str, is_private=False):
    raw = bytes.fromhex(hex_str)
    if is_private:
        return SigningKey.from_string(raw, curve=SECP256k1)
    return VerifyingKey.from_string(raw, curve=SECP256k1)

# ----------------------------------------
# 🧪 Utility (Optional Hashing)
# ----------------------------------------

def sha256_hash(data: bytes):
    return sha256(data).digest()
