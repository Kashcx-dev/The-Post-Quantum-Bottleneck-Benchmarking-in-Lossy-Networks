import os
from cryptography.hazmat.primitives.asymmetric import x25519, rsa, padding
from cryptography.hazmat.primitives import serialization, hashes

def get_client_pubkey(algo):
    """Client Step 1: Generate keypair and return public key bytes to send."""
    if algo == 'ECDH':
        priv_key = x25519.X25519PrivateKey.generate()
        pub_bytes = priv_key.public_key().public_bytes(
            serialization.Encoding.Raw, serialization.PublicFormat.Raw
        )
        return pub_bytes, priv_key

    elif algo == 'RSA':
        priv_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        pub_bytes = priv_key.public_key().public_bytes(
            serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo
        )
        return pub_bytes, priv_key

    elif algo == 'ML-KEM':
        import oqs
        kem = oqs.KeyEncapsulation('ML-KEM-768')
        pub_bytes = kem.generate_keypair()
        return pub_bytes, kem

def server_encapsulate(algo, client_pub_bytes):
    """Server Step 2: Use client's public key to create a secret and ciphertext."""
    if algo == 'ECDH':
        # Server acts as the other half of ECDH
        server_priv = x25519.X25519PrivateKey.generate()
        ciphertext = server_priv.public_key().public_bytes(
            serialization.Encoding.Raw, serialization.PublicFormat.Raw
        )
        client_pub = x25519.X25519PublicKey.from_public_bytes(client_pub_bytes)
        shared_secret = server_priv.exchange(client_pub)
        return ciphertext, shared_secret

    elif algo == 'RSA':
        # Server generates a 32-byte AES key and encrypts it with Client's RSA key
        shared_secret = os.urandom(32)
        client_pub = serialization.load_pem_public_key(client_pub_bytes)
        ciphertext = client_pub.encrypt(
            shared_secret,
            padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None)
        )
        return ciphertext, shared_secret

    elif algo == 'ML-KEM':
        import oqs
        with oqs.KeyEncapsulation('ML-KEM-768') as kem:
            ciphertext, shared_secret = kem.encap_secret(client_pub_bytes)
        return ciphertext, shared_secret

def client_decapsulate(algo, priv_state, ciphertext):
    """Client Step 3: Decrypt the ciphertext to recover the shared secret."""
    if algo == 'ECDH':
        server_pub = x25519.X25519PublicKey.from_public_bytes(ciphertext)
        return priv_state.exchange(server_pub)

    elif algo == 'RSA':
        return priv_state.decrypt(
            ciphertext,
            padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None)
        )

    elif algo == 'ML-KEM':
        import oqs
        shared_secret = priv_state.decap_secret(ciphertext)
        priv_state.free()  # Clean up C memory
        return shared_secret