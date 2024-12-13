import random
from hashlib import sha256

def chunk_message(message, chunk_size):
    """Split the message into chunks of specified size."""
    return [message[i:i + chunk_size] for i in range(0, len(message), chunk_size)]

# Simple RSA Implementation Without External Libraries
def generate_rsa_keys(bits=2048):
    from sympy import nextprime
    from random import getrandbits

    # Generate two large primes p and q
    p = nextprime(getrandbits(bits // 2))
    q = nextprime(getrandbits(bits // 2))

    # Compute n and phi(n)
    n = p * q
    phi = (p - 1) * (q - 1)

    # Choose e such that 1 < e < phi(n) and gcd(e, phi) = 1
    e = 65537  # Commonly used public exponent

    # Compute d, the modular multiplicative inverse of e mod phi
    d = pow(e, -1, phi)

    return ((e, n), (d, n))

def rsa_encrypt(public_key, message):
    e, n = public_key
    message_chunks = chunk_message(message, (n.bit_length() // 8) - 1)  # Split into small chunks
    ciphertext_chunks = []
    for chunk in message_chunks:
        message_int = int.from_bytes(chunk.encode('utf-8'), byteorder='big')
        if message_int >= n:
            raise ValueError("Message chunk too large for RSA encryption")
        ciphertext = pow(message_int, e, n)
        ciphertext_chunks.append(ciphertext)
    return ciphertext_chunks

def rsa_decrypt(private_key, ciphertext_chunks):
    d, n = private_key
    message = b''
    for ciphertext in ciphertext_chunks:
        message_int = pow(ciphertext, d, n)
        message += message_int.to_bytes((message_int.bit_length() + 7) // 8, byteorder='big')
    return message.decode('utf-8')

# Generate keys for Alice, Bob, and TTP
alice_public_key, alice_private_key = generate_rsa_keys()
bob_public_key, bob_private_key = generate_rsa_keys()
ttp_public_key, ttp_private_key = generate_rsa_keys()

# Step 1: Alice -> TTP: E(KE_S, ID_A || ID_B)
alice_to_ttp_message = "Alice||Bob"
alice_to_ttp_encrypted = rsa_encrypt(ttp_public_key, alice_to_ttp_message)

# Step 2: TTP -> Alice: E(KA_S, ID_B || KE_B)
ttp_to_alice_message = f"Bob||{bob_public_key[0]}||{bob_public_key[1]}"
ttp_to_alice_encrypted = rsa_encrypt(alice_public_key, ttp_to_alice_message)

# Step 3: Alice -> Bob: E(KE_B, NA || ID_A)
na = random.randint(1, 1000000)  # Random nonce
alice_to_bob_message = f"{na}||Alice"
alice_to_bob_encrypted = rsa_encrypt(bob_public_key, alice_to_bob_message)

# Step 4: Bob -> TTP: E(KE_S, ID_B || ID_A)
bob_to_ttp_message = "Bob||Alice"
bob_to_ttp_encrypted = rsa_encrypt(ttp_public_key, bob_to_ttp_message)

# Step 5: TTP -> Bob: E(KA_S, ID_A || KE_A)
ttp_to_bob_message = f"Alice||{alice_public_key[0]}||{alice_public_key[1]}"
ttp_to_bob_encrypted = rsa_encrypt(bob_public_key, ttp_to_bob_message)

# Step 6: Bob -> Alice: E(KE_A, ID_B || NA || NB)
nb = random.randint(1, 1000000)  # Random nonce
bob_to_alice_message = f"Bob||{na}||{nb}"
bob_to_alice_encrypted = rsa_encrypt(alice_public_key, bob_to_alice_message)

# Step 7: Alice -> Bob: E(KE_B, NB)
alice_to_bob_final_message = f"{nb}"
alice_to_bob_final_encrypted = rsa_encrypt(bob_public_key, alice_to_bob_final_message)

# Demonstrate successful exchange and verification
def verify_exchange():
    # Decrypt Bob -> Alice message
    decrypted_bob_to_alice = rsa_decrypt(alice_private_key, bob_to_alice_encrypted)
    decrypted_bob_id, decrypted_na, decrypted_nb = decrypted_bob_to_alice.split("||")
    assert decrypted_bob_id == "Bob", "Responder identity mismatch"
    assert int(decrypted_na) == na, "NA mismatch"

    # Decrypt Alice -> Bob final message
    decrypted_alice_to_bob_final = rsa_decrypt(bob_private_key, alice_to_bob_final_encrypted)
    assert int(decrypted_alice_to_bob_final) == nb, "NB mismatch"

    print("Key exchange successful and verified!")
    print("Alice to Bob initial message:", f"{na}||Alice")
    print("Bob to Alice response message:", f"Bob||{na}||{nb}")
    print("Alice to Bob final message:", f"{nb}")

verify_exchange()
