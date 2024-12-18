from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.backends import default_backend
import os

def encrypt(key, plaintext):
    cipher = Cipher(algorithms.AES(key), modes.ECB(), backend=default_backend())
    encryptor = cipher.encryptor()
    padder = padding.PKCS7(algorithms.AES.block_size).padder()
    padded_data = padder.update(plaintext) + padder.finalize()
    return encryptor.update(padded_data) + encryptor.finalize()

def decrypt(key, ciphertext):
    cipher = Cipher(algorithms.AES(key), modes.ECB(), backend=default_backend())
    decryptor = cipher.decryptor()
    unpadder = padding.PKCS7(algorithms.AES.block_size).unpadder()
    decrypted_data = decryptor.update(ciphertext) + decryptor.finalize()
    return unpadder.update(decrypted_data) + unpadder.finalize()

def generate_key():
    return os.urandom(16)  

user_table = {
    "Alice": generate_key(),
    "Bob": generate_key()
}

def add_user(username):
    if username not in user_table:
        user_table[username] = generate_key()

K_AB = generate_key()

ID_A = b"Alice"
ID_B = b"Bob"
N_A = os.urandom(8)  
N_B = os.urandom(8)  
J = os.urandom(8)    


K_A = user_table["Alice"]
message_1 = encrypt(K_A, ID_A + ID_B + N_A)
print("Step 1: Alice -> TTP (encrypted message):", message_1)

K_B = user_table["Bob"]
message_for_bob = encrypt(K_B, K_AB + ID_A + J)
message_2 = encrypt(K_A, ID_A + ID_B + N_A + K_AB + message_for_bob)
print("Step 2: TTP -> Alice (encrypted message):", message_2)

message_3 = message_for_bob  
print("Step 3: Alice -> Bob (encrypted message):", message_3)

decrypted_message_for_bob = decrypt(K_B, message_3)
print("Step 3: Bob decrypts the message:")
print("  Session Key (K_AB):", decrypted_message_for_bob[:16])
print("  Alice's Identity (ID_A):", decrypted_message_for_bob[16:21])
print("  Freshness Nonce (J):", decrypted_message_for_bob[21:])
assert decrypted_message_for_bob[:16] == K_AB  #verify the session key
assert decrypted_message_for_bob[16:21] == ID_A  # vrify Alice's identity
assert decrypted_message_for_bob[21:] == J       #verify nonce J

message_4 = encrypt(K_AB, N_B)
print("Step 4: Bob -> Alice (encrypted message):", message_4)

decrypted_message_4 = decrypt(K_AB, message_4)
print("Step 4: Alice decrypts the message:")
print("  Nonce from Bob (N_B):", decrypted_message_4)
assert decrypted_message_4 == N_B  

message_5 = encrypt(K_AB, (int.from_bytes(N_B, "big") - 1).to_bytes(8, "big"))
print("Step 5: Alice -> Bob (encrypted message):", message_5)

decrypted_message_5 = decrypt(K_AB, message_5)
print("Step 5: Bob decrypts the message:")
print("  Decremented Nonce (N_B - 1):", decrypted_message_5)
assert decrypted_message_5 == (int.from_bytes(N_B, "big") - 1).to_bytes(8, "big") 

print("Protocol successfully implemented and verified with freshness (using nonce J).")

print("User Table:")
for user, key in user_table.items():
    print(f"User: {user}, Key: {key.hex()}")
