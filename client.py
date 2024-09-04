import socket
import threading
import getpass
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from Crypto.Random import get_random_bytes

HOST = input("Enter server IP: ")
PORT = int(input("Enter server port: "))

KEY = get_random_bytes(16)
USERNAME = getpass.getuser()

def encrypt_message(message, key):
    cipher = AES.new(key, AES.MODE_CBC)
    iv = cipher.iv
    ct_bytes = cipher.encrypt(pad(message.encode(), AES.block_size))
    return iv + ct_bytes

def decrypt_message(ciphertext, key):
    try:
        iv = ciphertext[:AES.block_size]
        ct = ciphertext[AES.block_size:]
        cipher = AES.new(key, AES.MODE_CBC, iv)
        padded_message = cipher.decrypt(ct)
        return unpad(padded_message, AES.block_size).decode()
    except (ValueError, KeyError) as e:
        print(f"\n[ERROR] Decryption error: {e}\n")
        return None

def handle_receive(client_socket):
    global KEY
    while True:
        try:
            message = client_socket.recv(1024)
            if len(message) == 16:
                KEY = message
                print(f"\n[INFO] Received new encryption key from server.\n")
            elif message:
                decrypted_message = decrypt_message(message, KEY)
                if decrypted_message is not None:
                    print(f"\n {decrypted_message}\n")
                else:
                    print("\n[ERROR] Failed to decrypt the message.\n")
            else:
                print("\n[INFO] Server closed the connection.\n")
                break
        except Exception as e:
            print(f"\n[ERROR] {e}\n")
            break

def start_client():
    client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    client_socket.connect((HOST, PORT))
    print(f"[INFO] Connected to server at {HOST}:{PORT}")

    client_socket.send(KEY)
    print(f"[INFO] Sent encryption key to server.")

    thread = threading.Thread(target=handle_receive, args=(client_socket,))
    thread.start()

    while True:
        message = input("\n[SEND MESSAGE]: ")
        full_message = f"{USERNAME}: {message}"
        encrypted_message = encrypt_message(full_message, KEY)

        client_socket.send(encrypted_message)

if __name__ == "__main__":
    start_client()

