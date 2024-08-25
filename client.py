import socket
import threading
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from Crypto.Random import get_random_bytes

HOST = input("Enter server IP: ")
PORT = int(input("Enter server port: "))

KEY = get_random_bytes(16)  

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
        print(f"[ERROR] Decryption error: {e}")
        return None

def handle_receive(client_socket):
    global KEY
    while True:
        try:
            message = client_socket.recv(1024)
            if len(message) == 16:
                KEY = message
                print(f"[INFO] Received new encryption key from server.")
            elif message:
                decrypted_message = decrypt_message(message, KEY)
                if decrypted_message is not None:
                    print(f"[MESSAGE] {decrypted_message}")
                else:
                    print("[ERROR] Failed to decrypt the message.")
            else:
                print("[INFO] Server closed the connection.")
                break
        except Exception as e:
            print(f"[ERROR] {e}")
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
        message = input("[SEND MESSAGE]: ")
        encrypted_message = encrypt_message(message, KEY)
        
        client_socket.send(encrypted_message)
        
if __name__ == "__main__":
    start_client()
