import socket
import threading

HOST = socket.gethostbyname(socket.gethostname())
PORT = 0

clients = []

def handle_client(conn, addr):
    print(f"[INFO]: {addr} connected")
    while True:
        try:
            message = conn.recv(1024)
            if not message:
                break

            if len(message) == 16:  
                print(f"[INFO] Received key from {addr}")
                broadcast_key(message, conn)
            else:
                print(f"[RECEIVED] Message from {addr}: {message}")
                broadcast(message, conn)

        except ConnectionResetError:
            break
        
    conn.close()
    clients.remove(conn)
    print(f"[INFO] {addr} disconnected.")
    
def broadcast_key(key, sender_conn):
    """Broadcast the received key to all clients except the sender."""
    for client in clients:
        if client != sender_conn:
            try:
                client.send(key)
                print(f"[INFO] Sent key to {client.getpeername()}")
            except Exception as e:
                print(f"[ERROR] Could not send key to {client.getpeername()}: {e}")

def broadcast(message, sender_conn):
    """Broadcast a normal message to all clients except the sender."""
    for client in clients:
        if client != sender_conn:
            try:
                client.send(message)
            except Exception as e:
                print(f"[ERROR] Could not send message to {client.getpeername()}: {e}")

def start_server():
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.bind((HOST, PORT))
    server.listen(5)
    print(f"[INFO] Server listening on {HOST}:{server.getsockname()[1]}")
    
    while True:
        conn, addr = server.accept()
        clients.append(conn)
        thread = threading.Thread(target=handle_client, args=(conn, addr))
        thread.start()
        
if __name__ == "__main__":
    start_server()
