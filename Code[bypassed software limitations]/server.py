import socket
from cryptoHandlers import server_encapsulate
from utils import recv_msg, send_msg

HOST = '127.0.0.1'
PORT = 65432
ALGO = 'ML-KEM'  # Options: 'RSA', 'ECDH', 'ML-KEM'

def run_server():
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind((HOST, PORT))
        s.listen()
        print(f"The server has started to listen on port < == :: == > {PORT}. Active Algorithm: {ALGO}")
        
        while True:
            try:
                conn, addr = s.accept()
                with conn:
                    print(f"Connected by {addr}, starting continuous stream...")
                    while True:
                        # Receive Client Public Key
                        client_pub_bytes = recv_msg(conn)
                        if not client_pub_bytes:
                            print("Client disconnected.")
                            break
                        
                        # Process Shared Secret and Ciphertext
                        ciphertext, shared_secret = server_encapsulate(ALGO, client_pub_bytes)
                        
                        # Return Ciphertext
                        send_msg(conn, ciphertext)
            except Exception as e:
                # Ignore connection errors and bad data, keep the server running
                pass

if __name__ == "__main__":
    run_server()