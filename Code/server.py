import socket
from cryptoHandlers import server_encapsulate

HOST = '127.0.0.1'
PORT = 65432
ALGO = 'RSA'  # Options: 'RSA', 'ECDH', 'ML-KEM'

def run_server():
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind((HOST, PORT))
        s.listen()
        print(f"The server has started to listen on port < == :: == > {PORT}. Active Algorithm: {ALGO}")
        
        while True:
            try:
                conn, addr = s.accept()
                with conn:
                    # Receive Client Public Key
                    client_pub_bytes = conn.recv(8192)
                    if not client_pub_bytes:
                        continue
                    
                    # Process Shared Secret and Ciphertext
                    ciphertext, shared_secret = server_encapsulate(ALGO, client_pub_bytes)
                    
                    # Return Ciphertext
                    conn.sendall(ciphertext)
            except Exception as e:
                # Ignore connection errors and bad data, keep the server running
                pass

if __name__ == "__main__":
    run_server()