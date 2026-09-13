import socket
import time
import statistics
from cryptoHandlers import get_client_pubkey, client_decapsulate

HOST = '127.0.0.1'
PORT = 65432
ALGO = 'RSA'  # Options: 'RSA', 'ECDH', 'ML-KEM'
ITERATIONS = 1000
OS_BASELINE_MS = 0.0858  # Your calculated loopback median

def run_client():
    latencies = []
    failures = 0
    print(f"Benchmarking {ITERATIONS} handshakes for {ALGO}...")

    for i in range(ITERATIONS):
        if (i + 1) % 100 == 0:
            print(f"  ... completed {i + 1}/{ITERATIONS} handshakes")
            
        # Pre-generate keys (Outside timer to isolate network speed)
        pub_bytes, priv_state = get_client_pubkey(ALGO)
        
        # --- TIMER START ---
        start_time = time.perf_counter()
        
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.settimeout(5.0)  # Add a 5 second timeout so it doesn't hang forever
                s.connect((HOST, PORT))
                s.sendall(pub_bytes)
                ciphertext = s.recv(8192)
                
            end_time = time.perf_counter()
            # --- TIMER END ---
            
            # Extract secret (Outside timer)
            shared_secret = client_decapsulate(ALGO, priv_state, ciphertext)
            
            # Calculate true network delay
            raw_latency_ms = (end_time - start_time) * 1000
            true_net_latency = raw_latency_ms - OS_BASELINE_MS
            latencies.append(true_net_latency)
            
        except Exception as e:
            failures += 1
            # print(f"  [!] Handshake {i} failed: {e}")

    # Final Output
    if latencies:
        median_latency = statistics.median(latencies)
        print(f"[{ALGO}] True Median Latency: {median_latency:.6f} ms")
    else:
        print(f"[{ALGO}] All handshakes failed!")
    
    failure_rate = (failures / ITERATIONS) * 100
    print(f"[{ALGO}] Failure Rate: {failure_rate:.2f}% ({failures}/{ITERATIONS})")
    
if __name__ == "__main__":
    run_client()