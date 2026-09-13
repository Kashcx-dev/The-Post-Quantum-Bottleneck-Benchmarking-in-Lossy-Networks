import socket
import time
import statistics

HOST = '127.0.0.1'
PORT = 65432
ITERATIONS = 5000
latencies = []

def run_calibration():
    for _ in range(ITERATIONS):
        start = time.perf_counter()
        
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.connect((HOST, PORT))
            s.sendall(b"0" * 32) 
            s.recv(4096)         
            
        end = time.perf_counter()
        latencies.append((end - start) * 1000)

    median_latency = statistics.median(latencies)
    mean_latency = sum(latencies) / ITERATIONS
    
    print(f"Median OS Loopback Baseline: {median_latency:.4f} ms")
    print(f"Mean (for reference): {mean_latency:.4f} ms")

if __name__ == "__main__":
    run_calibration()