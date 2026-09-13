import struct

def send_msg(sock, msg: bytes):
    # Prefix each message with a 4-byte length (network byte order)
    msg_len = struct.pack('>I', len(msg))
    sock.sendall(msg_len + msg)

def recv_msg(sock) -> bytes:
    # Read message length and unpack it into an integer
    raw_msg_len = recvall(sock, 4)
    if not raw_msg_len:
        return None
    msg_len = struct.unpack('>I', raw_msg_len)[0]
    # Read the message data
    return recvall(sock, msg_len)

def recvall(sock, n) -> bytearray:
    # Helper function to recv n bytes or return None if EOF is hit
    data = bytearray()
    while len(data) < n:
        packet = sock.recv(n - len(data))
        if not packet:
            return None
        data.extend(packet)
    return bytes(data)
