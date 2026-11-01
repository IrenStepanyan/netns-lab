import socket

HOST = "10.0.0.2"   # receiver's own IP inside ns_receiver
PORT = 5000

# AF_INET = IPv4, SOCK_STREAM = TCP
server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

# Allow quick restart of the script without "Address already in use"
server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

server_socket.bind((HOST, PORT))   # attach socket to this IP:port
server_socket.listen(1)            # start listening, queue of 1 pending connection
print(f"[receiver] Listening on {HOST}:{PORT} ...")

conn, addr = server_socket.accept()   # blocks until sender connects
print(f"[receiver] Connection established from {addr}")

data = conn.recv(1024)   # read up to 1024 bytes
print(f"[receiver] Received: {data.decode()}")

conn.close()
server_socket.close()
