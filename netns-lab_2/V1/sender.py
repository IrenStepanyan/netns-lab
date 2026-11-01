import socket

TARGET_HOST = "10.0.0.2"   # receiver's IP
TARGET_PORT = 5000

client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
client_socket.connect((TARGET_HOST, TARGET_PORT))   # 3-way TCP handshake happens here
print(f"[sender] Connected to {TARGET_HOST}:{TARGET_PORT}")

message = "Hello Iren!"
client_socket.send(message.encode())
print(f"[sender] Sent: {message}")

client_socket.close()
