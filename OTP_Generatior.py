import socket
import random
import time
import hashlib
import hmac
import os
import json
from base64 import b64encode
import threading

# Cấu hình
HOST = '127.0.0.1'  # Localhost
PORT = 65432        # Port để lắng nghe
SECRET_KEY = "AnToanPhucHoiDuLieu_2024"
SALT_LENGTH = 16

def make_smartOTP(seed_x):
    """Tạo OTP và token xác thực"""
    timestamp = int(time.time() * 1000000)
    random_salt = os.urandom(SALT_LENGTH).hex()
    
    # Tạo OTP
    message = f"{seed_x}{timestamp}{random_salt}".encode('utf-8')
    key = SECRET_KEY.encode('utf-8')
    h = hmac.new(key, message, hashlib.sha256)
    mixed_hash = hashlib.sha512(h.digest()).digest()
    final_bytes = mixed_hash[-8:]
    otp = int.from_bytes(final_bytes, byteorder='big') % 100000000
    if otp < 10000000:
        otp += 10000000

    # Tạo verification token
    verification_data = {
        "timestamp": timestamp,
        "salt": random_salt,
        "x": seed_x
    }
    token = b64encode(json.dumps(verification_data).encode()).decode()
    
    return otp, token

def handle_client(conn, addr):
    """Xử lý kết nối từ một client"""
    print(f"Connected by {addr}")
    try:
        while True:
            # Chờ yêu cầu từ CLIENT
            request = conn.recv(1024).decode()
            if not request:
                break
            
            # Nếu CLIENT gửi yêu cầu "REQUEST_OTP"
            if request.strip() == "REQUEST_OTP":
                # Tạo số X ngẫu nhiên và OTP
                x = random.randint(1000, 9999)
                otp, token = make_smartOTP(x)
                
                # Gửi dữ liệu tới client
                data = {
                    "x": x,
                    "token": token,
                    "timestamp": int(time.time())
                }
                json_data = json.dumps(data)
                conn.sendall(json_data.encode() + b"\n")
                
                print("The token has been sent to the authentication device.")
                print(f"X: {x}")
                print(f"OTP: {otp}")
                
            else:
                print("Received an invalid request from the CLIENT.")
    except Exception as e:
        print(f"Error: {e}")
    finally:
        conn.close()
        print(f"Connection from {addr} closed")

def start_server():
    """Khởi động server"""
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.bind((HOST, PORT))
    server.listen()
    print(f"The server is listening at... {HOST}:{PORT}")
    
    try:
        while True:
            conn, addr = server.accept()
            client_thread = threading.Thread(target=handle_client, args=(conn, addr))
            client_thread.start()
    except KeyboardInterrupt:
        print("\nThe server is stopping...")
    finally:
        server.close()

if __name__ == "__main__":
    start_server()