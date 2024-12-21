import socket
import json
import time
import hashlib
import hmac
from base64 import b64decode

# Cấu hình
HOST = '127.0.0.1'  # Server's hostname
PORT = 65432        # Port đã cấu hình trên server
SECRET_KEY = "This_is_a_very_long_and_secure_secret_key_2024"  # Phải giống với server

def decode_verification_token(token):
    """Giải mã token để lấy thông tin xác thực"""
    try:
        data = json.loads(b64decode(token))
        return data["timestamp"], data["salt"], data["x"]
    except Exception as e:
        print(f"Lỗi giải mã token: {e}")
        return None, None, None

def verify_smartOTP(input_y, verification_token):
    """Xác thực OTP dựa trên token"""
    timestamp, random_salt, x = decode_verification_token(verification_token)
    if None in (timestamp, random_salt, x):
        return False
    
    message = f"{x}{timestamp}{random_salt}".encode('utf-8')
    key = SECRET_KEY.encode('utf-8')
    h = hmac.new(key, message, hashlib.sha256)
    mixed_hash = hashlib.sha512(h.digest()).digest()
    expected_otp = int.from_bytes(mixed_hash[-8:], byteorder='big') % 100000000
    if expected_otp < 10000000:
        expected_otp += 10000000
    
    return input_y == expected_otp

def handle_user_input(token, x):
    """Xử lý nhập liệu từ người dùng"""
    attempts = 0
    max_attempts = 3
    start_time = time.time()
    
    while attempts < max_attempts:
        try:
            print(f"\nSố X của bạn là: {x}")
            y = int(input("Nhập mã OTP 8 chữ số: "))
            current_time = time.time()
            
            # Kiểm tra thời gian
            if current_time - start_time > 20:
                print("Hết thời gian! Vui lòng gửi yêu cầu OTP mới.")
                return
            
            # Kiểm tra độ dài OTP
            if len(str(y)) != 8:
                print("OTP phải có 8 chữ số!")
                attempts += 1
                continue
            
            # Xác thực OTP
            if verify_smartOTP(y, token):
                print("✓ Xác thực thành công!")
                return
            else:
                print("✗ Mã OTP không chính xác!")
                attempts += 1
                
        except ValueError:
            current_time = time.time()            
            # Kiểm tra thời gian
            if current_time - start_time > 20:
                print("Hết thời gian! Vui lòng gửi yêu cầu OTP mới.")
                return
            
            print("Dữ liệu không hợp lệ!")
            attempts += 1
            
    if attempts >= max_attempts:
        print("\nBạn đã nhập sai quá 3 lần. Vui lòng gửi yêu cầu OTP mới.")

def request_otp():
    """Mở kết nối đến server để gửi yêu cầu và nhận OTP"""
    while True:
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.connect((HOST, PORT))
                print("Đã kết nối với server!")
                
                # Gửi yêu cầu OTP
                s.sendall(b"REQUEST_OTP\n")
                
                # Nhận dữ liệu từ server
                data = s.recv(1024).decode()
                if not data:
                    print("Không nhận được phản hồi từ server.")
                    return
                
                # Xử lý dữ liệu nhận được
                json_data = json.loads(data)
                x = json_data["x"]
                token = json_data["token"]
                
                print("\n" + "="*50)
                print("Nhận được OTP mới!")
                
                # Xử lý nhập liệu từ người dùng
                handle_user_input(token, x)
                break
                
        except ConnectionRefusedError:
            print("Không thể kết nối tới server. Kết nối lại sau 5 giây...")
            time.sleep(5)
        except Exception as e:
            print(f"Lỗi: {e}")

if __name__ == "__main__":
    request_otp()
