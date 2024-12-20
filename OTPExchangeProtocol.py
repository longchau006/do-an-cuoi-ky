import random
import time
import hashlib
import hmac
import os
import json
from base64 import b64encode

# Định nghĩa các constant
SECRET_KEY = "AnToanPhucHoiDuLieu"  # Trong thực tế nên lưu trong file config riêng
SALT_LENGTH = 16

def make_smartOTP(seed_x):
    """
    Tạo OTP và thông tin cần thiết để xác thực
    """
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

# Test generator
if __name__ == "__main__":
    while True:
        try:
            x = random.randint(1000, 9999)
            otp, token = make_smartOTP(x)
            print(f"\nSố X: {x}")
            print(f"OTP: {otp}")
            print(f"Verification Token: {token}")
            
            choice = input("\nTạo OTP mới? (y/n): ")
            if choice.lower() != 'y':
                break
        except Exception as e:
            print(f"Lỗi: {e}")
            break