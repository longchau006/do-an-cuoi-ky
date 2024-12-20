import json
import time
import hashlib
import hmac
from base64 import b64decode

SECRET_KEY = "AnToanPhucHoiDuLieu"  # Phải giống với máy generator
SALT_LENGTH = 16

def decode_verification_token(token):
    """
    Giải mã token để lấy thông tin xác thực
    """
    try:
        data = json.loads(b64decode(token))
        return data["timestamp"], data["salt"], data["x"]
    except Exception as e:
        print(f"Lỗi giải mã token: {e}")
        return None, None, None

def verify_smartOTP(input_y, verification_token):
    """
    Xác thực OTP dựa trên token
    """
    # Giải mã token
    timestamp, random_salt, x = decode_verification_token(verification_token)
    if None in (timestamp, random_salt, x):
        return False
    
    # Tái tạo OTP với cùng thông số
    message = f"{x}{timestamp}{random_salt}".encode('utf-8')
    key = SECRET_KEY.encode('utf-8')
    h = hmac.new(key, message, hashlib.sha256)
    mixed_hash = hashlib.sha512(h.digest()).digest()
    expected_otp = int.from_bytes(mixed_hash[-8:], byteorder='big') % 100000000
    if expected_otp < 10000000:
        expected_otp += 10000000
    
    return input_y == expected_otp

def main():
    attempts = 0
    max_attempts = 3
    
    while attempts < max_attempts:
        try:
            # Nhận verification token từ người dùng
            print("\n" + "="*50)
            token = input("Nhập verification token: ")
            start_time = time.time()
            
            y = int(input("Nhập mã OTP 8 chữ số: "))
            current_time = time.time()
            
            # Kiểm tra thời gian
            if current_time - start_time > 20:
                print("Hết thời gian! Vui lòng thử lại.")
                attempts += 1
                continue
            
            # Kiểm tra độ dài OTP
            if len(str(y)) != 8:
                print("OTP phải có 8 chữ số!")
                attempts += 1
                continue
            
            # Xác thực OTP
            if verify_smartOTP(y, token):
                print("✓ Xác thực thành công!")
                break
            else:
                print("✗ Mã OTP không chính xác!")
                attempts += 1
                
        except ValueError:
            print("Dữ liệu không hợp lệ!")
            attempts += 1
        except Exception as e:
            print(f"Lỗi: {e}")
            attempts += 1
            
    if attempts >= max_attempts:
        print("\nBạn đã nhập sai quá 3 lần. Chương trình sẽ tự hủy!")
        exit()

if __name__ == "__main__":
    main()