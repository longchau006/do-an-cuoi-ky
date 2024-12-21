# Import các thư viện cần thiết
import os
import hashlib
import binascii
import json
import shutil
import gzip
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from tabulate import tabulate
import platform
import socket
import time
import hmac
from base64 import b64decode
import sys

# Đường dẫn đến file dữ liệu MyFS và file metadata
MYFS_PATH = "D:/MyFS.Dat"
METADATA_PATH = "E:/MyFS_Metadata.json"
BACKUP_PATH = "E:/MyFS_backup.py"
SOURCE_PATH = __file__

HOST = '127.0.0.1'  # Server's hostname
PORT = 65432        # Port đã cấu hình trên server
SECRET_KEY = "AnToanPhucHoiDuLieu_2024"  # Phải giống với server

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
                sys.exit()
            
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
                sys.exit()
            
            print("Dữ liệu không hợp lệ!")
            attempts += 1
            
    if attempts >= max_attempts:
        print("\nBạn đã nhập sai quá 3 lần. Vui lòng gửi yêu cầu OTP mới.")
        sys.exit()

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

# Cấu trúc metadata để lưu trữ thông tin về các file
metadata = {
    "files": {},  # Thông tin về các file hiện có trong MyFS
    "deleted_files": {}  # Lưu trữ các file đã xóa để có thể phục hồi
}

def calculate_hash(file_path):
    """Tính toán mã hash của file."""
    hash_func = hashlib.sha256()
    with open(file_path, 'rb') as f:
        while chunk := f.read(8192):
            hash_func.update(chunk)
    return hash_func.hexdigest()

def create_backup():
    """Tạo file backup của mã nguồn."""
    shutil.copyfile(SOURCE_PATH, BACKUP_PATH)

def check_integrity():
    """Kiểm tra tính toàn vẹn của mã nguồn."""
    if not os.path.exists(BACKUP_PATH):
        create_backup()
        return True

    original_hash = calculate_hash(BACKUP_PATH)
    current_hash = calculate_hash(SOURCE_PATH)
    return original_hash == current_hash

def restore_from_backup():
    """Phục hồi mã nguồn từ file backup."""
    shutil.copyfile(BACKUP_PATH, SOURCE_PATH)

# Hàm khởi tạo MyFS, tạo file dữ liệu và file metadata nếu chưa tồn tại
def initialize_myfs():
    global metadata

    # Kiểm tra tính toàn vẹn của mã nguồn
    if not check_integrity():
        print("Mã nguồn bị thay đổi, phục hồi từ file backup...")
        restore_from_backup()

    # Tạo file dữ liệu MyFS nếu chưa tồn tại
    if not os.path.exists(MYFS_PATH):
        with open(MYFS_PATH, 'wb') as f:
            f.write(b'')

    # Tạo file metadata nếu chưa tồn tại
    if not os.path.exists(METADATA_PATH):
        metadata["system_info"] = platform.uname()._asdict()  # Thêm thông tin hệ thống
        with open(METADATA_PATH, 'w') as f:
            json.dump(metadata, f)
    else:
        # Đọc metadata từ file nếu đã tồn tại
        with open(METADATA_PATH, 'r') as f:
            metadata = json.load(f)

    # Kiểm tra thông tin hệ thống
    current_system_info = platform.uname()._asdict()
    if metadata.get("system_info") != current_system_info:
        print("This system is not authorized to use MyFS.")
        exit()
        
     # Tạo file backup nếu chưa tồn tại
   
    if not os.path.exists(BACKUP_PATH):
        create_backup()
    print("MyFS initialized successfully.")

def set_myfs_password():
    password = input("Enter a new password for MyFS: ").strip()
    password_hash = binascii.hexlify(hash_key(password)).decode()
    metadata["myfs_password_hash"] = password_hash
    with open(METADATA_PATH, 'w') as f:
        json.dump(metadata, f)
    print("MyFS password set successfully.")
    return True  # Trả về True để cập nhật biến authenticated

def change_myfs_password():
    old_password = input("Enter the current MyFS password: ").strip()
    old_password_hash = binascii.hexlify(hash_key(old_password)).decode()
    if old_password_hash != metadata.get("myfs_password_hash"):
        print("Invalid password. Password change failed.")
        return False  # Trả về False nếu mật khẩu không đúng
    new_password = input("Enter a new password for MyFS (leave empty to remove password): ").strip()
    if new_password:
        new_password_hash = binascii.hexlify(hash_key(new_password)).decode()
        metadata["myfs_password_hash"] = new_password_hash
        print("MyFS password changed successfully.")
    else:
        del metadata["myfs_password_hash"]
        print("MyFS password removed successfully.")
    with open(METADATA_PATH, 'w') as f:
        json.dump(metadata, f)
    return True  # Trả về True để cập nhật biến authenticated

def check_myfs_password():
    password = input("Enter the MyFS password: ").strip()
    password_hash = binascii.hexlify(hash_key(password)).decode()
    if password_hash != metadata.get("myfs_password_hash"):
        print("Invalid password.")
        return False
    return True

# Hàm mã hóa file với mật khẩu
def encrypt_file(file_data, password):
    # Tạo salt ngẫu nhiên cho mật khẩu
    password_salt = os.urandom(16)
    # Tạo khóa mã hóa từ mật khẩu và salt
    key = hashlib.pbkdf2_hmac('sha256', password.encode(), password_salt, 100000, 32)
    # Tạo IV ngẫu nhiên
    iv = os.urandom(16)
    # Tạo đối tượng mã hóa AES
    cipher = Cipher(algorithms.AES(key), modes.CFB(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    # Mã hóa dữ liệu
    ciphertext = encryptor.update(file_data) + encryptor.finalize()
    return ciphertext, password_salt, iv

# Hàm giải mã file với mật khẩu
def decrypt_file(ciphertext, password, password_salt, iv):
    # Tạo khóa mã hóa từ mật khẩu và salt
    key = hashlib.pbkdf2_hmac('sha256', password.encode(), password_salt, 100000, 32)
    # Tạo đối tượng giải mã AES
    cipher = Cipher(algorithms.AES(key), modes.CFB(iv), backend=default_backend())
    decryptor = cipher.decryptor()
    # Giải mã dữ liệu
    plaintext = decryptor.update(ciphertext) + decryptor.finalize()
    return plaintext

# Hàm băm mật khẩu
def hash_key(key):
    return hashlib.sha256(key.encode()).digest()

# Hàm nhập file vào MyFS
def import_file(file_path):
    if not os.path.exists(file_path):
        print("File does not exist.")
        return

    if len(metadata["files"]) >= 99:
        print("Maximum number of files reached.")
        return

    file_name = os.path.basename(file_path)
    file_size = os.path.getsize(file_path)
    is_important = file_size <= 100 * 1024 * 1024

    if file_name in metadata["files"]:
        print(f"A file with the name '{file_name}' already exists in MyFS.")
        return

    with open(file_path, 'rb') as f:
        file_data = f.read()

    password = None
    if is_important:
        password = input("Enter a password for this file (required for important files): ").strip()
        if not password:
            print("Password is required for important files.")
            return

    # Nén dữ liệu nếu file không quan trọng
    if not is_important:
        file_data = gzip.compress(file_data)
    
    if password:
        ciphertext, password_salt, iv = encrypt_file(file_data, password)
        encrypted = True
    else:
        ciphertext = file_data
        password_salt = None
        iv = None
        encrypted = False        

    with open(MYFS_PATH, 'ab') as f:
        offset = f.tell()
        f.write(ciphertext)

    file_attributes = os.stat(file_path)
    file_directory = os.path.dirname(file_path)

    metadata["files"][file_name] = {
        "size": file_size,
        "checksum": hashlib.sha256(ciphertext).hexdigest() if is_important else None,
        "offset": offset,
        "encrypted": encrypted,
        "compressed": not is_important,
        "password_hash": binascii.hexlify(hash_key(password)).decode() if encrypted else None,
        "password_salt": binascii.hexlify(password_salt).decode() if encrypted else None,
        "iv": binascii.hexlify(iv).decode() if encrypted else None,
        "attributes": file_attributes,
        "directory": file_directory
    }

    with open(METADATA_PATH, 'w') as f:
        json.dump(metadata, f, default=str)  # Sử dụng default=str để tuần tự hóa các thuộc tính file

    print(f"File {file_name} imported successfully.")

# Hàm xuất file từ MyFS
def export_file(file_name, export_path=None):
    if file_name not in metadata["files"]:
        print("File not found in MyFS.")
        return

    file_info = metadata["files"][file_name]

    with open(MYFS_PATH, 'rb') as f:
        f.seek(file_info["offset"])
        ciphertext = f.read(file_info["size"])

    if file_info["checksum"]:
        current_checksum = hashlib.sha256(ciphertext).hexdigest()
        if current_checksum != file_info["checksum"]:
            print("Data integrity check failed. Export aborted.")
            return

    if file_info["compressed"]:
        file_data = gzip.decompress(ciphertext)

    if file_info["encrypted"]:
        password = input("Enter the password for this file: ").strip()
        password_hash = binascii.hexlify(hash_key(password)).decode()
        if password_hash != file_info["password_hash"]:
            print("Invalid password. Export failed.")
            return

        password_salt = binascii.unhexlify(file_info["password_salt"])
        iv = binascii.unhexlify(file_info["iv"])
        try:
            file_data = decrypt_file(ciphertext, password, password_salt, iv)
        except Exception:
            print("Invalid password. Export failed.")
            return

    if export_path is None:
        export_path = os.path.join(file_info["directory"], file_name)

    with open(export_path, 'wb') as f:
        f.write(file_data)

    print(f"File {file_name} exported to {export_path}.")

# Hàm thay đổi mật khẩu của file
def change_password(file_name):
    if file_name not in metadata["files"]:
        print("File not found in MyFS.")
        return

    file_info = metadata["files"][file_name]

    if not file_info["encrypted"]:
        print("File is not encrypted. Cannot change password.")
        return

    with open(MYFS_PATH, 'rb') as f:
        f.seek(file_info["offset"])
        ciphertext = f.read(file_info["size"])

    if file_info["checksum"]:
        current_checksum = hashlib.sha256(ciphertext).hexdigest()
        if current_checksum != file_info["checksum"]:
            print("Data integrity check failed. Password change aborted.")
            return

    old_password = input("Enter the current password for this file: ").strip()
    password_hash = binascii.hexlify(hash_key(old_password)).decode()
    if password_hash != file_info["password_hash"]:
        print("Invalid password. Password change failed.")
        return

    password_salt = binascii.unhexlify(file_info["password_salt"])
    iv = binascii.unhexlify(file_info["iv"])
    try:
        file_data = decrypt_file(ciphertext, old_password, password_salt, iv)
    except Exception:
        print("Invalid password. Password change failed.")
        return

    if file_info["compressed"]:
        file_data = gzip.decompress(file_data)

    new_password = input("Enter the new password for this file: ").strip()
    new_ciphertext, new_password_salt, new_iv = encrypt_file(file_data, new_password)

    if file_info["compressed"]:
        new_ciphertext = gzip.compress(new_ciphertext)

    with open(MYFS_PATH, 'ab') as f:
        new_offset = f.tell()
        f.write(new_ciphertext)

    file_info["password_hash"] = binascii.hexlify(hash_key(new_password)).decode()
    file_info["password_salt"] = binascii.hexlify(new_password_salt).decode()
    file_info["iv"] = binascii.hexlify(new_iv).decode()
    file_info["offset"] = new_offset
    file_info["checksum"] = hashlib.sha256(new_ciphertext).hexdigest() if file_info["checksum"] else None

    with open(METADATA_PATH, 'w') as f:
        json.dump(metadata, f)

    print(f"Password for {file_name} updated successfully.")

# Hàm liệt kê các file trong MyFS
def list_files():
    if not metadata["files"]:
        print("No files in MyFS.")
        return

    table = []
    for file_name, file_info in metadata["files"].items():
        table.append([
            file_name,
            f"{file_info['size']} bytes",
            file_info["offset"],
            "Yes" if file_info["encrypted"] else "No"
        ])

    headers = ["Name", "Size", "Offset", "Encrypted"]
    print("\nFiles in MyFS:")
    print(tabulate(table, headers=headers, tablefmt="grid"))

# Hàm xóa file khỏi MyFS
def delete_file(file_name):
    if file_name not in metadata["files"]:
        print("File not found in MyFS.")
        return

    file_info = metadata["files"][file_name]

    if file_info["encrypted"]:
        password = input("Enter the password for this file: ").strip()
        password_hash = binascii.hexlify(hash_key(password)).decode()
        if password_hash != file_info["password_hash"]:
            print("Invalid password. File deletion failed.")
            return

    metadata["deleted_files"][file_name] = metadata["files"][file_name]
    del metadata["files"][file_name]

    with open(METADATA_PATH, 'w') as f:
        json.dump(metadata, f)

    print(f"File {file_name} deleted successfully.")

# Hàm phục hồi file đã xóa
def restore_file(file_name):
    if file_name not in metadata["deleted_files"]:
        print("File not found in deleted files.")
        return

    metadata["files"][file_name] = metadata["deleted_files"][file_name]
    del metadata["deleted_files"][file_name]

    with open(METADATA_PATH, 'w') as f:
        json.dump(metadata, f)

    print(f"File {file_name} restored successfully.")

# Hàm menu để người dùng tương tác với hệ thống
def menu():
    authenticated = False
    if "myfs_password_hash" in metadata:
        # Yêu cầu nhập mật khẩu hệ thống khi khởi động nếu đã đặt mật khẩu
        if not check_myfs_password():
            print("Invalid password. Exiting MyFS.")
            return
        authenticated = True

    while True:
        print("\nMyFS Menu")
        print("1. Import a File")
        print("2. Export a File")
        print("3. Change File Password")
        print("4. List Files")
        print("5. Delete a File")
        print("6. Restore a File")
        if "myfs_password_hash" not in metadata:
            print("7. Set MyFS Password")
        else:
            print("7. Change MyFS Password")
        print("8. Exit")

        choice = input("Enter your choice: ")

        if choice == "1":
            if "myfs_password_hash" not in metadata or authenticated:
                file_path = input("Enter the path of the file to import: ")
                import_file(file_path)
        elif choice == "2":
            if "myfs_password_hash" not in metadata or authenticated:
                file_name = input("Enter the file name to export: ")
                export_path = input("Enter the path to export the file (leave empty to use original path): ").strip()
                if not export_path:
                    export_file(file_name)
                else:
                    export_file(file_name, export_path)
        elif choice == "3":
            if "myfs_password_hash" not in metadata or authenticated:
                file_name = input("Enter the file name to change password: ")
                change_password(file_name)
        elif choice == "4":
            if "myfs_password_hash" not in metadata or authenticated:
                list_files()
        elif choice == "5":
            if "myfs_password_hash" not in metadata or authenticated:
                file_name = input("Enter the file name to delete: ")
                delete_file(file_name)
        elif choice == "6":
            if "myfs_password_hash" not in metadata or authenticated:
                file_name = input("Enter the file name to restore: ")
                restore_file(file_name)
        elif choice == "7":
            if "myfs_password_hash" not in metadata:
                authenticated = set_myfs_password()
            else:
                authenticated = change_myfs_password()
        elif choice == "8":
            print("Exiting MyFS. Goodbye!")
            break
        else:
            print("Invalid choice. Please try again.")


if __name__ == "__main__":
    request_otp()
    initialize_myfs()
    menu()