# Import các thư viện cần thiết
import os
import hashlib
import binascii
import json
import shutil
import gzip
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.fernet import Fernet
from tabulate import tabulate
import platform

# Đường dẫn đến file dữ liệu MyFS và file metadata
MYFS_PATH = "D:/MyFS.Dat"
METADATA_PATH = "E:/MyFS_Metadata.json"
BACKUP_PATH = "E:/MyFS_Backup.json"

# Cấu trúc metadata để lưu trữ thông tin về các file
metadata = {
    "files": {},  # Thông tin về các file hiện có trong MyFS
    "encryption_key": None,  # Khóa mã hóa mặc định
    "deleted_files": {}  # Lưu trữ các file đã xóa để có thể phục hồi
}

# Hàm khởi tạo MyFS, tạo file dữ liệu và file metadata nếu chưa tồn tại
def initialize_myfs():
    global metadata

    # Tạo file dữ liệu MyFS nếu chưa tồn tại
    if not os.path.exists(MYFS_PATH):
        with open(MYFS_PATH, 'wb') as f:
            f.write(b'')

    # Tạo file metadata nếu chưa tồn tại
    if not os.path.exists(METADATA_PATH):
        encryption_key = Fernet.generate_key()
        metadata["encryption_key"] = encryption_key.decode()
        metadata["system_info"] = platform.uname()._asdict()  # Thêm thông tin hệ thống
        with open(METADATA_PATH, 'w') as f:
            json.dump(metadata, f)
    else:
        # Đọc metadata từ file nếu đã tồn tại
        with open(METADATA_PATH, 'r') as f:
            metadata = json.load(f)

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

# Hàm sao lưu metadata
def backup_metadata():
    shutil.copy(METADATA_PATH, BACKUP_PATH)
    print("Metadata backup created.")

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

    backup_metadata()
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

    backup_metadata()
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

    backup_metadata()
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

    backup_metadata()
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
    initialize_myfs()
    menu()