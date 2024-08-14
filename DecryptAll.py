import os
import marshal
import pickle
import json
import base64
import zlib
import bz2
import lzma
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend

def decrypt_marshal(file_path):
    """فك تشفير ملفات مشفرة باستخدام marshal"""
    with open(file_path, 'rb') as f:
        f.seek(16)  # تخطي رأس الملف
        code = marshal.load(f)
        return code

def decrypt_pickle(file_path):
    """فك تشفير ملفات مشفرة باستخدام pickle"""
    with open(file_path, 'rb') as f:
        data = pickle.load(f)
        return data

def decrypt_json(file_path):
    """فك تشفير ملفات مشفرة باستخدام JSON"""
    with open(file_path, 'r') as f:
        data = json.load(f)
        return data

def decrypt_base64(file_path):
    """فك تشفير نصوص مشفرة بـ base64"""
    with open(file_path, 'r') as f:
        encoded_str = f.read()
    decoded_bytes = base64.b64decode(encoded_str)
    return decoded_bytes.decode('utf-8')

def decrypt_zlib(file_path):
    """فك تشفير البيانات المضغوطة باستخدام zlib"""
    with open(file_path, 'rb') as f:
        compressed_data = f.read()
    decompressed_data = zlib.decompress(compressed_data)
    return decompressed_data

def decrypt_bz2(file_path):
    """فك تشفير البيانات المضغوطة باستخدام bz2"""
    with open(file_path, 'rb') as f:
        compressed_data = f.read()
    decompressed_data = bz2.decompress(compressed_data)
    return decompressed_data

def decrypt_lzma(file_path):
    """فك تشفير البيانات المضغوطة باستخدام lzma"""
    with open(file_path, 'rb') as f:
        compressed_data = f.read()
    decompressed_data = lzma.decompress(compressed_data)
    return decompressed_data

def decrypt_aes(file_path, key, iv):
    """فك تشفير البيانات المشفرة باستخدام AES"""
    if len(key) not in [16, 24, 32]:
        raise ValueError("مفتاح التشفير يجب أن يكون بطول 16، 24، أو 32 بايت")
    if len(iv) != 16:
        raise ValueError("IV يجب أن يكون بطول 16 بايت")

    with open(file_path, 'rb') as f:
        encrypted_data = f.read()

    cipher = Cipher(algorithms.AES(key), modes.CFB(iv), backend=default_backend())
    decryptor = cipher.decryptor()
    decrypted_data = decryptor.update(encrypted_data) + decryptor.finalize()
    return decrypted_data

def main():
    current_path = os.path.dirname(os.path.realpath(__file__))
    options = {
        '1': ('marshal', decrypt_marshal),
        '2': ('pickle', decrypt_pickle),
        '3': ('json', decrypt_json),
        '4': ('base64', decrypt_base64),
        '5': ('zlib', decrypt_zlib),
        '6': ('bz2', decrypt_bz2),
        '7': ('lzma', decrypt_lzma),
        '8': ('aes', decrypt_aes)
    }

    print("اختر نوع التشفير الذي تريد فك تشفيره:")
    for key, value in options.items():
        print(f"{key}. {value[0]}")

    choice = input("أدخل رقم الخيار: ")

    if choice not in options:
        print("اختيار غير صالح.")
        return

    ext, decrypt_function = options[choice]

    if ext == 'aes':
        key = input("أدخل مفتاح التشفير (يجب أن يكون بطول 16 أو 24 أو 32 بايت): ").encode()
        iv = input("أدخل IV (يجب أن يكون بطول 16 بايت): ").encode()
        for file in os.listdir(current_path):
            if file.endswith('.enc'):
                file_path = os.path.join(current_path, file)
                try:
                    decrypted_data = decrypt_function(file_path, key, iv)
                    new_file_path = os.path.join(current_path, f"decrypted_{file}")
                    with open(new_file_path, 'wb') as f:
                        f.write(decrypted_data)
                    print(f"تم حفظ الملف المفكك: {new_file_path}")
                except Exception as e:
                    print(f"حدث خطأ أثناء فك التشفير: {e}")
    else:
        for file in os.listdir(current_path):
            if file.endswith(f".{ext}"):
                file_path = os.path.join(current_path, file)
                print(f"فك تشفير {file_path}")

                try:
                    decrypted_data = decrypt_function(file_path)
                    new_file_path = os.path.join(current_path, f"decrypted_{file}")
                    with open(new_file_path, 'w' if ext != 'zlib' else 'wb') as f:
                        f.write(decrypted_data)
                    print(f"تم حفظ الملف المفكك: {new_file_path}")
                except Exception as e:
                    print(f"حدث خطأ أثناء فك التشفير: {e}")

if __name__ == "__main__":
    main()
