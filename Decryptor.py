from cryptography.fernet import Fernet
import os

def decrypt_file(key, file_path):
    try:
        f = Fernet(key)
        if os.path.isfile(file_path):
            with open(file_path, 'rb') as encrypted_file:
                encrypted = encrypted_file.read()
            decrypted = f.decrypt(encrypted)
            backup_file_path = file_path + '.bak'
            # Create a backup of the original file
            os.rename(file_path, backup_file_path)
            with open(file_path, 'wb') as decrypted_file:
                decrypted_file.write(decrypted)
            print('File decrypted successfully')
        else:
            print('Decryption unsuccessful: file not found')
    except ValueError:
        print('Decryption unsuccessful: invalid key')

if __name__ == "__main__":
    key = input("Enter the symmetric key to decrypt your file: ")
