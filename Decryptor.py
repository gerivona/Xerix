from cryptography.fernet import Fernet
import os 

# Read the key from the unlock.key file
key = input("Enter the symmetric key to decrypt your file:")

try:
    f = Fernet(key)
    # Ask the user for the name of the file to be decrypted
    x = bytes(input('Enter file to be decrypted:'), 'utf-8')
    if os.path.isfile(x):
        with open(x, 'rb') as encrypted_file:
            encrypted = encrypted_file.read()
        # Decrypt the file
        decrypted = f.decrypt(encrypted)
        with open(x, 'wb') as decrypted_file:
            decrypted_file.write(decrypted)
            print('File decrypted successfully')
    else:
        print('Decryption unsuccessful: file not found')
except ValueError:
    print('Decryption unsuccessful: invalid key')

