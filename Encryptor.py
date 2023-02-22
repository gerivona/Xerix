from cryptography.fernet import Fernet
import os 

key = bytes(input('Enter key:'),'utf-8')
        #string the key into a file
with open('unlock.key', 'wb') as unlock:
           unlock.write(key)
             
with open('unlock.key', 'rb') as unlock:
        key = unlock.read()
        print(key)

try:
   f = Fernet(key)
   #open the original file to encrypt
   x = bytes(input('Enter file to be encrypted:'),'utf-8')
   if os.path.isfile(x):
      with open(x, 'rb') as original_file:
         original = original_file.read()
#encrypt the file
      encrypted = f.encrypt(original)
      with open(x,"wb") as f:
          f.write(encrypted)
          print("File Encrypted Succesfully")

   else:
         print("Encryption unsucessfull Please check if the file is the same directory with Xerix") 
except ValueError:
   print("Enter a valid key")