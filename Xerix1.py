import os
import time
import whois
import ipapi
import socket
import random
import getpass
import codecs
import string
import hashlib
import pyfiglet
import requests
import pyperclip
import cryptography
import socketserver
from faker import Faker
from datetime import date
#from zipfile import Zipfile
from datetime import datetime
from cryptography.fernet import Fernet

#Introduction to Xerix program
def intro():
      ascii_banner = pyfiglet.figlet_format("XERIX")
      print(ascii_banner)
      print("Created by:CYBER ELITE NETWORK™")
      print ("C <----- You must create an account first To do so press C")
      print ("L <----- To login")
      print("-" *100)

# Text conversion to hash  
class Hashes:

    def __init__(self):
        pass

    def md5_str(self):
            '''it takes a string and converts it to a md5 hash'''
            a_string = input("Enter text to be hashed:")
            st = time.process_time()
            hashed_string = hashlib.md5(a_string.encode('utf-8')).hexdigest()
            print(hashed_string)
            clip_board = pyperclip.copy(hashed_string)
            et = time.process_time()
            ep = et - st
            print("Execution time:",ep,"sec")
            print("-"*50)        
        
    def Sha256_str(self):
            '''it takes a string and converts it to sha256 hash'''
            st = time.process_time()
            b_string = input("Enter text to be hashed:")
            hashed_string = hashlib.sha256(b_string.encode('utf-8')).hexdigest()
            print (hashed_string)
            clip_board = pyperclip.copy(hashed_string)
            et = time.process_time()
            ep = et - st
            print("Execution time",ep,"sec")
            print("-"*50)
            
    def Sha512_str(self):
          '''it takes a string and coverts it to sha512 hash'''
          c_string = input("Enter text to be hashed:")
          st = time.process_time()  
          hashed_string = hashlib.sha512(c_string.encode('utf-8')). hexdigest ()
          print (hashed_string)
          clip_board = pyperclip.copy(hashed_string)
          et = time.process_time()
          ep = et - st
          print("Execution time:",ep,"sec") 
          print("-"*50)

#Encrypting strings 
def str_enc():
     '''it encrypts a string using fernet and it also decrypts the string'''
     st = time.process_time()         
     while True:
          text = input ("Enter an option:")
          
# encryption
          if text == ("encrypt"):
               key =bytes(input("Enter key:"),"utf-8")
               fernet = Fernet(key)
               Text = input("Enter text:")
               x = bytes(Text,'utf-8')
               x = fernet.encrypt(x)
               print(x)
               break
#decryption
          elif text == "decrypt":

              encText = input("Enter encrypted text:")
              key = input("Enter key:")
              f = Fernet(key)
              c = f.decrypt(bytes(encText, 'utf-8'))
              print(c.decode('utf-8'))
                
          else: 
                    print ("Not found")      
     et = time.process_time()
     ep = et - st
     print("Execution time:",ep,"sec")
     print("-" *50)

#The class that has operating system commands
class Ops:
  
    def pwd(self):
         ''' shows the working directory'''
         st = time.process_time()
         print (os.getcwd())
         et = time.process_time()
         ep = et - st
         print("Execution time:",ep,"secs")
         print('-'*50)
         
    def clear(self):
         '''it clears the screen'''
         os.system('cls')
         
    def cd(self):
          ''' changes the directory'''
          st = time.process_time()       
          path = input ("Enter path:")
          try:
              print (os.chdir(path))
          except:
                print("Enter a valid path")
          et = time.process_time()
          ep = et - st
          print("Execution time:",ep,"secs")
          print("-"*50)

    def shutdown(self):
        ''' shutdowns your computer '''
        os.system("shutdown /s")

    def shutab(self):
        '''aborts the shutdown command '''
        os.system("shutdown /a")
          
    def mkdir(self):
         ''' makes a new directory'''
         st = time.process_time()          
         var = input("Enter the name of the directory:")
         os.mkdir(var)
         print ("This folder is created in the working directory")
         print ('folder created successfully')
         et = time.process_time()
         ep = et - st
         print("Execution time:",ep,"secs")
         print("-"*50)

    def ls(self):
             ''' lists all the files in the current directory'''
             st = time.process_time()
             print (os.listdir())
             et = time.process_time()
             ep = et - st
             print("Execution time:",ep)
             print("-"*50)
             
              
    def rmdir (self):
           ''' remove the current directory'''
           st = time.process_time()
           rmip = input ("Enter folder:")
           try:
               os.rmdir(rmip)
           except:
             print("Enter a valid folder")
           et = time.process_time()
           ep = et - st
           print("Execution time:",ep,"secs")
           print("-"*50)

    def meta_info(self):
            ''' gives meta information about a file'''
            st = time.process_time()   
            file_info  = input ("Enter file name and extension:")
            print (os.stat(file_info))
            et = time.process_time()
            ep = et - st 
            print("Exection time:",ep,"secs")
            print("-"*50)
            
    def file_date(self):
             '''' it gives you the last modification date of a file'''
             st = time.process_time()        
             file = input ("Enter file name and extension:")
             print ("Please make sure the file is in the current directory")
             t=os.stat(file).st_mtime
             print(datetime.fromtimestamp(t))
             et = time.process_time()
             ep = et - st
             print ("Execution time:",ep,"secs")
             print("-"*50)

# The Web section
class web:

    def __init__(self):
        pass
    
    def html_request(self):
          ''' shows the html code of a website'''
          try:
              st = time.process_time()
              html = input ("Enter URL:")
              x = requests.get(html)              
              print (x.text)
              et = time.process_time()
              ep = et - st
              print("Execution time:",ep,"secs")
              print("-"*50)
          except:
            print('No connection')
          
    def html_write(self):
        ''' if allows you to write html file'''
        st = time.process_time()
        path2 = input ("Enter directory:")
        os.chdir(path2)
        with open (input("Enter the HTML file to be created:"),"w") as codes:
            codes.write(input("Enter your codes:"))
            codes.close()
        et = time.process_time()
        ep = et - st
        print("Execution time:",ep,"secs")
        print("-"*50)
     
    def domain(self):
        ''' checks the avaliablity of a domain'''
        st = time.process_time()
        x = input("Enter domain:")
        domain = whois.whois(x)
        et = time.process_time()
        ep = et - st
        print("Execution time:",ep,"secs")
        print("-"*50)

class Enc:

      def __init__(self):
        pass

      def enc_file_key(self):
            ''' this is used to encrypt a file in symmetric key cryptography using the fernet encryption algrorithms'''
            st = time.process_time()
            try:
                import Encryptor
            except:
                print("Try a valid key")
                print("You could generate a key using the sym key command")
                print("-"*50)
            et = time.process_time()
            ep = et - st 
            print("Execution time:",ep,"secs")
            print("-"*50) 
      
      def dec_file_key():
          ''' This is used to decrypt a file that has been encrypted with symmetric key cryptography '''
          try:
              st = time.process_time()
              import Decryptor
              et = time.process_time()
              ep = et - st
              print("Execution time:",ep,"secs")
          except:
             print("Enter a valid file")
 
def pass_Gen():                 
  ''' This is a password genrator'''
  # Choose a random selection of characters from the set of lowercase letters, uppercase letters, and digits
  y = string.ascii_lowercase + string.ascii_uppercase + string.digits 
  pas = input("Enter length:")

  if pas == "4":
       for i in range(0,4):
          pg_copy1 = print(random.choice(y),end="")
          pyperclip.copy(pg_copy1)
  elif pas == "6":
        for i in range(0,6):
          pg_copy2 = print(random.choice(y),end="")
          pyperclip.copy(pg_copy2)
  elif pas == "8":
       for i in range(0,8):
            pg_copy2 = print(random.choice(y),end="")
  else:
       print("Enter an option")

class Net:

    def __init__(self):
        pass
   
    def ip_private(self):
      '''shows you your private ip address'''
      st = time.process_time()
      get = socket.gethostname()    
      x = socket.gethostbyname(get)
      print(get,":",x)
      et = time.process_time()
      ep = et - st
      print("Execution time",ep,"secs")
      print("-"*50)
     
    def ip_public(self):
        '''shows the public ip address '''
        st = time.time()
        try:
             response = requests.get("https://api.ipify.org")
             if response.status_code == 200:
                  print(response.text)
                  return response.text
             else:
                return "Unable to get IP address"
        except:
           print("No connection")  
        et = time.time()
        ep = et - st
        print("Execution time:",ep,"secs")
        print("-"*50)
  
    def ip_config(self):
        ''' shows the both the public and private ip address'''
        s = socket.gethostname()
        t = socket.gethostbyname(s)
        print(s,":",t)
        try:
              response = requests.get('https://api.ipify.org')
              if response.status_code == 200:
                 print(response.text)
              else:
                   print("Unable to get ip address")
        except:
               print("No connection")
        print("-"*50)
       
    def web_ip(self):
        ''' shows the ip address of a website'''
        st = time.process_time()
        try:
             web_input = input ("Enter website:")
             s = socket.gethostbyname(web_input)
             print(s)
        except:
           print("Unable to find ip address")
        et = time.process_time()
        ep = et - st
        print("Execution time:",ep,"secs")
        print("-"*50)

    def ip_track(ip):
          ''' tracks the ip address by providing the infotmation of the country where the ip address is located and many more'''
          st = time.process_time()
          try:
              location = ipapi.location(ip)
              print("country:",location['country_name'])
              print("contry capital:",location['country_capital'])
              print("Region:",location['region'])
              print("Continent:",location['continent_code'])  
              print("longitude:", location['longitude'])
              print("latitude:", location['latitude'])
              print("oragansation:",location['org'])     
          except:
              print("Unable to find info of the ip address") 
          et = time.process_time()
          ep = et - st
          print("Execution time:",ep,"secs")
          print("-"*50)
    
    def ps( self,start_port,end_port,target):
        ''' Scans for open ports of a network ip address '''
        print(f"Scanning ports {start_port} to {end_port} on {target}...")
        for port in range(start_port, end_port + 1):
             sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
             sock.settimeout(0.5)
             result = sock.connect_ex((target, port))
             if result == 0:
                 print(f"Port {port} is open")
             sock.close()


    def lanc_host(self):
        ''' Creates a chat server within a LAN '''
        # create a socket object
        server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

        # get the hostname of this machine
        host = socket.gethostname()

        # specify the port to use
        port = 12345

        # bind the socket to a specific address and port
        server.bind((host, port))

        # set the server to listen for incoming connections
        server.listen(5)

        print(f"Server listening on {host}:{port}...")

         # loop to handle multiple client connections
        while True:
           # wait for a client to connect
           client, address = server.accept()
           print(f"Received connection from {address}")
    
           # send a welcome message to the client
           client.send("Welcome to the server!".encode())
    
           # loop to handle messages from the client
           while True:
                # receive a message from the client
                data = client.recv(1024).decode()
        
           # if the client closes the connection, break out of the loop
           if not data:
              break
        
           print(f"Received message from {address}: {data}")
        
           # send a response back to the client
           response = f"You sent: {data}"
           client.send(response.encode())
    
         # close the connection with the client
           client.close()
           print(f"Connection with {address} closed")

 

    def lanc_clt(self):
        '''Connecting to a server created by another Xerix commander or created by you'''
        try:
        # create a socket object
           client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

        # get server hostname
           host = socket.gethostname()

        # specify port to use
           port = 12345

        # connect to the server
           client.connect((host, port))

        # receive the welcome message from the server
           data = client.recv(1024).decode()
           print(data)

       # loop to send multiple messages to the server
           while True:
           # prompt the user for input
              message = input("Enter a message to send to the server (or type 'quit' to exit): ")
    
           # if the user enters 'quit', break out of the loop
              if message.lower() == 'quit':
                 break
    
        # send the message to the server
           client.send(message.encode())
    
        # receive the server's response
           response = client.recv(1024).decode()
           print(f"Response from server: {response}")

        # close the connection
           client.close()
        except ConnectionRefusedError:
            print("No connection try again!")

    def Net_Sender():
        ''' Allows you to send a file while being the host'''

        host = gethostbyname(gethostname())
        clients = socket.socket(AF_INET,socket.SOCK_STREAM)

        clients.connect((host,1234))
        file_input = input("Enter the file:")
        file = open(file_input,"rb")
        file_size = os.path.getsize(file)
        print(f"The size of the file is {file_size}")
        
    def Nets_Cli():
        ''' Allows you to recieve a file incomming from the host over a LAN'''
        
         
def sym_gen_key():
      '''' generates a 32 bit key for symmetric key encryption'''
      st = time.process_time()
      key = Fernet.generate_key()
      with open("sym.txt","wb") as f:
        f.write(bytes(key))
      print(key)     
      str_key = codecs.decode(key)
      pyperclip.copy(str_key)
      et = time.process_time()
      ep = et - st
      print("Execution time:",ep,"secs")
      print('-'*50)
    
def EXIF_Scraper():
    ''' This tool scrapes the meta data (EXIF) of an image or a picture'''
    st = time.process()

      
def To_date():
  '''
  it prints out today's date and time'''
  today = date.today()
  print(today)
  
def timer():
  ''' prints out the current time'''
  now = datetime.now()
  print(now)


class SocialEng:

    def __init__(self):
        pass
    
    def fake_name(self):
      '''this generates random fake names'''
      st =time.process_time()
      try:
         x = int(input('Enter the numbers of name:'))
         faker = Faker()
         for i in range(0,x):
             print(faker.name())
      except:
           print('Enter a valid Number')
      et = time.process_time()
      ep = et - st
      print('Execution time:',ep,'secs')

class Cracker:

    def __init__(self):
        pass

    def zip_cracker():
        pass


 
def help1():     
      help2 = ("cd <--- changes directory","cls <--- clears the screen","dom av <--- checks for the avalibility of  a domain","dec file <--- used to decrypt files that are encrypted","enc file <--- used to encrypt file","file_info  <--- prints information about a file","file_date <--- shows the last modification date about  a file","ip/config <--- prints the  ip address of the device","md5_str <-- hashes a string in md5 algorithm","mkdir <--- creates directory","pg <--- generates a passowrd","sha256 <--- hashes a string in sha256 algorithm","sha512 <--- hashes a string in sha512 algorithm","sym key <--- randomly generate a symmetric key")
      print(help2)
         
#help section                        
intro()
def commands():
    while True:
         cmd = input (">>> ")
         if cmd.startswith('md5_str'):
            Hash1 = Hashes()
            Hash1.md5_str()
         elif cmd.startswith('sha256_str'):
            Hash1 = Hashes()
            Hash1.Sha256_str()
         elif cmd.startswith("sha512_str"):
             Hash1 = Hashes()
             Hash1.Sha512_str()
         elif cmd == 'pwd':
              Op1 = Ops()
              Op1.pwd()
         elif cmd == 'cd':
            Op1 = Ops()
            Op1.cd()
         elif cmd == 'mkdir':
              Op1 = Ops()
              Op1.mkdir()
         elif cmd == 'ls':
              Op1 = Ops ()
              Op1.ls()
         elif cmd == 'rmdir':
              Op1 = Ops()
              Op1.rmdir()
         elif cmd == "meta_info":
             Op1.meta_info()
         elif cmd == "file_date":
              Op1.file_date()
         elif cmd == "shutdown":
              Op1 = Ops()
              Op1.shutdown()
         elif cmd == "shutdown -a":
            Op1 = Ops()
            Op1.shutab()
         elif cmd == "cls" or cmd == "clear":
            Op1 = Ops()
            Op1.clear()
         elif cmd == "html_request":
           web1 = web()
           web1.html_request()
         elif cmd == "html_write":
            web1 = web()
            web1.html_write()
         elif cmd == "str_enc":
           str_enc()
         elif cmd == "pg":
           pass_Gen()
         elif cmd == 'help':
             help1()
         elif cmd == "file_enc":
            Enc1 = Enc()
            Enc1.enc_file_key()
         elif cmd == "dom av":
           web1 = web()
           web1.domain()
         elif cmd == "ip/private":
             Net1 = Net()
             Net1.ip_private()
         elif cmd == "ip/public":
              Net1 = Net()
              Net.ip_public()
         elif cmd == "ip/config":
             Net1 = Net()
             Net1.ip_config()
         elif cmd == "ip/web":
            Net1 = Net()
            Net1.web_ip()
         elif cmd == "ip/track":
            Net1 = Net()
            Net1.ip_track()
         elif cmd == "ps":
            Net1 = Net()
            pass
         elif cmd =="chat -h":
            Net1 = Net()
            Net1.lanc_host()
         elif cmd == "chat -c":
            Net1 = Net()
            Net1.lanc_clt()
         elif cmd == "file_dec":
            dec_file_key()
         elif cmd == "sym key":
          sym_gen_key()
         elif cmd == "date":
               To_date()
         elif cmd == "time":
             timer()
         elif cmd == "fake_name":
            SoE = SocialEng()
            SoE.fake_name()
         elif cmd == "help(chat -c)":
            print(Net1.lanc_clt.__doc__)
         elif cmd == "help(chat -h)":
            print(Net1.lanc_host.__doc__)
         elif cmd == 'help(fake_name)':
              print(SoE.fake_name.__doc__)
         elif cmd == "help(date)":
                 print(date.__doc__)
         elif cmd == "help(time)":
               print(time.__doc__)
         elif cmd == 'help(md5)':
             Hash1 = Hashes
             print(Hash1.md5_str.__doc__)
         elif cmd == "help(sha256)":
             Hash1 = Hashes
             print(Hash1.Sha256_str.__doc__)
         elif cmd == 'help(sha512)':
                Hash1 = Hashes
                print(Hash1.Sha512_str.__doc__)
         elif cmd == "help(pwd)":
                Op1 = Ops
                print(Op1.pwd.__doc__)
         elif cmd == "help(cd)":
                Op1 = Ops
                print(Op1.cd.__doc__)
         elif cmd == "help(mkdir)":
               Op1 = Ops()
               print(Op1.mkdir.__doc__)
         elif cmd == "help(ls)":
             Op1 = Ops
             print(Op1.ls.__doc__)
         elif cmd == "help(rmdir)":
               Op1 = Ops
               print(Op1.rmdir.__doc__)
         elif cmd == "help(meta_info)":
                Op1 = Ops
                print(Op1.meta_info.__doc__)
         elif cmd == "help(shutdown)":
               Op1 = Ops
         elif cmd == "help(shutdown -a)":
            Op1 = Ops
            print(Op1.shutab.__doc__)
         elif cmd == "help(file_date)":
                Op1 = Ops
                print(Op1.file_date.__doc__)
         elif cmd == "help(pg)":
               print(pass_Gen.__doc__)
         elif cmd == "help(html_request)":
               print(web1.html_request.__doc__)
         elif cmd == "help(html_write)":
                print(web1.html_write.__doc__)
         elif cmd == "help(str enc)":
                print(str_enc.__doc__)
         elif cmd == "help(enc file)":
                print(Enc1.enc_file_key.__doc__)
         elif cmd == "help(dom av)":
                print(web1.domain.__doc__)
         elif cmd == "help(ip/private)":
               print(Net1.ip_private.__doc__)
         elif  cmd ==  "help(ip/public)":
                print(Net1.ip_public.__doc__)
         elif cmd  == "help(ip/config)":
                 print(Net1.ip_config.__doc__)
         elif cmd == "help(ip/track)":
                print(Net1.ip_track.__doc__)
         elif cmd == "help(dec file)":
               print(dec_file_key.__doc__)
         elif cmd == "help(sym key)":
                print(sym_gen_key.__doc__)
         elif cmd == 'help(cls)':
                 print(Op1.cls.__doc__)
         elif cmd == "banner" or cmd == "BANNER" or cmd == "Banner":
            intro()  
         elif cmd == "":
           continue                 
         elif cmd == "exit":
            print ("Version 2.5")
            print ("Created by CYBER ELITE NETWORK ™")
            exit()
         else:
             continue

#Security Features (Authentication)
while True:
    cmd2 = input(">>> ")
    if cmd2 == 'l' or cmd2 == "L":
        Log_usn = input("Enter name:")
        Log_pass = getpass.getpass(prompt="Enter your password:")

        Log_hash = hashlib.md5(Log_pass.encode('utf-8')).hexdigest()
        
        with open("Log.txt", "r") as f:
            # Compare the hashed passwords
            if Log_hash != f.read():
                print('login error')
            else:
                print(f"Welcome back commander {Log_usn}")
                commands()    
    elif cmd2 == "c" or cmd2 == "C":
        Reg_usn = input("Enter name:")

        Reg_pass = getpass.getpass(prompt='Enter your password: ')
                
        Reg_hash = hashlib.md5(Reg_pass.encode('utf-8')).hexdigest()

        with open("Log.txt", "w") as f:
               f.write(Reg_hash)
    else:
         print("Enter an option")    
        
