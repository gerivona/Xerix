import os
import sys
import pprint
import time
import whois
import json
import ipapi
import socket
import shutil
import random
import getpass
import codecs
import string
import hashlib
import pyfiglet
import requests
import pyperclip
import ipaddress
import subprocess
import http.server
import socketserver
import cryptography
from faker import Faker
from datetime import date
from datetime import datetime
from cryptography.fernet import Fernet


# Introduction to Xerix program
def intro():
    ascii_banner = pyfiglet.figlet_format("XERIX")
    print(ascii_banner)
    print("Created by:CYBER ELITE NETWORK™")
    print("C <----- You must create an account first To do so press C")
    print("L <----- To login")
    print("-" *100)

#Decorators
def exec_time(func):
    
    def timer1(*args,**kwargs):
        st = time.time()
        func(*args,*kwargs)
        et = time.time() - st
        print(f'Execution time: {et} secs')
        print(50 * '-')
    return timer1

def key_interup(func):

    def method(*args,**kwargs):
        try:
            func(*args,**kwargs)
        except KeyboardInterrupt:
            print(commands)
    return method


# Text conversion to hash  
class Hashes:
    
    def __init__(self):
        pass
    
    @exec_time
    def hash_encryption(self):
        """ This function takes a string and converts it to different hashes like
    md5, sha256 and sha512
        """
        
        input_hash = input("Enter the hash type (md5, sha256, sha512): ").strip().lower()
        
        if input_hash in ["md5", "sha256", "sha512"]:
            input_text = input("Enter text: ").strip()
            
            if input_hash == "md5":
                hashed_text = hashlib.md5(input_text.encode()).hexdigest()
            elif input_hash == "sha256":
                hashed_text = hashlib.sha256(input_text.encode()).hexdigest()
            elif input_hash == "sha512":
                hashed_text = hashlib.sha512(input_text.encode()).hexdigest()

            pyperclip.copy(hashed_text)
            print(hashed_text)
            
        else:
            print("Invalid hash type")

#Encrypting strings 
@key_interup
@exec_time
def str_enc():
    '''it encrypts a string using fernet and it also decrypts the string'''        
    while True:
        text = input ("Enter an option:").strip()
          
# encryption
        try:
            if text == ("encrypt"):
                key = bytes(input("Enter key:"),"utf-8")
                fernet = Fernet(key)
                Text = input("Enter text:")
                Text_Conv = bytes(Text,'utf-8')
                Text_Conv = fernet.encrypt(Text_Conv)
                print(Text_Conv)
                break
        
            elif text == "decrypt":

                encText = input("Enter encrypted text:").strip()
                key = input("Enter key:")
                f = Fernet(key)
                c = f.decrypt(bytes(encText, 'utf-8'))
                print(c.decode('utf-8'))
                    
            elif text == "exit":
                break

            else: 
                    print ("Not found")

        except ValueError:
            print("Please enter a valid key to be able to decrypt the string")
   
#The class that has operating system commands
class Operating_system:

    def __init__(self):
        pass
    
    @exec_time
    def pwd(self):
        ''' shows the working directory'''
        print(os.getcwd())
                
    def cls(self):
        '''it clears the screen'''
        os.system('cls')

    @exec_time    
    def cd(self):
        ''' changes the directory'''
        path = input ("Enter path:")
        try:
            print (os.chdir(path))
        except:
            print("Enter a valid path")

    def shutdown(self):
        ''' shutdowns your computer '''
        os.system("shutdown /s")

    def shutab(self):
        '''aborts the shutdown command '''
        os.system("shutdown /a")

    @exec_time     
    def mkdir(self):
        ''' makes a new directory'''        
        var = input("Enter the name of the directory:")
        os.mkdir(var)
        print ("This folder is created in the working directory")
        print ('Folder created successfully')
      
    @exec_time
    def ls(self):
        ''' lists all the files in the current directory'''
        print (os.listdir())

    @key_interup   
    @exec_time
    def tre(self):
        ''' show of the directory and files '''
        os.system('tree')
            

    @exec_time 
    def rmdir (self):
        ''' remove the current directory'''
        rmip = input ("Enter folder:")
        try:
           os.rmdir(rmip)
        except:
            print("Enter a valid folder")
    
    @exec_time
    def meta_info(self):
        ''' gives meta information about a file'''
        file_info  = input ("Enter file name and extension:")
        print (os.stat(file_info))
    
    @exec_time        
    def file_date(self):
        '''' it gives you the last modification date of a file'''   
        file_in = input ("Enter file name and extension:")
        print ("Please make sure the file is in the current directory")
        t = os.stat(file_in).st_mtime
        print(datetime.fromtimestamp(t))

    @exec_time  
    def sys_info(self):
       ''' This prints out information about a system.'''
       os.system('systeminfo')

    @exec_time  
    def cmd(self):
        ''' This functions allows you to use cmd module''' 
        import setup

    @exec_time
    def cat(self):
        '''This allows you to view the contents of a file'''

 
# The Web section
class web:

    def __init__(self):
        pass
    

    @exec_time
    def html_request(self):
        ''' shows the html code of a website'''
        try:
            html = input ("Enter URL:")
            x = requests.get(html)              
            print (x.text)
        except:
           print('No connection')

    @exec_time      
    def html_write(self):
        ''' it allows you to write html file'''
        path2 = input("Enter directory:")
        os.chdir(path2)
        with open (input("Enter the HTML file to be created:"),"w") as codes:
            codes.write(input("Enter your codes:"))
            codes.close()

    @exec_time   
    def domain(self):
        ''' checks the avaliablity of a domain'''
        x = input("Enter domain:")
        domain = whois.whois(x)
        print(domain)
        
    @exec_time
    def mail():
       ''' This allows you send email in xerix'''
       import Mail
      


class Encryption:

    def __init__(self):
        print('_' * 50)


    @exec_time  
    def enc_file_key(self):
        ''' This is used to encrypt a file in symmetric key cryptography using the fernet encryption algrorithms'''
        try:
            import Encryptor
        except:
            print("Try a valid key")
            print("You could generate a key using the sym key command")
            print("-"*50)
        
    @exec_time
    def dec_file_key():
        ''' This is used to decrypt a file that has been encrypted with symmetric key cryptography '''
        try:
            import Decryptor
        except:
            print("Enter a valid file")

@exec_time 
def pass_Gen():                 
    ''' This is a password generator'''
    # Choose a random selection of characters from the set of lowercase letters, uppercase letters, and digits
    length = int(input("Enter the length of the password: "))
    characters = string.ascii_letters + string.digits + string.punctuation
    password = ''.join(random.choice(characters) for _ in range(length))
    print("Generated password:", password)
    pyperclip.copy(password)
    print("Password copied to the clipboard.")
  
class Net:

    def __init__(self):
        pass

    @exec_time
    def ip_private(self):
      '''shows you your private ip address'''
      get = socket.gethostname()    
      x = socket.gethostbyname(get)
      print(get,":",x)

    @exec_time 
    def ip_public(self):
        '''shows the public ip address '''
        try:
            response = requests.get("https://api.ipify.org")
            if response.status_code == 200:
                print(response.text)
                return response.text
            else:
               return "Unable to get IP address"
        except:
           print("No connection")  
      
    @exec_time
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

    @exec_time  
    def web_ip(self):
        ''' Shows the ip address of a website'''
        try:
            web_input = input ("Enter website:")
            s = socket.gethostbyname(web_input)
            print(s)
        except:
           print("Unable to find ip address")
        
    @exec_time   
    def ip_track(ip):
          ''' Tracks the ip address by providing the information of the country where the ip address is located and many more'''
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
          
    @exec_time              
    def ps(self):
        ''' Scans for open ports of a network ip address '''
        try:
            target = input("Enter Ip address: ")
            ipaddress.IPv4Address(target) # Validating the ip
            start_port = int(input("Enter start port: "))
            end_port = int(input("Enter end port: "))

            open_port = []

            for port in range(start_port,end_port + 1):
                sock = socket.socket(socket.AF_INET,socket.SOCK_STREAM)
                sock.settimeout(0.5) # set the timeout here
                result = sock.connect_ex((target, port))
                print(f"Scanning ports {start_port} to {end_port} on {target}")

                if result == 0:
                    print(f'Port {port} is open')
                    open_port.append(port)

                sock.close()

            print(f"List of open ports: {open_port}")
        except:
            print('Enter a valid ip address')

    @exec_time    
    def lanc_host(self):
        ''' Creates a chat server  within a LAN '''
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

    @exec_time
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
    
    @exec_time
    def Net_Sender():
        ''' Allows you to send a file while being the host.'''

        host = socket.gethostbyname(socket.gethostname())
        clients = socket.socket(socket.AF_INET,socket.SOCK_STREAM)

        clients.connect((host,1234))
        file_input = input("Enter the file:")
        file = open(file_input,"rb")
        file_size = os.path.getsize(file)
        print(f"The size of the file is {file_size}")
        
    def Nets_Cli():
        ''' Allows you to recieve a file incomming from the host over a LAN.'''
    
    @exec_time    
    def http_server(self):
        ''' This setups a http server. '''
        try:
            PORT = 8000
            Handler = http.server.SimpleHTTPRequestHandler

            with socketserver.TCPServer(("", PORT), Handler) as httpd:
                print("Server started at port", PORT)
                httpd.serve_forever()
                
        except KeyboardInterrupt:
            commands()


@exec_time                
def sym_gen_key():
    '''' Generates a 32 bit key for symmetric key encryption.'''
    key = Fernet.generate_key()
    with open("sym.txt","wb") as f:
        f.write(bytes(key))
    print(key)     
    str_key = codecs.decode(key)
    pyperclip.copy(str_key)

      
def To_date():
   '''
   it prints out today's date and time.'''
   today = date.today()
   print(today)
  
def timer():
   ''' prints out the current time.'''
   now = datetime.now()
   print(now)


class SocialEng:

    def __init__(self):
        pass
    
    @exec_time
    def fake_name(self):
      '''this generates random fake names.'''
      try:
        x = int(input('Enter the numbers of name:'))
        faker = Faker()
        for i in range(0,x):
            print(faker.name())
      except KeyboardInterrupt:
        print('Enter a valid Number')
    
    
    @exec_time
    def exif(self):
        ''' This actually strips exif information from an image written by David Bombal '''
        import Exif
    
        
class Cracker:

    def __init__(self,name):
        self.name = "This is just the part of python class"

    def zip_cracker(self):
        pass
    
    @exec_time
    def ssh_cracker(self):
        ''' This alllows you to brute force ssh passwords. '''
        import ssh_cracker

class VulScan:

    def __init__(self):
        pass
    
    @exec_time
    def Xss(self):
        '''Scans Websites to check if their is an xss vulneraliblity'''
        Website = input('Enter the website that you want to scan:')
        r = requests.get(Website)
        if r.status_code == 200:
            print('Connection Sucessfull')
        else:
            print('Invalid Connection')




class Malware:
    
    def __init_():
        pass

#Help section
def help_func():
    with open('Help.txt',  "r") as Help_func:
        
        content = Help_func()
        print(content)
        
def commands():
    try:
        while True:
            cmd = input ("X6>>> ").strip()
            if cmd.startswith('hash'):
                Hash1 = Hashes()
                Hash1.hash_encryption()
    
            elif cmd == 'pwd':
                Op1 = Operating_system()
                Op1.pwd()
                
            elif cmd == 'cd':
                Op1 = Operating_system()
                Op1.cd()
                
            elif cmd == 'mkdir':
                Op1 = Operating_system()
                Op1.mkdir()
                
            elif cmd == 'ls':
                Op1 = Operating_system()
                Op1.ls()
                
            elif cmd == 'rmdir':
                Op1 = Operating_system()
                Op1.rmdir()
                
            elif cmd == "meta_info":
                Op1 = Operating_system()
                Op1.meta_info()
                    
            elif cmd == "cls" or cmd == "clear":
                Op1 = Operating_system()
                Op1.cls()
                
            elif cmd == "file_date":
                Op1 = Operating_system()
                Op1.file_date()
                
            elif cmd == "shutdown":
                Op1 = Operating_system()
                Op1.shutdown()
                
            elif cmd == "shutdown -a":
                Op1 = Operating_system()
                Op1.shutab()
                
            elif cmd == "sys_info":
                Op1 = Operating_system()
                Op1.sys_info()

            elif cmd == "tree":
                Op1 = Operating_system()
                Op1.tre()
            
            elif cmd == "os term":
                Op1 = Operating_system()
                Op1.cmd()
                    
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
                help_func()
                    
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
                
            elif cmd =="chat -h":
                Net1 = Net()
                Net1.lanc_host()
                
            elif cmd == "chat -c":
                Net1 = Net()
                Net1.lanc_clt()
                
            elif cmd == "http start server":
                Net1 = Net()
                Net1.http_server()
        
            elif cmd == 'ps scan':
                Net1 = Net()
                Net1.ps()

            elif cmd == "file_enc":
                Enc1 = Encryption()
                Enc1.enc_file_key()
                
            elif cmd == "file_dec":
                Enc1 = Encryption()
                Enc1.dec_file_key()
                
            elif cmd == "sym key":
               sym_gen_key()
            
            elif cmd == "date":
                To_date()
                
            elif cmd == "time":
                timer()
                
            elif cmd == "fake_name":
                SoE = SocialEng()
                SoE.fake_name()

            elif cmd == "exif ext":
                SoE = SocialEng()
                SoE.exif()
                
            elif cmd == "ssh crack":
                Cracker1 = Cracker()
                Cracker1.ssh_cracker()

            elif cmd == "zip crack":
                Cracker1 = Cracker()
                Cracker1.zip_cracker()

            elif cmd == "help(exif ext)":
                print(SoE.exif.__doc__)

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
                Op1 = Operating_system
                print(Op1.pwd.__doc__)
                
            elif cmd == "help(cd)":
                Op1 = Operating_system
                print(Op1.cd.__doc__)
                
            elif cmd == "help(mkdir)":
                Op1 = Operating_system
                print(Op1.mkdir.__doc__)
                
            elif cmd == "help(ls)":
                Op1 = Operating_system
                print(Op1.ls.__doc__)
                
            elif cmd == "help(rmdir)":
                Op1 = Operating_system
                print(Op1.rmdir.__doc__)
                
            elif cmd == "help(meta_info)":
                Op1 = Operating_system()
                print(Op1.meta_info.__doc__)
                
            elif cmd == "help(shutdown)":
                Op1 = Operating_system
                print(Op1.shutdown.__doc__)
                
            elif cmd == "help(shutdown -a)":
                Op1 = Operating_system
                print(Op1.shutab.__doc__)
                
            elif cmd == "help(file_date)":
                Op1 = Operating_system
                print(Op1.file_date.__doc__)

            elif cmd == "help(tree)":
                Op1 = Operating_system
                print(Op1.tre.__doc__)
                    
            elif cmd == "help(pg)":
                print(pass_Gen.__doc__)
                
            elif cmd == "help(html_request)":
                print(web1.html_request.__doc__)
                
            elif cmd == "help(html_write)":
                print(web1.html_write.__doc__)
                    
            elif cmd == "help(str enc)":
                print(str_enc.__doc__)
                
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

            elif cmd == "help(ps scan)":
                print(Net1.ps.__doc__)   
                        
            elif cmd == "help(enc file)":
                print(Enc1.enc_file_key.__doc__)
                
            elif cmd == "help(dec file)":
                print(Enc1.dec_file_key.__doc__)
                
            elif cmd == "help(sym key)":
                print(sym_gen_key.__doc__)

            elif cmd == "help(ssh crack)":
                print(Cracker1.ssh_cracker.__doc__)
                        
            elif cmd == 'help(cls)':
                print(Op1.cls.__doc__)
                
            elif cmd == "banner" or cmd == "Banner" or cmd == "BANNER":
                intro()  
                
            elif cmd == "":
               continue
                            
            elif cmd == "exit":
                print ("Version 1.0.0")
                print ("Created by CYBER ELITE NETWORK ™")
                exit()
                
            else:
                print("Command not recognized. Enter 'help' for the list of the avaliable commands ")
                continue

    except KeyboardInterrupt:
        pass

#Security Features (Authentication)
def Acct():
    while True:    
        cmd2 = input(">>> ").strip()
        try:
            if cmd2 == 'l' or cmd2 == "L":
                Log_usn = input("Enter name:")
                Log_pass = getpass.getpass(prompt="Enter your password:").strip()

                Log_hash = hashlib.sha256(Log_pass.encode('utf-8')).hexdigest()
                
                with open("Log.txt", "r") as f:
                    # Compare the hashed passwords
                    if Log_hash != f.read():
                        print('login error')
                    else:
                        print(f"Welcome back commander {Log_usn}")
                        commands()
                        
            elif cmd2 == "c" or cmd2 == "C":
                Reg_usn = input("Enter name:").strip()

                Reg_pass = getpass.getpass(prompt='Enter your password: ').strip()
                        
                Reg_hash = hashlib.sha256(Reg_pass.encode('utf-8')).hexdigest()

                with open("Log.txt", "w") as f:
                    f.write(Reg_hash)
                    
            
            elif cmd2  == "exit":
                print ("Version 1.0.0")
                print ("Created by CYBER ELITE NETWORK")
                exit()

            else:
              print("Enter an option")

        except FileNotFoundError:
            print("You must create an account first. Enter C to create an account")


    # Somethings is wrong with the authetication
    # Encryption and Decryption

if __name__ == "__main__":
    intro()
    Acct()
    commands()
    