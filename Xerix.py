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
from faker import Faker
from datetime import date
from datetime import datetime
from cryptography.fernet import Fernet

def intro():
      ascii_banner = pyfiglet.figlet_format("XeriX")
      print(ascii_banner)
      print("Created by:CYBER ELITE NETWORK™")
      print ("C <----- You must create an account first To do so press C")
      print ("L <----- To login")
      print("-" *100)
    
    
def md5_str():
        '''it takes a string and converts it to a md5  hash'''
        st = time.process_time()
        a_string = input('Enter text to be hashed:')
        hashed_string = hashlib.md5(a_string.encode('utf-8')).hexdigest()
        print(hashed_string)
        clip_board = pyperclip.copy(hashed_string)
        et = time.process_time()
        ep = et - st
        print("Execution time:",ep,"sec")
        print("-"*50)        
        
def Sha256_str():
            '''it takes a string and converts it to sha256 hash'''
            st = time.process_time()
            b_string = input ('Enter text to be hashed:')
            hashed_string = hashlib.sha256(b_string.encode('utf-8')).hexdigest()
            print (hashed_string)
            clip_board = pyperclip.copy(hashed_string)
            et = time.process_time()
            ep = et - st
            print("Execution time",ep,"sec")
            print("-"*50)
            
def Sha512_str():
          '''it takes a string and coverts it to sha512  hash'''
          st = time.process_time()  
          c_string = input ('Enter text to be hashed:')
          hashed_string = hashlib.sha512(c_string.encode('utf-8')). hexdigest ()
          print (hashed_string)
          clip_board = pyperclip.copy(hashed_string)
          et = time.process_time()
          ep = et - st
          print("Execution time:",ep,"sec") 
          print("-"*50)
          
def str_enc():
     '''it encrypts a string using fernet and it also decrypts the string'''
     st = time.process_time()         
     while True:
          text = input ("Enter an option:")
          
# encryption
          if text == ("encrypt"):
               key =bytes( input("Enter key:"),"utf-8")
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
     
def pwd():
         ''' shows the working directory'''
         st = time.process_time()
         print (os.getcwd())
         et = time.process_time()
         ep = et - st
         print("Execution time:",ep,"secs")
         print('-'*50)
         
def cls():
         '''it clears the screen'''
         os.system('clear')
         
def cd():
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
          
def mkdir():
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

def ls():
             ''' lists all the files in the current directory'''
             st = time.process_time()
             print (os.listdir())
             et = time.process_time()
             ep = et - st
             print("Execution time:",ep)
             print("-"*50)
             
              
def rmdir ():
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

def file_info():
            ''' gives an information of a particular file in the working directory'''
            st = time.process_time()   
            file_info  = input ("Enter file name and extension:")
            print (os.stat(file_info))
            et = time.process_time()
            ep = et - st 
            print("Exection time:",ep,"secs")
            print("-"*50)
            
def file_date():
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

# request section
def html_request():
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
          
def html_write():
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
     
def domain():
   ''' checks the avaliablity of a domain'''
   st = time.process_time()
   x = input("Enter domain:")
   domain = whois.whois(x)
   et = time.process_time()
   ep = et - st
   print("Execution time:",ep,"secs")
   print("-"*50)
   
def enc_file_key():
   ''' this is used to encrypt a file in symmetric key cryptography using the fernet encryption algrorithms'''
   try:
       st = time.process_time()
       import Encryptor
       et = time.process_time()
       ep = et - st 
       print("Execution time:",ep,"secs")
       print("-"*50)          
   except:
      print("Try a valid key")
      print("You could generate a key using the sym key command")
      print("-"*50)
      
def dec_file_key():
    ''' this is used to decrypt a file that has been encrypted with symmetric key cryptography '''
    try:
      st = time.process_time()
      import Decryptor
      et = time.process_time()
      ep = et - st
      print("Execution time:",ep,"secs")
    except:
      print("Enter a valid file")
 
def pass_Gen():
  '''this is a password genrator'''
  # Choose a random selection of characters from the set of lowercase letters, uppercase letters, and digits
  y = string.ascii_lowercase + string.ascii_uppercase + string.digits 
  pas = input("Enter length:")

  if pas == "4":
       for i in range(0,4):
           print(random.choice(y), end="")
  elif pas == 6:
        for i in range(0,6):
          print(random.choice(y),end="")
  else:
       print("Enter an option")

def ip_private():
     '''shows you your private ip address'''
     st = time.process_time()
     get = socket.gethostname()    
     x = socket.gethostbyname(get)
     print(get,":",x)
     et = time.process_time()
     ep = et - st
     print("Execution time",ep,"secs")
     print("-"*50)
     
def ip_public():
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
  
def ip_config():
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
       
def web_ip():
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

def ip_track():
          ''' tracks the ip address by providing the infotmation of the country where the ip address is located and many more'''
          st = time.process_time()
          try:
              ip = input('Enter ip address:')
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
      
def To_date():
  '''
  it prints out today's date and time'''
  today = date.today()
  print(today)
  
def timer():
  ''' prints out the current time'''
  now = datetime.now()
  print(now)

def fake_name():
  try:
    st =time.process_time()
    '''this generates random fake names'''
    x = int(input('Enter the numbers of name:'))
    faker = Faker()
    for i in range(0,x):
      print(faker.name())
  except:
    print('Enter a valid Number')
  et = time.process_time()
  ep = et - st
  print('Execution time:',ep,'secs')

def dom_ping():
  '''This pings a website and get the public ip address of a website'''
  st = time.process_time()
  dom_ping_input = input("Enter website:")
  fetch = socket.gethostbyname(dom_ping_input)
  for i in range(0,4):
    print("Pinging",dom_ping_input)
  print(fetch)
  et = time.process_time
  ep = et - st                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                          
  print("Execution time:",ep,"secs")

def pass_cracker():
    print()
 
def help1():     
      help2 = ("cd <--- changes directory","cls <--- clears the screen","dom av <--- checks for the avalibility of  a domain","dec file <--- used to decrypt files that are encrypted","enc file <--- used to encrypt file","file_info  <--- prints information about a file","file_date <--- shows the last modification date about  a file","ip/config <--- prints the  ip address of the device","md5_str <-- hashes a string in md5 algorithm","mkdir <--- creates directory","pg <--- generates a passowrd","sha256 <--- hashes a string in sha256 algorithm","sha512 <--- hashes a string in sha512 algorithm","sym key <--- randomly generate a symmetric key")
      print(help2)
         
#help section                        
intro()
def commands():
    while True:
         cmd = input (">>> ")
         if cmd == 'md5_str':
            md5_str()
         elif cmd == 'sha256_str':
            Sha256_str()
         elif cmd == 'sha512_str':
             Sha512_str()
         elif cmd == 'pwd':
             pwd()
         elif cmd == 'cd':
            cd()
         elif cmd == 'mkdir':
              mkdir()
         elif cmd == 'ls':
              ls()
         elif cmd == 'rmdir':
              rmdir ()
         elif cmd == "file_info":
             file_info()
         elif cmd == "file_date":
              file_date()
         elif cmd == "html_request":
           html_request()
         elif cmd == "html_write":
            html_write()
         elif cmd == "str_enc":
           str_enc()
         elif cmd == "pg":
           pass_Gen()
         elif cmd == 'help':
             help1()
         elif cmd == "file_enc":
            enc_file_key()
         elif cmd == "dom av":
           domain()
         elif cmd == "ip/private":
             ip_private()
         elif cmd == "ip/public":
              ip_public()
         elif cmd == "ip/config":
             ip_config()
         elif cmd == "ip/web":
            web_ip()
         elif cmd == "ip/track":
            ip_track()
         elif cmd == "file_dec":
            dec_file_key()
         elif cmd == "sym key":
          sym_gen_key()
         elif cmd == "date":
               To_date()
         elif cmd == "time":
             timer()
         elif cmd == "cls":
             cls()
         elif cmd == "fake_name":
            fake_name()
         elif cmd == "ping_web":
          dom_ping()
         elif cmd == 'help(ping_web)':
              print(dom_ping.__doc__)
         elif cmd == 'help(fake_name)':
              print(fake_name.__doc__)
         elif cmd == "help(date)":
                 print(date.__doc__)
         elif cmd == "help(time)":
               print(time.__doc__)
         elif cmd == 'help(md5)':
             print(md5_str.__doc__)
         elif cmd == "help(sha256)":
             print(Sha256_str.__doc__)
         elif cmd == 'help(sha512)':
                print(Sha512_str.__doc__)
         elif cmd == "help(pwd)":
                print(pwd.__doc__)
         elif cmd == "help(cd)":
                print(cd.__doc__)
         elif cmd == "help(mkdir)":
               print(mkdir.__doc__)
         elif cmd == "help(ls)":
           print(ls.__doc__)
         elif cmd == "help(rmdir)":
               print(rmdir.__doc__)
         elif cmd == "help(file_info)":
                print(file_info.__doc__)
         elif cmd == "help(file_date)":
                print(file_date.__doc__)
         elif cmd == "help(pg)":
               print(pass_Gen.__doc__)
         elif cmd == "help(html_request)":
               print(html_request.__doc__)
         elif cmd == "help(html_write)":
                print(html_write.__doc__)
         elif cmd == "help(str enc)":
                print(str_enc.__doc__)
         elif cmd == "help(enc file)":
                print(enc_file_key.__doc__)
         elif cmd == "help(dom av)":
                print(domain.__doc__)
         elif cmd == "help(ip/private)":
               print(ip_private.__doc__)
         elif  cmd ==  "help(ip/public)":
                print(ip_public.__doc__)
         elif cmd  == "help(ip/config)":
                 print(ip_config.__doc__)
         elif cmd == "help(ip/track)":
                print(ip_track.__doc__)
         elif cmd == "help(dec file)":
               print(dec_file_key.__doc__)
         elif cmd == "help(sym key)":
                print(sym_gen_key.__doc__)
         elif cmd == 'help(cls)':
                 print(cls.__doc__)  
         elif cmd == "":
           continue                 
         elif cmd == "exit":
            print ("Version 3.5")
            print ("Created by CYBER ELITE NETWORK ™")  
            break
         else:
             continue

while True:
    cmd2 = input(">>>")
    if cmd2 == "c" or cmd2 == "C":
        Reg_usn = input("Enter name:")

        Reg_pass = getpass.getpass(prompt='Enter your password: ')

                
        Reg_hash = hashlib.md5(Reg_pass.encode('utf-8')).hexdigest()

        with open("x.txt", "w") as f:
            f.write(Reg_hash)
    if cmd2 == 'l' or cmd2 == "L":
        Log_usn = input("Enter name:")
        Log_pass = getpass.getpass(prompt="Enter your password:")

        Log_hash = hashlib.md5(Log_pass.encode('utf-8')).hexdigest()
        
        with open("x.txt", "r") as f:
            # Compare the hashed passwords
            if Log_hash != f.read():
                print('login error')
            else:
                commands()
