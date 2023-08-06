import requests

import json


  

def get_temporary_email():
    headers = {

    'User-Agent':'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/115.0.0.0 Safari/537.36',
    'Authorization': 'Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1dWlkIjoiNmM3NDMzMGM0NDQ2NDc4MjkwMjIwZGFkNjQ0Y2RkOTAiLCJtYWlsYm94IjoicGlmaXhvODk4OEBuYXltZWRpYS5jb20iLCJpYXQiOjE2OTEyMzA2MTZ9.Wjl7dds5dU91knyjKaCIxLOqz9k4903nPX8bRjm7zBU'
    }


    r = requests.get('https://web2.temp-mail.org/messages',headers=headers)
    try:
        mail = json.loads(r.content.decode())
    except:
        mail = "Error"
    return mail


print(get_temporary_email())

