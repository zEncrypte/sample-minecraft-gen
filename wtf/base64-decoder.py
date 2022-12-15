import base64
import time
import os

print("String to Decode: ")
basenig = input('').encode('utf-8')
wtfdude = base64.decodebytes(basenig).decode('ascii')
os.system('cls')
print(f'{wtfdude}')
time.sleep(100)