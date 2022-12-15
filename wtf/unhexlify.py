from binascii import unhexlify
import time 
niginput = bytes(input("String to Unhexlify: ").encode('utf-8'))
unblack = unhexlify(niginput)
print(unblack)
time.sleep(100)